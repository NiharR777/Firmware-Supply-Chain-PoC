"""
Controlled ML Training and Evaluation
Firmware & Supply-Chain Assurance PoC

This script implements the approved ML experiment only.

Important assurance boundaries:
- The frozen dataset is never modified.
- Ground-truth labels/factors are never model inputs.
- Scenario names/manifests/expected decisions are never model inputs.
- Lineage-aware GroupKFold is used for training CV.
- Validation is used for candidate selection and calibration.
- Test data is evaluated only after model/calibration freeze.
- Deterministic policy fidelity is an assurance check, not an ML feature.
- Isolation Forest is trained only on training rows labeled "normal".
- No rule/ML fusion, API, dashboard, flashing, quarantine, or production action
  is implemented here.
"""

from __future__ import annotations

import hashlib
import json
import math
import platform
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from sklearn.base import clone
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest, RandomForestClassifier
from sklearn.dummy import DummyClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    log_loss,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupKFold, ParameterGrid
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


# =============================================================================
# Paths and immutable experiment constants
# =============================================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATASET_DIR = (
    PROJECT_ROOT
    / "data"
    / "synthetic"
    / "supply_chain_poc"
    / "dataset"
)

ARTIFACT_DIR = PROJECT_ROOT / "artifacts" / "ml_experiment"
MODEL_DIR = PROJECT_ROOT / "models" / "ml"

FEATURE_FILE = DATASET_DIR / "engineered_features.csv"
FEATURE_METADATA_FILE = DATASET_DIR / "feature_metadata.json"
OBSERVABLE_FILE = DATASET_DIR / "observable_features.csv"
REFERENCE_FILE = DATASET_DIR / "reference_data.csv"
LABEL_FILE = DATASET_DIR / "ground_truth_labels.csv"
SPLIT_FILE = DATASET_DIR / "split_assignments.csv"
GENERATION_FILE = DATASET_DIR / "generation_parameters.json"

SEED = 20260828
ROBUSTNESS_SEED = 20260903

REPORT_CLASS_ORDER = [
    "normal",
    "investigate",
    "high_risk",
]

EXPECTED_FEATURE_COUNT = 22
EXPECTED_RECORD_COUNT = 5000
EXPECTED_SPLIT_COUNTS = {
    "train": 3500,
    "validation": 750,
    "test": 750,
}

EXPECTED_LABEL_COUNTS = {
    "normal": 1000,
    "investigate": 2000,
    "high_risk": 2000,
}

N_CV_FOLDS = 5

# Proposed mandatory acceptance gates from the approved specification.
GATES = {
    "macro_f1": 0.95,
    "high_risk_recall": 0.98,
    "per_class_recall": 0.90,
    "per_class_precision": 0.90,
    "min_per_class_f1": 0.90,
    "multiclass_brier": 0.10,
    "log_loss": 0.25,
    "ece": 0.05,
    "isolation_forest_auroc": 0.80,
    "isolation_forest_auprc": 0.80,
    "isolation_forest_recall_at_5pct_fpr": 0.70,
}

ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
MODEL_DIR.mkdir(parents=True, exist_ok=True)


# =============================================================================
# Utilities
# =============================================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def json_dump(data: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, sort_keys=True, default=str)


def safe_float(value: Any) -> float | None:
    if value is None:
        return None

    try:
        value = float(value)
    except (TypeError, ValueError):
        return None

    if not math.isfinite(value):
        return None

    return value


def version_tuple(value: Any) -> tuple[int, ...]:
    import re

    numbers = re.findall(r"\d+", str(value or ""))
    if not numbers:
        raise ValueError(f"Invalid firmware version: {value!r}")
    return tuple(int(number) for number in numbers)


def assert_required_columns(
    frame: pd.DataFrame,
    required: set[str],
    frame_name: str,
) -> None:
    missing = sorted(required - set(frame.columns))
    if missing:
        raise AssertionError(
            f"{frame_name} is missing required columns: {missing}"
        )


def map_probabilities_to_report_order(
    model_classes: np.ndarray,
    probabilities: np.ndarray,
) -> np.ndarray:
    """
    Map sklearn's native class ordering explicitly into the fixed report order.

    This avoids class-order ambiguity in Brier/log-loss/ECE calculations.
    """
    model_classes = list(model_classes)

    output = np.zeros(
        (probabilities.shape[0], len(REPORT_CLASS_ORDER)),
        dtype=float,
    )

    for source_index, class_name in enumerate(model_classes):
        if class_name not in REPORT_CLASS_ORDER:
            raise AssertionError(
                f"Unexpected model class {class_name!r}"
            )

        target_index = REPORT_CLASS_ORDER.index(class_name)
        output[:, target_index] = probabilities[:, source_index]

    row_sums = output.sum(axis=1)

    if not np.allclose(row_sums, 1.0, atol=1e-8):
        raise AssertionError(
            "Mapped probability rows do not sum to 1."
        )

    return output


def probabilities_to_predictions(
    probabilities: np.ndarray,
) -> np.ndarray:
    indices = np.argmax(probabilities, axis=1)
    return np.asarray(
        [REPORT_CLASS_ORDER[index] for index in indices],
        dtype=object,
    )


def multiclass_brier(
    y_true: np.ndarray,
    probabilities: np.ndarray,
) -> float:
    class_index = {
        label: index
        for index, label in enumerate(REPORT_CLASS_ORDER)
    }

    y_indices = np.asarray(
        [class_index[label] for label in y_true]
    )

    one_hot = np.zeros_like(probabilities)

    one_hot[
        np.arange(len(y_indices)),
        y_indices,
    ] = 1.0

    return float(
        np.mean(
            np.sum(
                (probabilities - one_hot) ** 2,
                axis=1,
            )
        )
    )


def expected_calibration_error(
    y_true: np.ndarray,
    probabilities: np.ndarray,
    n_bins: int = 10,
) -> float:
    """
    Fixed equal-width bins [0,0.1), ..., [0.9,1.0].

    For multiclass calibration:
    confidence = maximum predicted probability
    correctness = whether argmax prediction equals y_true
    """
    predictions = probabilities_to_predictions(probabilities)
    confidence = probabilities.max(axis=1)
    correctness = (
        predictions == y_true
    ).astype(float)

    ece = 0.0

    for bin_index in range(n_bins):
        lower = bin_index / n_bins
        upper = (
            (bin_index + 1) / n_bins
        )

        if bin_index == n_bins - 1:
            mask = (
                (confidence >= lower)
                & (confidence <= upper)
            )
        else:
            mask = (
                (confidence >= lower)
                & (confidence < upper)
            )

        if not np.any(mask):
            continue

        bin_confidence = confidence[mask].mean()
        bin_accuracy = correctness[mask].mean()
        bin_fraction = mask.mean()

        ece += (
            bin_fraction
            * abs(
                bin_accuracy
                - bin_confidence
            )
        )

    return float(ece)


def reliability_table(
    y_true: np.ndarray,
    probabilities: np.ndarray,
    n_bins: int = 10,
) -> list[dict[str, Any]]:
    predictions = probabilities_to_predictions(probabilities)
    confidence = probabilities.max(axis=1)
    correctness = (
        predictions == y_true
    ).astype(float)

    rows = []

    for bin_index in range(n_bins):
        lower = bin_index / n_bins
        upper = (
            (bin_index + 1) / n_bins
        )

        if bin_index == n_bins - 1:
            mask = (
                (confidence >= lower)
                & (confidence <= upper)
            )
        else:
            mask = (
                (confidence >= lower)
                & (confidence < upper)
            )

        if not np.any(mask):
            rows.append(
                {
                    "bin": bin_index,
                    "lower": lower,
                    "upper": upper,
                    "count": 0,
                    "mean_confidence": None,
                    "accuracy": None,
                }
            )
            continue

        rows.append(
            {
                "bin": bin_index,
                "lower": lower,
                "upper": upper,
                "count": int(mask.sum()),
                "mean_confidence": float(
                    confidence[mask].mean()
                ),
                "accuracy": float(
                    correctness[mask].mean()
                ),
            }
        )

    return rows


def classification_metrics(
    y_true: np.ndarray,
    predictions: np.ndarray,
    probabilities: np.ndarray,
) -> dict[str, Any]:
    precision = precision_score(
        y_true,
        predictions,
        labels=REPORT_CLASS_ORDER,
        average=None,
        zero_division=0,
    )

    recall = recall_score(
        y_true,
        predictions,
        labels=REPORT_CLASS_ORDER,
        average=None,
        zero_division=0,
    )

    f1 = f1_score(
        y_true,
        predictions,
        labels=REPORT_CLASS_ORDER,
        average=None,
        zero_division=0,
    )

    class_metrics = {}

    for index, label in enumerate(REPORT_CLASS_ORDER):
        class_metrics[label] = {
            "precision": float(precision[index]),
            "recall": float(recall[index]),
            "f1": float(f1[index]),
        }

    brier = multiclass_brier(
        y_true,
        probabilities,
    )

    class_to_index = {
        class_name: index
        for index, class_name in enumerate(REPORT_CLASS_ORDER)
    }

    true_class_indices = np.array(
        [class_to_index[label] for label in y_true],
        dtype=int,
    )

    true_class_probabilities = probabilities[
        np.arange(len(y_true)),
        true_class_indices,
    ]

    true_class_probabilities = np.clip(
        true_class_probabilities,
        1e-15,
        1.0,
    )

    ll = float(
        -np.mean(np.log(true_class_probabilities))
    )

    ece = expected_calibration_error(
        y_true,
        probabilities,
        n_bins=10,
    )

    return {
        "accuracy": float(
            accuracy_score(
                y_true,
                predictions,
            )
        ),
        "macro_f1": float(
            f1_score(
                y_true,
                predictions,
                labels=REPORT_CLASS_ORDER,
                average="macro",
                zero_division=0,
            )
        ),
        "high_risk_recall": float(
            class_metrics["high_risk"]["recall"]
        ),
        "min_per_class_f1": float(
            min(
                item["f1"]
                for item in class_metrics.values()
            )
        ),
        "min_per_class_recall": float(
            min(
                item["recall"]
                for item in class_metrics.values()
            )
        ),
        "min_per_class_precision": float(
            min(
                item["precision"]
                for item in class_metrics.values()
            )
        ),
        "per_class": class_metrics,
        "confusion_matrix": confusion_matrix(
            y_true,
            predictions,
            labels=REPORT_CLASS_ORDER,
        ).tolist(),
        "multiclass_brier": float(brier),
        "log_loss": float(ll),
        "ece_fixed_10_bins": float(ece),
        "reliability": reliability_table(
            y_true,
            probabilities,
            n_bins=10,
        ),
    }


def gate_results(
    metrics: dict[str, Any],
) -> dict[str, Any]:
    result = {
        "macro_f1": metrics["macro_f1"] >= GATES["macro_f1"],
        "high_risk_recall": (
            metrics["high_risk_recall"]
            >= GATES["high_risk_recall"]
        ),
        "per_class_recall": (
            metrics["min_per_class_recall"]
            >= GATES["per_class_recall"]
        ),
        "per_class_precision": (
            metrics["min_per_class_precision"]
            >= GATES["per_class_precision"]
        ),
        "min_per_class_f1": (
            metrics["min_per_class_f1"]
            >= GATES["min_per_class_f1"]
        ),
        "multiclass_brier": (
            metrics["multiclass_brier"]
            <= GATES["multiclass_brier"]
        ),
        "log_loss": (
            metrics["log_loss"]
            <= GATES["log_loss"]
        ),
        "ece": (
            metrics["ece_fixed_10_bins"]
            <= GATES["ece"]
        ),
    }

    return {
        "gates": result,
        "all_pass": all(result.values()),
    }


# =============================================================================
# Exact deterministic policy reconstruction
# =============================================================================

RISK_WEIGHTS = {
    "hash_integrity_failure": 40,
    "signature_failure": 30,
    "trusted_root_failure": 20,
    "untrusted_vendor": 40,
    "unauthorized_rollback": 40,
    "vulnerable_component": 20,
    "unexpected_component": 20,
    "missing_sbom": 15,
    "stale_evidence": 10,
}


def calculate_policy_result(
    observable: pd.Series,
    reference: pd.Series,
) -> dict[str, Any]:
    """
    Reproduce the deterministic decision policy using dataset observation
    and reference fields.

    This mirrors decision_engine.py.

    Ground-truth label/factor columns are deliberately absent here.
    """

    factors: list[str] = []

    # 1. Hash integrity
    expected_hash = reference["trusted_hash"]
    observed_hash = observable["observed_hash"]

    if expected_hash != observed_hash:
        factors.append(
            "hash_integrity_failure"
        )

    # 2. Signature
    #
    # The observable dataset represents signature validity as a boolean.
    # False corresponds to the decision engine's invalid/untrusted statuses.
    if bool(observable["signature_valid"]) is False:
        factors.append(
            "signature_failure"
        )

    # 3. Trusted root
    if bool(observable["trusted_root_valid"]) is False:
        factors.append(
            "trusted_root_failure"
        )

    # 4. Vendor trust
    observed_vendor = observable[
        "observed_vendor_id"
    ]
    expected_vendor = reference[
        "approved_vendor_id"
    ]

    # VEND-004 is explicitly marked untrusted in reference_catalog.csv.
    # The observable dataset does not contain vendor_trust_status, so the
    # vendor reference catalog is represented by the known trusted-vendor set.
    trusted_vendors = {
        "VEND-001",
        "VEND-002",
        "VEND-003",
    }

    if (
        expected_vendor != observed_vendor
        or observed_vendor not in trusted_vendors
    ):
        factors.append(
            "untrusted_vendor"
        )

    # 5. Rollback
    observed_version = observable[
        "observed_version"
    ]
    expected_version = reference[
        "approved_version"
    ]

    rollback_authorized = bool(
        observable["rollback_authorized"]
    )

    if (
        version_tuple(observed_version)
        < version_tuple(expected_version)
        and rollback_authorized is False
    ):
        factors.append(
            "unauthorized_rollback"
        )

    # 6. SBOM
    #
    # decision_engine.py:
    # if sbom_present is False OR sbom_status != "complete"
    #
    # The frozen observable representation contains sbom_present and
    # sbom_complete. Therefore:
    if bool(observable["sbom_present"]) is False:
        factors.append(
            "missing_sbom"
        )
    elif bool(observable["sbom_complete"]) is False:
        factors.append(
            "missing_sbom"
        )

    # 7. Vulnerability
    #
    # The generated observable representation has vulnerability_present and
    # vulnerability_applicable. An affected SBOM vulnerability requires the
    # vulnerability to be present and applicable.
    if (
        bool(observable["vulnerability_present"])
        and bool(observable["vulnerability_applicable"])
    ):
        factors.append(
            "vulnerable_component"
        )

    # 8. Unexpected component
    if bool(observable["unexpected_component"]) is True:
        factors.append(
            "unexpected_component"
        )

    # 9. Evidence freshness
    evidence_age = int(
        observable["evidence_age_days"]
    )

    freshness_threshold = int(
        reference["freshness_threshold_days"]
    )

    if evidence_age > freshness_threshold:
        factors.append(
            "stale_evidence"
        )

    score = sum(
        RISK_WEIGHTS[factor]
        for factor in factors
    )

    score = min(score, 100)

    if score >= 40:
        risk_level = "high_risk"
    elif score > 0:
        risk_level = "investigate"
    else:
        risk_level = "normal"

    return {
        "risk_factors": factors,
        "risk_score": int(score),
        "risk_level": risk_level,
    }


def deterministic_policy_fidelity(
    observable: pd.DataFrame,
    reference: pd.DataFrame,
    labels: pd.DataFrame,
) -> dict[str, Any]:
    merged = (
        observable[
            [
                "record_id",
                "package_id",
                "lineage_id",
                "observed_vendor_id",
                "observed_hash",
                "signature_valid",
                "trusted_root_valid",
                "sbom_present",
                "sbom_complete",
                "observed_version",
                "rollback_authorized",
                "vulnerability_present",
                "vulnerability_applicable",
                "unexpected_component",
                "evidence_age_days",
            ]
        ]
        .merge(
            reference[
                [
                    "record_id",
                    "package_id",
                    "lineage_id",
                    "approved_vendor_id",
                    "trusted_hash",
                    "approved_version",
                    "freshness_threshold_days",
                ]
            ],
            on=[
                "record_id",
                "package_id",
                "lineage_id",
            ],
            validate="one_to_one",
        )
        .merge(
            labels[
                [
                    "record_id",
                    "ground_truth_label",
                    "ground_truth_score",
                    "ground_truth_factors",
                ]
            ],
            on="record_id",
            validate="one_to_one",
        )
    )

    reconstructed_labels = []
    reconstructed_scores = []
    reconstructed_factors = []

    for _, row in merged.iterrows():
        result = calculate_policy_result(
            row,
            row,
        )

        reconstructed_labels.append(
            result["risk_level"]
        )
        reconstructed_scores.append(
            result["risk_score"]
        )
        reconstructed_factors.append(
            ";".join(result["risk_factors"])
        )

    merged["reconstructed_label"] = (
        reconstructed_labels
    )
    merged["reconstructed_score"] = (
        reconstructed_scores
    )
    merged["reconstructed_factors"] = (
        reconstructed_factors
    )

    label_match = (
        merged["reconstructed_label"]
        == merged["ground_truth_label"]
    )

    score_match = (
        merged["reconstructed_score"]
        == merged["ground_truth_score"]
    )

    factor_match = (
        merged["reconstructed_factors"].fillna("")
        == merged["ground_truth_factors"].fillna("")
    )

    mismatches = merged[
        ~(label_match & score_match & factor_match)
    ]

    return {
        "records": int(len(merged)),
        "label_matches": int(label_match.sum()),
        "score_matches": int(score_match.sum()),
        "factor_matches": int(factor_match.sum()),
        "label_fidelity": float(label_match.mean()),
        "score_fidelity": float(score_match.mean()),
        "factor_fidelity": float(factor_match.mean()),
        "overall_exact_fidelity": float(
            (label_match & score_match & factor_match).mean()
        ),
        "mismatch_count": int(len(mismatches)),
        "mismatches": mismatches[
            [
                "record_id",
                "ground_truth_label",
                "reconstructed_label",
                "ground_truth_score",
                "reconstructed_score",
                "ground_truth_factors",
                "reconstructed_factors",
            ]
        ].head(50).to_dict(
            orient="records"
        ),
    }


# =============================================================================
# Dataset loading and assurance checks
# =============================================================================

def load_dataset() -> dict[str, Any]:
    print("\n===== DATASET LOADING =====")

    features = pd.read_csv(
        FEATURE_FILE
    )

    observable = pd.read_csv(
        OBSERVABLE_FILE
    )

    reference = pd.read_csv(
        REFERENCE_FILE
    )

    labels = pd.read_csv(
        LABEL_FILE
    )

    splits = pd.read_csv(
        SPLIT_FILE
    )

    with GENERATION_FILE.open(
        "r",
        encoding="utf-8",
    ) as handle:
        generation = json.load(handle)

    with FEATURE_METADATA_FILE.open(
        "r",
        encoding="utf-8",
    ) as handle:
        feature_metadata = json.load(handle)

    print(
        f"Records: {len(features)}"
    )
    print(
        f"Features: {len(features.columns) - 1}"
    )
    print(
        f"Lineage groups: {splits['group_id'].nunique()}"
    )
    print(
        "Splits:",
        splits["split"].value_counts().to_dict(),
    )
    print(
        "Labels:",
        labels["ground_truth_label"].value_counts().to_dict(),
    )

    return {
        "features": features,
        "observable": observable,
        "reference": reference,
        "labels": labels,
        "splits": splits,
        "generation": generation,
        "feature_metadata": feature_metadata,
    }


def validate_dataset_contract(
    data: dict[str, Any],
) -> None:
    print("\n===== DATASET CONTRACT CHECKS =====")

    features = data["features"]
    observable = data["observable"]
    reference = data["reference"]
    labels = data["labels"]
    splits = data["splits"]
    generation = data["generation"]
    feature_metadata = data[
        "feature_metadata"
    ]

    assert len(features) == EXPECTED_RECORD_COUNT

    assert (
        len(features.columns) - 1
        == EXPECTED_FEATURE_COUNT
    )

    assert_required_columns(
        features,
        {"record_id"},
        "engineered_features.csv",
    )

    assert_required_columns(
        observable,
        {
            "record_id",
            "package_id",
            "lineage_id",
            "product_id",
            "asset_id",
            "observed_vendor_id",
            "observed_hash",
            "signature_valid",
            "trusted_root_valid",
            "sbom_present",
            "sbom_complete",
            "observed_version",
            "rollback_authorized",
            "vulnerability_present",
            "vulnerability_applicable",
            "unexpected_component",
            "evidence_age_days",
            "package_size_bytes",
            "component_count",
            "known_vulnerability_count",
            "max_cvss_score",
        },
        "observable_features.csv",
    )

    assert_required_columns(
        reference,
        {
            "record_id",
            "package_id",
            "lineage_id",
            "approved_vendor_id",
            "trusted_hash",
            "approved_version",
            "freshness_threshold_days",
            "approved_component_count",
        },
        "reference_data.csv",
    )

    assert_required_columns(
        labels,
        {
            "record_id",
            "ground_truth_label",
            "ground_truth_score",
            "ground_truth_factors",
        },
        "ground_truth_labels.csv",
    )

    assert_required_columns(
        splits,
        {
            "record_id",
            "package_id",
            "split",
            "group_id",
            "run_id",
        },
        "split_assignments.csv",
    )

    assert set(
        features["record_id"]
    ) == set(
        observable["record_id"]
    )

    assert set(
        features["record_id"]
    ) == set(
        labels["record_id"]
    )

    assert set(
        features["record_id"]
    ) == set(
        splits["record_id"]
    )

    assert len(reference) == EXPECTED_RECORD_COUNT

    assert (
        reference[
            [
                "record_id",
                "package_id",
                "lineage_id",
            ]
        ]
        .duplicated()
        .sum()
        == 0
    )

    split_counts = (
        splits["split"]
        .value_counts()
        .to_dict()
    )

    assert split_counts == EXPECTED_SPLIT_COUNTS

    label_counts = (
        labels[
            "ground_truth_label"
        ]
        .value_counts()
        .to_dict()
    )

    assert label_counts == EXPECTED_LABEL_COUNTS

    # Every lineage belongs to exactly one split.
    lineage_split_counts = (
        splits.groupby(
            "group_id"
        )["split"]
        .nunique()
    )

    assert (
        lineage_split_counts.max()
        == 1
    )

    # All classes must appear in all three splits.
    split_class = (
        splits[
            [
                "record_id",
                "split",
            ]
        ]
        .merge(
            labels[
                [
                    "record_id",
                    "ground_truth_label",
                ]
            ],
            on="record_id",
            validate="one_to_one",
        )
    )

    for split_name in [
        "train",
        "validation",
        "test",
    ]:
        observed_classes = set(
            split_class.loc[
                split_class["split"]
                == split_name,
                "ground_truth_label",
            ]
        )

        assert observed_classes == set(
            REPORT_CLASS_ORDER
        )

    feature_list = feature_metadata.get(
        "features",
        feature_metadata.get(
            "feature_names",
            [],
        ),
    )

    if isinstance(feature_list, dict):
        feature_list = list(
            feature_list.keys()
        )

    assert len(feature_list) == EXPECTED_FEATURE_COUNT

    # Explicit forbidden model inputs.
    forbidden_tokens = {
        "ground_truth",
        "ground_truth_label",
        "ground_truth_score",
        "ground_truth_factors",
        "scenario_type",
        "expected_decision",
        "risk_target",
        "target",
        "label",
        "scenario",
        "manifest",
        "run_id",
        "record_id",
        "group_id",
        "lineage_id",
        "split",
        "package_id",
    }

    feature_names = set(
        feature_list
    )

    forbidden_features = {
        feature
        for feature in feature_names
        if feature.lower()
        in forbidden_tokens
    }

    assert not forbidden_features, (
        "Forbidden feature names detected: "
        f"{sorted(forbidden_features)}"
    )

    print(
        "Dataset contract: PASS"
    )


# =============================================================================
# Model feature preparation
# =============================================================================

def prepare_model_frame(
    data: dict[str, Any],
) -> tuple[
    pd.DataFrame,
    pd.Series,
    pd.Series,
    pd.Series,
    list[str],
]:
    features = data["features"]
    labels = data["labels"]
    splits = data["splits"]

    feature_columns = [
        column
        for column in features.columns
        if column != "record_id"
    ]

    X = features[
        feature_columns
    ].copy()

    # Ensure numeric features only.
    for column in feature_columns:
        X[column] = pd.to_numeric(
            X[column],
            errors="raise",
        )

    if X.isna().any().any():
        raise AssertionError(
            "Training feature matrix contains NaN."
        )

    if not np.isfinite(
        X.to_numpy(dtype=float)
    ).all():
        raise AssertionError(
            "Training feature matrix contains non-finite values."
        )

    label_lookup = labels.set_index(
        "record_id"
    )["ground_truth_label"]

    split_lookup = splits.set_index(
        "record_id"
    )

    y = features[
        "record_id"
    ].map(label_lookup)

    split_series = features[
        "record_id"
    ].map(
        split_lookup["split"]
    )

    group_series = features[
        "record_id"
    ].map(
        split_lookup["group_id"]
    )

    if y.isna().any():
        raise AssertionError(
            "Some feature rows have no label."
        )

    if split_series.isna().any():
        raise AssertionError(
            "Some feature rows have no split."
        )

    if group_series.isna().any():
        raise AssertionError(
            "Some feature rows have no group."
        )

    return (
        X,
        y.astype(str),
        split_series.astype(str),
        group_series.astype(str),
        feature_columns,
    )


# =============================================================================
# Model specifications
# =============================================================================

def build_model_candidates() -> list[dict[str, Any]]:
    """
    Exact declared supervised candidate families and grids.

    Extra Trees is intentionally NOT included.
    """

    candidates: list[dict[str, Any]] = []

    # -------------------------------------------------------------------------
    # DummyClassifier
    # -------------------------------------------------------------------------

    dummy_grid = {
        "strategy": [
            "most_frequent",
            "stratified",
        ],
    }

    for params in ParameterGrid(
        dummy_grid
    ):
        candidates.append(
            {
                "family": "DummyClassifier",
                "estimator": DummyClassifier(
                    random_state=SEED,
                    **params,
                ),
                "params": params,
            }
        )

    # -------------------------------------------------------------------------
    # Logistic Regression
    # -------------------------------------------------------------------------

    logistic_grid = {
        "C": [
            0.01,
            0.1,
            1,
            10,
        ],
        "class_weight": [
            None,
            "balanced",
        ],
    }

    for params in ParameterGrid(
        logistic_grid
    ):
        estimator = Pipeline(
            [
                (
                    "scaler",
                    StandardScaler(),
                ),
                (
                    "model",
                    LogisticRegression(
                        solver="lbfgs",
                        max_iter=2000,
                        random_state=SEED,
                        **params,
                    ),
                ),
            ]
        )

        candidates.append(
            {
                "family": "LogisticRegression",
                "estimator": estimator,
                "params": params,
            }
        )

    # -------------------------------------------------------------------------
    # Random Forest
    # -------------------------------------------------------------------------

    rf_grid = {
        "n_estimators": [
            300,
            600,
        ],
        "max_depth": [
            None,
            8,
            16,
        ],
        "min_samples_leaf": [
            1,
            5,
            10,
        ],
        "max_features": [
            "sqrt",
            0.75,
        ],
        "class_weight": [
            None,
            "balanced",
        ],
    }

    for params in ParameterGrid(
        rf_grid
    ):
        estimator = RandomForestClassifier(
            random_state=SEED,
            n_jobs=1,
            **params,
        )

        candidates.append(
            {
                "family": "RandomForestClassifier",
                "estimator": estimator,
                "params": params,
            }
        )

    # -------------------------------------------------------------------------
    # HistGradientBoosting
    # -------------------------------------------------------------------------

    hgb_grid = {
        "learning_rate": [
            0.03,
            0.1,
        ],
        "max_iter": [
            200,
            400,
        ],
        "max_leaf_nodes": [
            15,
            31,
        ],
        "min_samples_leaf": [
            10,
            20,
        ],
        "l2_regularization": [
            0,
            1,
        ],
        "weighting": [
            "unweighted",
            "balanced",
        ],
    }

    for params in ParameterGrid(
        hgb_grid
    ):
        model_params = {
            key: value
            for key, value in params.items()
            if key != "weighting"
        }

        estimator = HistGradientBoostingClassifier(
            random_state=SEED,
            **model_params,
        )

        candidates.append(
            {
                "family": "HistGradientBoostingClassifier",
                "estimator": estimator,
                "params": params,
            }
        )

    return candidates


# =============================================================================
# Cross-validation
# =============================================================================

def balanced_sample_weights(
    y: pd.Series,
) -> np.ndarray:
    counts = y.value_counts()

    total = len(y)
    n_classes = len(counts)

    weights = {
        label: total / (
            n_classes * count
        )
        for label, count in counts.items()
    }

    return y.map(weights).to_numpy(
        dtype=float
    )


def fit_candidate(
    candidate: dict[str, Any],
    X_train: pd.DataFrame,
    y_train: pd.Series,
) -> Any:
    estimator = clone(
        candidate["estimator"]
    )

    if (
        candidate["family"]
        == "HistGradientBoostingClassifier"
        and candidate["params"]["weighting"]
        == "balanced"
    ):
        sample_weight = balanced_sample_weights(
            y_train
        )

        estimator.fit(
            X_train,
            y_train,
            sample_weight=sample_weight,
        )

    else:
        estimator.fit(
            X_train,
            y_train,
        )

    return estimator


def cv_candidate(
    candidate: dict[str, Any],
    X_train: pd.DataFrame,
    y_train: pd.Series,
    groups_train: pd.Series,
) -> dict[str, Any]:
    cv = GroupKFold(
        n_splits=N_CV_FOLDS
    )

    fold_results = []

    for fold_index, (
        fit_index,
        validation_index,
    ) in enumerate(
        cv.split(
            X_train,
            y_train,
            groups=groups_train,
        ),
        start=1,
    ):
        X_fit = X_train.iloc[
            fit_index
        ]
        y_fit = y_train.iloc[
            fit_index
        ]

        X_fold_validation = (
            X_train.iloc[
                validation_index
            ]
        )
        y_fold_validation = (
            y_train.iloc[
                validation_index
            ]
        )

        model = fit_candidate(
            candidate,
            X_fit,
            y_fit,
        )

        predictions = model.predict(
            X_fold_validation
        )

        fold_macro_f1 = f1_score(
            y_fold_validation,
            predictions,
            labels=REPORT_CLASS_ORDER,
            average="macro",
            zero_division=0,
        )

        fold_high_risk_recall = recall_score(
            y_fold_validation,
            predictions,
            labels=[
                "high_risk"
            ],
            average="macro",
            zero_division=0,
        )

        per_class_f1 = f1_score(
            y_fold_validation,
            predictions,
            labels=REPORT_CLASS_ORDER,
            average=None,
            zero_division=0,
        )

        fold_results.append(
            {
                "fold": fold_index,
                "macro_f1": float(
                    fold_macro_f1
                ),
                "high_risk_recall": float(
                    fold_high_risk_recall
                ),
                "min_per_class_f1": float(
                    min(per_class_f1)
                ),
            }
        )

    return {
        "cv_macro_f1_mean": float(
            np.mean(
                [
                    row["macro_f1"]
                    for row in fold_results
                ]
            )
        ),
        "cv_macro_f1_std": float(
            np.std(
                [
                    row["macro_f1"]
                    for row in fold_results
                ]
            )
        ),
        "cv_high_risk_recall_mean": float(
            np.mean(
                [
                    row[
                        "high_risk_recall"
                    ]
                    for row in fold_results
                ]
            )
        ),
        "cv_min_per_class_f1_mean": float(
            np.mean(
                [
                    row[
                        "min_per_class_f1"
                    ]
                    for row in fold_results
                ]
            )
        ),
        "folds": fold_results,
    }


# =============================================================================
# Validation candidate evaluation and selection
# =============================================================================

def evaluate_uncalibrated_candidate(
    model: Any,
    X_validation: pd.DataFrame,
    y_validation: pd.Series,
) -> dict[str, Any]:
    predictions = model.predict(
        X_validation
    )

    probabilities = model.predict_proba(
        X_validation
    )

    mapped_probabilities = (
        map_probabilities_to_report_order(
            model.classes_,
            probabilities,
        )
    )

    metrics = classification_metrics(
        y_validation.to_numpy(),
        predictions,
        mapped_probabilities,
    )

    return metrics


def candidate_selection_key(
    result: dict[str, Any],
) -> tuple:
    """
    Approved selection ordering:

    1. validation Macro-F1
    2. high-risk recall
    3. minimum per-class F1
    4. lower log-loss
    5. lower complexity

    Complexity is represented by a deterministic family/parameter complexity
    score generated separately.
    """

    return (
        result["validation"]["macro_f1"],
        result["validation"][
            "high_risk_recall"
        ],
        result["validation"][
            "min_per_class_f1"
        ],
        -result["validation"]["log_loss"],
        -result["complexity_score"],
    )


def complexity_score(
    family: str,
    params: dict[str, Any],
) -> float:
    if family == "DummyClassifier":
        return 1.0

    if family == "LogisticRegression":
        return 10.0 + abs(
            math.log10(
                float(params["C"])
            )
        )

    if family == "RandomForestClassifier":
        estimators = float(
            params["n_estimators"]
        )
        depth = (
            32.0
            if params["max_depth"]
            is None
            else float(
                params["max_depth"]
            )
        )

        return (
            100.0
            + estimators / 100.0
            + depth
            + float(
                params["min_samples_leaf"]
            )
        )

    if family == "HistGradientBoostingClassifier":
        return (
            50.0
            + float(
                params["max_iter"]
            )
            / 10.0
            + float(
                params["max_leaf_nodes"]
            )
            + float(
                params["min_samples_leaf"]
            )
        )

    return 1000.0


# =============================================================================
# Calibration
# =============================================================================

def fit_sigmoid_calibrator(
    frozen_selected_model: Any,
    X_validation: pd.DataFrame,
    y_validation: pd.Series,
) -> Any:
    """
    Fit sigmoid calibration exclusively on validation predictions/labels.

    The selected classifier itself is already frozen after training on the
    complete training split.
    """

    try:
        from sklearn.frozen import FrozenEstimator
    except ImportError as exc:
        raise RuntimeError(
            "scikit-learn 1.9 FrozenEstimator is required "
            "for the approved validation-only calibration procedure."
        ) from exc

    calibrator = CalibratedClassifierCV(
        FrozenEstimator(
            frozen_selected_model
        ),
        method="sigmoid",
        cv=None,
    )

    calibrator.fit(
        X_validation,
        y_validation,
    )

    return calibrator


# =============================================================================
# Isolation Forest
# =============================================================================

def isolation_forest_evaluation(
    X_train: pd.DataFrame,
    y_train: pd.Series,
    X_validation: pd.DataFrame,
    y_validation: pd.Series,
    X_test: pd.DataFrame,
    y_test: pd.Series,
) -> dict[str, Any]:
    """
    Isolation Forest is trained only on immutable normal training rows.

    No scenario metadata is consulted.
    Validation labels are used only to choose the threshold.
    Test is evaluated after threshold freeze.
    """

    normal_mask = (
        y_train == "normal"
    )

    X_train_normal = X_train.loc[
        normal_mask
    ]

    if len(X_train_normal) == 0:
        raise AssertionError(
            "Isolation Forest has no normal training rows."
        )

    model = IsolationForest(
        random_state=SEED,
        n_jobs=1,
        contamination="auto",
    )

    model.fit(
        X_train_normal
    )

    # Higher score means more anomalous.
    validation_anomaly_score = (
        -model.score_samples(
            X_validation
        )
    )

    y_validation_anomaly = (
        y_validation != "normal"
    ).astype(int).to_numpy()
    y_validation_anomaly = np.asarray(
        y_validation_anomaly
    )

    validation_auroc = roc_auc_score(
        y_validation_anomaly,
        validation_anomaly_score,
    )

    validation_auprc = average_precision_score(
        y_validation_anomaly,
        validation_anomaly_score,
    )

    # Choose the highest-recall threshold subject to FPR <= 5%.
    normal_validation = (
        y_validation_anomaly == 0
    )
    anomalous_validation = (
        y_validation_anomaly == 1
    )

    normal_scores = np.sort(
        validation_anomaly_score[
            normal_validation
        ]
    )

    candidate_thresholds = (
        np.unique(
            validation_anomaly_score
        )
    )

    best_threshold = float(
        candidate_thresholds[0]
    )
    best_recall = -1.0
    best_fpr = 1.0

    for threshold in candidate_thresholds:
        predicted_anomaly = (
            validation_anomaly_score
            >= threshold
        )

        false_positive_rate = (
            predicted_anomaly[
                normal_validation
            ].mean()
            if np.any(normal_validation)
            else 0.0
        )

        true_positive_rate = (
            predicted_anomaly[
                anomalous_validation
            ].mean()
            if np.any(anomalous_validation)
            else 0.0
        )

        if false_positive_rate <= 0.05:
            candidate_key = (
                true_positive_rate,
                -false_positive_rate,
                float(threshold),
            )

            best_key = (
                best_recall,
                -best_fpr,
                best_threshold,
            )

            if candidate_key > best_key:
                best_recall = float(
                    true_positive_rate
                )
                best_fpr = float(
                    false_positive_rate
                )
                best_threshold = float(
                    threshold
                )

    validation_predicted_anomaly = (
        validation_anomaly_score
        >= best_threshold
    )

    validation_confusion = confusion_matrix(
        y_validation_anomaly,
        validation_predicted_anomaly.astype(int),
        labels=[0, 1],
    )

    # Test is now evaluated after threshold freeze.
    test_anomaly_score = (
        -model.score_samples(
            X_test
        )
    )

    y_test_anomaly = (
        y_test != "normal"
    ).astype(int).to_numpy()

    test_predicted_anomaly = (
        test_anomaly_score
        >= best_threshold
    )

    test_auroc = roc_auc_score(
        y_test_anomaly,
        test_anomaly_score,
    )

    test_auprc = average_precision_score(
        y_test_anomaly,
        test_anomaly_score,
    )

    test_recall_at_threshold = recall_score(
        y_test_anomaly,
        test_predicted_anomaly.astype(int),
        zero_division=0,
    )

    test_normal = (
        y_test_anomaly == 0
    )

    test_fpr = (
        test_predicted_anomaly[
            test_normal
        ].mean()
        if np.any(test_normal)
        else 0.0
    )

    test_confusion = confusion_matrix(
        y_test_anomaly,
        test_predicted_anomaly.astype(int),
        labels=[0, 1],
    )

    gate = {
        "auroc": (
            test_auroc
            >= GATES[
                "isolation_forest_auroc"
            ]
        ),
        "auprc": (
            test_auprc
            >= GATES[
                "isolation_forest_auprc"
            ]
        ),
        "recall_at_5pct_fpr": (
            test_recall_at_threshold
            >= GATES[
                "isolation_forest_recall_at_5pct_fpr"
            ]
        ),
    }

    model_path = (
        MODEL_DIR
        / "isolation_forest.joblib"
    )

    joblib.dump(
        model,
        model_path,
    )

    return {
        "training_rows": int(
            len(X_train_normal)
        ),
        "training_label_restriction": (
            "ground_truth_label == normal"
        ),
        "validation_auroc": float(
            validation_auroc
        ),
        "validation_auprc": float(
            validation_auprc
        ),
        "validation_selected_threshold": float(
            best_threshold
        ),
        "validation_recall_at_threshold": float(
            best_recall
        ),
        "validation_fpr_at_threshold": float(
            best_fpr
        ),
        "validation_confusion_matrix": (
            validation_confusion.tolist()
        ),
        "test_auroc": float(
            test_auroc
        ),
        "test_auprc": float(
            test_auprc
        ),
        "test_recall_at_selected_threshold": float(
            test_recall_at_threshold
        ),
        "test_fpr_at_selected_threshold": float(
            test_fpr
        ),
        "test_confusion_matrix": (
            test_confusion.tolist()
        ),
        "gates": gate,
        "all_pass": all(
            gate.values()
        ),
        "artifact": str(
            model_path.relative_to(
                PROJECT_ROOT
            )
        ),
    }


# =============================================================================
# Robustness / malformed / adversarial / OOD evaluation
# =============================================================================

def robustness_evaluation(
    model: Any,
    X_test: pd.DataFrame,
    y_test: pd.Series,
) -> dict[str, Any]:
    """
    Controlled robustness mutation suite.

    IMPORTANT:
    - Uses a separate approved robustness seed.
    - Does not alter the frozen dataset.
    - Mutations are applied to copies only.
    - NaN/Inf/malformed/OOD cases are evaluated as model-input stress tests.
    """

    rng = np.random.default_rng(
        ROBUSTNESS_SEED
    )

    baseline_predictions = model.predict(
        X_test
    )

    baseline_accuracy = accuracy_score(
        y_test,
        baseline_predictions,
    )

    cases: dict[str, pd.DataFrame] = {}

    # -------------------------------------------------------------------------
    # Missing feature
    # -------------------------------------------------------------------------

    missing_case = X_test.copy()
    missing_column = (
        X_test.columns[0]
    )

    missing_case[missing_column] = np.nan
    cases["missing_feature"] = (
        missing_case
    )

    # -------------------------------------------------------------------------
    # NaN stress
    # -------------------------------------------------------------------------

    nan_case = X_test.astype(
        float
    ).copy()

    nan_row = int(
        rng.integers(
            0,
            len(nan_case),
        )
    )

    nan_col = int(
        rng.integers(
            0,
            nan_case.shape[1],
        )
    )

    nan_case.iloc[
        nan_row,
        nan_col
    ] = np.nan

    cases["nan"] = nan_case

    # -------------------------------------------------------------------------
    # Inf stress
    #
    # Convert to float first. This is required for Pandas 3.x because assigning
    # np.inf to an integer-typed column is rejected.
    # -------------------------------------------------------------------------

    inf_case = X_test.astype(
        float
    ).copy()

    inf_row = int(
        rng.integers(
            0,
            len(inf_case),
        )
    )

    inf_col = int(
        rng.integers(
            0,
            inf_case.shape[1],
        )
    )

    inf_case.iloc[
        inf_row,
        inf_col
    ] = np.inf

    cases["inf"] = inf_case

    # -------------------------------------------------------------------------
    # Small numeric perturbation
    # -------------------------------------------------------------------------

    perturb_case = X_test.astype(
        float
    ).copy()

    numeric_scale = (
        perturb_case.std(
            axis=0
        ).replace(
            0,
            1.0,
        )
    )

    noise = rng.normal(
        loc=0.0,
        scale=0.05,
        size=perturb_case.shape,
    )

    perturb_case = (
        perturb_case
        + noise
        * numeric_scale.to_numpy()
    )

    cases["small_numeric_perturbation"] = (
        perturb_case
    )

    # -------------------------------------------------------------------------
    # OOD high-magnitude stress
    # -------------------------------------------------------------------------

    ood_case = X_test.astype(
        float
    ).copy()

    means = ood_case.mean(
        axis=0
    )

    stds = ood_case.std(
        axis=0
    ).replace(
        0,
        1.0,
    )

    direction = rng.choice(
        [-1.0, 1.0],
        size=ood_case.shape,
    )

    ood_values = (
        means.to_numpy()[None, :]
        + direction
        * 10.0
        * stds.to_numpy()[None, :]
    )

    ood_case = pd.DataFrame(
        ood_values,
        index=ood_case.index,
        columns=ood_case.columns,
    )

    cases["ood_10_sigma"] = (
        ood_case
    )

    results = {}

    for name, frame in cases.items():
        try:
            predictions = model.predict(
                frame
            )

            results[name] = {
                "accepted": True,
                "prediction_count": int(
                    len(predictions)
                ),
                "class_distribution": (
                    pd.Series(
                        predictions
                    )
                    .value_counts()
                    .to_dict()
                ),
                "error": None,
            }

        except Exception as exc:
            results[name] = {
                "accepted": False,
                "prediction_count": 0,
                "class_distribution": {},
                "error": (
                    f"{type(exc).__name__}: "
                    f"{exc}"
                ),
            }

    return {
        "seed": ROBUSTNESS_SEED,
        "baseline_accuracy": float(
            baseline_accuracy
        ),
        "cases": results,
    }


# =============================================================================
# Explainability
# =============================================================================

def global_permutation_importance(
    model: Any,
    X_validation: pd.DataFrame,
    y_validation: pd.Series,
    feature_names: list[str],
) -> dict[str, Any]:
    result = permutation_importance(
        model,
        X_validation,
        y_validation,
        scoring="f1_macro",
        n_repeats=20,
        random_state=SEED,
        n_jobs=1,
    )

    ranking = []

    for index, feature in enumerate(
        feature_names
    ):
        ranking.append(
            {
                "feature": feature,
                "importance_mean": float(
                    result.importances_mean[
                        index
                    ]
                ),
                "importance_std": float(
                    result.importances_std[
                        index
                    ]
                ),
            }
        )

    ranking.sort(
        key=lambda row: row[
            "importance_mean"
        ],
        reverse=True,
    )

    return {
        "method": (
            "Global permutation importance"
        ),
        "metric": "macro_f1",
        "repeats": 20,
        "seed": SEED,
        "ranking": ranking,
    }


def local_model_sensitivity(
    model: Any,
    X_test: pd.DataFrame,
    feature_names: list[str],
    n_records: int = 25,
) -> dict[str, Any]:
    """
    Local explanation contract:

    For each selected test record, zero one feature at a time and observe the
    probability changes.

    These are model-sensitivity indicators, not causal explanations.
    """

    selected = X_test.iloc[
        : min(n_records, len(X_test))
    ].copy()

    baseline_probabilities = (
        map_probabilities_to_report_order(
            model.classes_,
            model.predict_proba(
                selected
            ),
        )
    )

    records = []

    for row_position, (_, row) in enumerate(
        selected.iterrows()
    ):
        baseline = (
            baseline_probabilities[
                row_position
            ]
        )

        changes = []

        for feature in feature_names:
            mutated = selected.copy()

            # One-feature baseline ablation.
            mutated.iloc[
                row_position,
                mutated.columns.get_loc(
                    feature
                )
            ] = 0.0

            mutated_probabilities = (
                map_probabilities_to_report_order(
                    model.classes_,
                    model.predict_proba(
                        mutated
                    ),
                )
            )

            changed = (
                mutated_probabilities[
                    row_position
                ]
                - baseline
            )

            changes.append(
                {
                    "feature": feature,
                    "absolute_probability_change": float(
                        np.max(
                            np.abs(
                                changed
                            )
                        )
                    ),
                    "probability_change": {
                        label: float(
                            changed[index]
                        )
                        for index, label in enumerate(
                            REPORT_CLASS_ORDER
                        )
                    },
                }
            )

        changes.sort(
            key=lambda item: item[
                "absolute_probability_change"
            ],
            reverse=True,
        )

        records.append(
            {
                "record_index": int(
                    row_position
                ),
                "top_5": changes[:5],
            }
        )

    return {
        "method": (
            "One-feature baseline ablation"
        ),
        "records_evaluated": len(records),
        "interpretation": (
            "Model-sensitivity indicators; "
            "not causal explanations."
        ),
        "records": records,
    }


# =============================================================================
# Technical subgroup analysis
# =============================================================================

def subgroup_analysis(
    model: Any,
    X_test: pd.DataFrame,
    y_test: pd.Series,
    observable: pd.DataFrame,
    splits: pd.DataFrame,
) -> dict[str, Any]:
    merged = (
        splits[
            [
                "record_id",
            ]
        ]
        .merge(
            observable,
            on="record_id",
            validate="one_to_one",
        )
    )

    # Keep exact X_test order.
    test_ids = (
        splits.loc[
            splits["split"] == "test",
            "record_id",
        ]
        .tolist()
    )

    merged = (
        pd.DataFrame(
            {
                "record_id": test_ids
            }
        )
        .merge(
            merged,
            on="record_id",
            validate="one_to_one",
        )
    )

    predictions = model.predict(
        X_test
    )

    merged["y_true"] = (
        y_test.to_numpy()
    )
    merged["prediction"] = (
        predictions
    )

    def summarize(
        frame: pd.DataFrame,
    ) -> dict[str, Any]:
        if len(frame) == 0:
            return {
                "count": 0
            }

        return {
            "count": int(
                len(frame)
            ),
            "accuracy": float(
                accuracy_score(
                    frame["y_true"],
                    frame["prediction"],
                )
            ),
            "macro_f1": float(
                f1_score(
                    frame["y_true"],
                    frame["prediction"],
                    labels=REPORT_CLASS_ORDER,
                    average="macro",
                    zero_division=0,
                )
            ),
            "high_risk_recall": float(
                recall_score(
                    frame["y_true"],
                    frame["prediction"],
                    labels=[
                        "high_risk"
                    ],
                    average="macro",
                    zero_division=0,
                )
            ),
        }

    result = {
        "vendor": {},
        "product": {},
        "lineage": {},
        "evidence_failure": {},
    }

    for value, frame in merged.groupby(
        "observed_vendor_id"
    ):
        result["vendor"][
            str(value)
        ] = summarize(frame)

    for value, frame in merged.groupby(
        "product_id"
    ):
        result["product"][
            str(value)
        ] = summarize(frame)

    for value, frame in merged.groupby(
        "lineage_id"
    ):
        result["lineage"][
            str(value)
        ] = summarize(frame)

    evidence_failure_mask = (
        (~merged["signature_valid"].astype(bool))
        | (~merged["trusted_root_valid"].astype(bool))
        | (~merged["sbom_present"].astype(bool))
        | (~merged["sbom_complete"].astype(bool))
        | (
            merged["vulnerability_present"].astype(bool)
            & merged[
                "vulnerability_applicable"
            ].astype(bool)
        )
        | merged[
            "unexpected_component"
        ].astype(bool)
        | (
            merged[
                "evidence_age_days"
            ]
            > 30
        )
    )

    result["evidence_failure"][
        "failure_present"
    ] = summarize(
        merged.loc[
            evidence_failure_mask
        ]
    )

    result["evidence_failure"][
        "failure_absent"
    ] = summarize(
        merged.loc[
            ~evidence_failure_mask
        ]
    )

    return result


# =============================================================================
# Assertion tests generated as experiment evidence
# =============================================================================

def run_ml_assertions(
    data: dict[str, Any],
    candidate_results: list[dict[str, Any]],
    selected: dict[str, Any],
    deterministic_policy: dict[str, Any],
) -> dict[str, Any]:
    features = data["features"]
    labels = data["labels"]
    splits = data["splits"]

    assertions = {}

    def check(
        name: str,
        condition: bool,
    ) -> None:
        assertions[name] = bool(
            condition
        )
        if not condition:
            raise AssertionError(
                f"ML assurance assertion failed: {name}"
            )

    check(
        "feature_count_22",
        len(features.columns) - 1
        == 22,
    )

    check(
        "record_count_5000",
        len(features) == 5000,
    )

    check(
        "split_train_3500",
        int(
            (splits["split"] == "train")
            .sum()
        )
        == 3500,
    )

    check(
        "split_validation_750",
        int(
            (splits["split"] == "validation")
            .sum()
        )
        == 750,
    )

    check(
        "split_test_750",
        int(
            (splits["split"] == "test")
            .sum()
        )
        == 750,
    )

    check(
        "lineage_no_cross_split_leakage",
        (
            splits.groupby(
                "group_id"
            )["split"]
            .nunique()
            .max()
            == 1
        ),
    )

    check(
        "candidate_count_146",
        len(candidate_results)
        == 146,
    )

    check(
        "selected_family_not_extra_trees",
        "ExtraTrees"
        not in selected["family"],
    )

    check(
        "deterministic_policy_exact",
        deterministic_policy[
            "overall_exact_fidelity"
        ]
        == 1.0,
    )

    check(
        "all_candidates_have_cv",
        all(
            "cv"
            in candidate
            for candidate in candidate_results
        ),
    )

    check(
        "all_candidates_have_validation",
        all(
            "validation"
            in candidate
            for candidate in candidate_results
        ),
    )

    return {
        "all_pass": all(
            assertions.values()
        ),
        "assertions": assertions,
    }


# =============================================================================
# Main experiment
# =============================================================================

def main() -> None:
    experiment_id = (
        f"ML-EXP-{utc_now()}"
    )

    print(
        "\n============================================================"
    )
    print(
        "CONTROLLED ML TRAINING AND EVALUATION"
    )
    print(
        "Firmware & Supply-Chain Assurance PoC"
    )
    print(
        "============================================================"
    )

    print(
        f"Experiment ID: {experiment_id}"
    )
    print(
        f"Python: {platform.python_version()}"
    )
    print(
        f"NumPy: {np.__version__}"
    )
    print(
        f"Pandas: {pd.__version__}"
    )

    import sklearn

    print(
        f"Scikit-learn: {sklearn.__version__}"
    )
    print(
        f"Joblib: {joblib.__version__}"
    )
    print(
        f"Training seed: {SEED}"
    )
    print(
        f"Robustness seed: {ROBUSTNESS_SEED}"
    )

    warnings.filterwarnings(
        "ignore",
        category=UserWarning,
    )

    # -------------------------------------------------------------------------
    # Load frozen dataset
    # -------------------------------------------------------------------------

    data = load_dataset()

    validate_dataset_contract(
        data
    )

    (
        X,
        y,
        split_series,
        group_series,
        feature_names,
    ) = prepare_model_frame(
        data
    )

    train_mask = (
        split_series == "train"
    )
    validation_mask = (
        split_series == "validation"
    )
    test_mask = (
        split_series == "test"
    )

    X_train = X.loc[
        train_mask
    ].copy()

    y_train = y.loc[
        train_mask
    ].copy()

    groups_train = group_series.loc[
        train_mask
    ].copy()

    X_validation = X.loc[
        validation_mask
    ].copy()

    y_validation = y.loc[
        validation_mask
    ].copy()

    X_test = X.loc[
        test_mask
    ].copy()

    y_test = y.loc[
        test_mask
    ].copy()

    # -------------------------------------------------------------------------
    # Deterministic policy fidelity
    # -------------------------------------------------------------------------

    print(
        "\n===== DETERMINISTIC POLICY FIDELITY ====="
    )

    policy_fidelity = (
        deterministic_policy_fidelity(
            data["observable"],
            data["reference"],
            data["labels"],
        )
    )

    print(
        "Exact fidelity:",
        policy_fidelity[
            "overall_exact_fidelity"
        ],
    )
    print(
        "Label fidelity:",
        policy_fidelity[
            "label_fidelity"
        ],
    )
    print(
        "Score fidelity:",
        policy_fidelity[
            "score_fidelity"
        ],
    )
    print(
        "Factor fidelity:",
        policy_fidelity[
            "factor_fidelity"
        ],
    )
    print(
        "Mismatches:",
        policy_fidelity[
            "mismatch_count"
        ],
    )

    if (
        policy_fidelity[
            "overall_exact_fidelity"
        ]
        != 1.0
    ):
        raise RuntimeError(
            "Deterministic policy fidelity is not exact. "
            "Experiment stopped before ML training."
        )

    # -------------------------------------------------------------------------
    # Candidate generation
    # -------------------------------------------------------------------------

    candidates = build_model_candidates()

    print(
        "\n===== MODEL CANDIDATE SEARCH ====="
    )
    print(
        f"Candidate count: {len(candidates)}"
    )

    if len(candidates) != 146:
        raise AssertionError(
            f"Expected 146 candidates, got {len(candidates)}"
        )

    candidate_results = []

    # -------------------------------------------------------------------------
    # Grouped CV + train refit + validation evaluation
    # -------------------------------------------------------------------------

    for index, candidate in enumerate(
        candidates,
        start=1,
    ):
        print(
            f"[{index:03d}/{len(candidates):03d}] "
            f"{candidate['family']} "
            f"{candidate['params']}"
        )

        cv_result = cv_candidate(
            candidate,
            X_train,
            y_train,
            groups_train,
        )

        # Refit tuned candidate on complete train split.
        fitted_model = fit_candidate(
            candidate,
            X_train,
            y_train,
        )

        validation_result = (
            evaluate_uncalibrated_candidate(
                fitted_model,
                X_validation,
                y_validation,
            )
        )

        result = {
            "candidate_index": index,
            "family": candidate[
                "family"
            ],
            "params": candidate[
                "params"
            ],
            "cv": cv_result,
            "validation": validation_result,
            "complexity_score": complexity_score(
                candidate[
                    "family"
                ],
                candidate[
                    "params"
                ],
            ),
            "model": fitted_model,
        }

        candidate_results.append(
            result
        )

        print(
            "    CV Macro-F1:",
            f"{cv_result['cv_macro_f1_mean']:.6f}",
        )
        print(
            "    Validation Macro-F1:",
            f"{validation_result['macro_f1']:.6f}",
        )
        print(
            "    Validation HR recall:",
            f"{validation_result['high_risk_recall']:.6f}",
        )

    # -------------------------------------------------------------------------
    # Selection
    # -------------------------------------------------------------------------

    selected = max(
        candidate_results,
        key=candidate_selection_key,
    )

    selected_model = selected[
        "model"
    ]

    print(
        "\n===== MODEL SELECTION ====="
    )
    print(
        "Selected candidate:",
        selected[
            "candidate_index"
        ],
    )
    print(
        "Family:",
        selected["family"],
    )
    print(
        "Parameters:",
        selected["params"],
    )
    print(
        "Validation Macro-F1:",
        selected["validation"][
            "macro_f1"
        ],
    )
    print(
        "Validation high-risk recall:",
        selected["validation"][
            "high_risk_recall"
        ],
    )

    # Remove fitted estimator from serializable candidate table later.
    candidate_result_summaries = []

    for result in candidate_results:
        candidate_result_summaries.append(
            {
                key: value
                for key, value in result.items()
                if key != "model"
            }
        )

    # -------------------------------------------------------------------------
    # Freeze selected uncalibrated model
    # -------------------------------------------------------------------------

    selected_model_path = (
        MODEL_DIR
        / "selected_uncalibrated_model.joblib"
    )

    joblib.dump(
        selected_model,
        selected_model_path,
    )

    # -------------------------------------------------------------------------
    # Validation-only sigmoid calibration
    # -------------------------------------------------------------------------

    print(
        "\n===== VALIDATION-ONLY CALIBRATION ====="
    )

    calibrated_model = (
        fit_sigmoid_calibrator(
            selected_model,
            X_validation,
            y_validation,
        )
    )

    calibrated_model_path = (
        MODEL_DIR
        / "selected_calibrated_model.joblib"
    )

    joblib.dump(
        calibrated_model,
        calibrated_model_path,
    )

    validation_calibrated_probabilities = (
        map_probabilities_to_report_order(
            calibrated_model.classes_,
            calibrated_model.predict_proba(
                X_validation
            ),
        )
    )

    validation_calibrated_predictions = (
        probabilities_to_predictions(
            validation_calibrated_probabilities
        )
    )

    validation_calibrated_metrics = (
        classification_metrics(
            y_validation.to_numpy(),
            validation_calibrated_predictions,
            validation_calibrated_probabilities,
        )
    )

    print(
        "Validation calibrated Macro-F1:",
        validation_calibrated_metrics[
            "macro_f1"
        ],
    )
    print(
        "Validation calibrated log-loss:",
        validation_calibrated_metrics[
            "log_loss"
        ],
    )

    # Diagnostic only. Validation labels were used to fit the calibrator, so
    # these results are NOT final acceptance evidence.
    validation_calibration_diagnostic = {
        "purpose": (
            "Diagnostic only; validation labels "
            "were used to fit the sigmoid calibrator."
        ),
        "metrics": validation_calibrated_metrics,
    }

    # -------------------------------------------------------------------------
    # Freeze calibrated model
    # -------------------------------------------------------------------------

    print(
        "\n===== MODEL FREEZE ====="
    )

    print(
        "Selected model frozen."
    )
    print(
        "Calibration frozen."
    )
    print(
        "No model/threshold changes after this point."
    )

    # -------------------------------------------------------------------------
    # Test evaluation
    # -------------------------------------------------------------------------

    print(
        "\n===== FINAL TEST EVALUATION ====="
    )

    test_probabilities = (
        map_probabilities_to_report_order(
            calibrated_model.classes_,
            calibrated_model.predict_proba(
                X_test
            ),
        )
    )

    test_predictions = (
        probabilities_to_predictions(
            test_probabilities
        )
    )

    test_metrics = classification_metrics(
        y_test.to_numpy(),
        test_predictions,
        test_probabilities,
    )

    test_gates = gate_results(
        test_metrics
    )

    print(
        "Test Macro-F1:",
        f"{test_metrics['macro_f1']:.6f}",
    )
    print(
        "Test high-risk recall:",
        f"{test_metrics['high_risk_recall']:.6f}",
    )
    print(
        "Test Brier:",
        f"{test_metrics['multiclass_brier']:.6f}",
    )
    print(
        "Test log-loss:",
        f"{test_metrics['log_loss']:.6f}",
    )
    print(
        "Test ECE:",
        f"{test_metrics['ece_fixed_10_bins']:.6f}",
    )

    print(
        "Mandatory classification gates:",
        "PASS"
        if test_gates["all_pass"]
        else "FAIL",
    )

    # -------------------------------------------------------------------------
    # Isolation Forest
    # -------------------------------------------------------------------------

    print(
        "\n===== ISOLATION FOREST ====="
    )

    isolation_results = (
        isolation_forest_evaluation(
            X_train,
            y_train,
            X_validation,
            y_validation,
            X_test,
            y_test,
        )
    )

    print(
        "Test AUROC:",
        isolation_results[
            "test_auroc"
        ],
    )
    print(
        "Test AUPRC:",
        isolation_results[
            "test_auprc"
        ],
    )
    print(
        "Test recall at selected threshold:",
        isolation_results[
            "test_recall_at_selected_threshold"
        ],
    )
    print(
        "Isolation Forest gates:",
        "PASS"
        if isolation_results["all_pass"]
        else "FAIL",
    )

    # -------------------------------------------------------------------------
    # Explainability
    # -------------------------------------------------------------------------

    print(
        "\n===== GLOBAL EXPLAINABILITY ====="
    )

    global_importance = (
        global_permutation_importance(
            selected_model,
            X_validation,
            y_validation,
            feature_names,
        )
    )

    print(
        "Top features:"
    )

    for row in global_importance[
        "ranking"
    ][:10]:
        print(
            f"  {row['feature']}: "
            f"{row['importance_mean']:.6f}"
        )

    print(
        "\n===== LOCAL EXPLAINABILITY ====="
    )

    local_explanations = (
        local_model_sensitivity(
            selected_model,
            X_test,
            feature_names,
            n_records=25,
        )
    )

    print(
        "Local records evaluated:",
        local_explanations[
            "records_evaluated"
        ],
    )

    # -------------------------------------------------------------------------
    # Robustness
    # -------------------------------------------------------------------------

    print(
        "\n===== ROBUSTNESS / MALFORMED / OOD ====="
    )

    robustness_results = (
        robustness_evaluation(
            selected_model,
            X_test,
            y_test,
        )
    )

    for name, result in (
        robustness_results[
            "cases"
        ].items()
    ):
        print(
            f"{name}: "
            f"{'handled' if result['accepted'] else 'rejected'}"
        )

    # -------------------------------------------------------------------------
    # Technical subgroup analysis
    # -------------------------------------------------------------------------

    print(
        "\n===== TECHNICAL SUBGROUP ANALYSIS ====="
    )

    subgroup_results = subgroup_analysis(
        selected_model,
        X_test,
        y_test,
        data["observable"],
        data["splits"],
    )

    print(
        "Vendor groups:",
        len(
            subgroup_results[
                "vendor"
            ]
        ),
    )
    print(
        "Product groups:",
        len(
            subgroup_results[
                "product"
            ]
        ),
    )
    print(
        "Lineage groups:",
        len(
            subgroup_results[
                "lineage"
            ]
        ),
    )

    # -------------------------------------------------------------------------
    # ML assurance assertions
    # -------------------------------------------------------------------------

    print(
        "\n===== ML ASSURANCE ASSERTIONS ====="
    )

    selected_summary = {
        key: value
        for key, value in selected.items()
        if key != "model"
    }

    assertion_results = run_ml_assertions(
        data,
        candidate_result_summaries,
        selected_summary,
        policy_fidelity,
    )

    print(
        "Assertions:",
        "PASS"
        if assertion_results["all_pass"]
        else "FAIL",
    )

    # -------------------------------------------------------------------------
    # Artifact metadata
    # -------------------------------------------------------------------------

    test_predictions_path = (
        ARTIFACT_DIR
        / "final_test_predictions.csv"
    )

    test_prediction_frame = pd.DataFrame(
        {
            "record_id": data[
                "features"
            ].loc[
                test_mask,
                "record_id",
            ].to_numpy(),
            "ground_truth_label": y_test.to_numpy(),
            "predicted_label": test_predictions,
            "prob_normal": test_probabilities[
                :, 0
            ],
            "prob_investigate": test_probabilities[
                :, 1
            ],
            "prob_high_risk": test_probabilities[
                :, 2
            ],
        }
    )

    test_prediction_frame.to_csv(
        test_predictions_path,
        index=False,
    )

    # -------------------------------------------------------------------------
    # Candidate results
    # -------------------------------------------------------------------------

    candidate_results_path = (
        ARTIFACT_DIR
        / "candidate_results.json"
    )

    json_dump(
        candidate_result_summaries,
        candidate_results_path,
    )

    # -------------------------------------------------------------------------
    # Metrics
    # -------------------------------------------------------------------------

    metrics_payload = {
        "experiment_id": experiment_id,
        "selected_candidate": selected_summary,
        "validation_uncalibrated": selected[
            "validation"
        ],
        "validation_calibration_diagnostic": (
            validation_calibration_diagnostic
        ),
        "final_test": test_metrics,
        "classification_gates": test_gates,
        "isolation_forest": isolation_results,
    }

    metrics_path = (
        ARTIFACT_DIR
        / "metrics.json"
    )

    json_dump(
        metrics_payload,
        metrics_path,
    )

    # -------------------------------------------------------------------------
    # Policy fidelity evidence
    # -------------------------------------------------------------------------

    policy_path = (
        ARTIFACT_DIR
        / "deterministic_policy_fidelity.json"
    )

    json_dump(
        policy_fidelity,
        policy_path,
    )

    # -------------------------------------------------------------------------
    # Explainability evidence
    # -------------------------------------------------------------------------

    global_path = (
        ARTIFACT_DIR
        / "global_permutation_importance.json"
    )

    local_path = (
        ARTIFACT_DIR
        / "local_model_sensitivity.json"
    )

    json_dump(
        global_importance,
        global_path,
    )

    json_dump(
        local_explanations,
        local_path,
    )

    # -------------------------------------------------------------------------
    # Robustness evidence
    # -------------------------------------------------------------------------

    robustness_path = (
        ARTIFACT_DIR
        / "robustness_results.json"
    )

    json_dump(
        robustness_results,
        robustness_path,
    )

    # -------------------------------------------------------------------------
    # Subgroup evidence
    # -------------------------------------------------------------------------

    subgroup_path = (
        ARTIFACT_DIR
        / "technical_subgroup_analysis.json"
    )

    json_dump(
        subgroup_results,
        subgroup_path,
    )

    # -------------------------------------------------------------------------
    # Assertion evidence
    # -------------------------------------------------------------------------

    assertion_path = (
        ARTIFACT_DIR
        / "ml_assurance_assertions.json"
    )

    json_dump(
        assertion_results,
        assertion_path,
    )

    # -------------------------------------------------------------------------
    # Experiment manifest
    # -------------------------------------------------------------------------

    tracked_inputs = [
        FEATURE_FILE,
        FEATURE_METADATA_FILE,
        OBSERVABLE_FILE,
        REFERENCE_FILE,
        LABEL_FILE,
        SPLIT_FILE,
        GENERATION_FILE,
    ]

    tracked_artifacts = [
        selected_model_path,
        calibrated_model_path,
        MODEL_DIR
        / "isolation_forest.joblib",
        candidate_results_path,
        metrics_path,
        policy_path,
        global_path,
        local_path,
        robustness_path,
        subgroup_path,
        assertion_path,
        test_predictions_path,
    ]

    input_hashes = {
        str(
            path.relative_to(
                PROJECT_ROOT
            )
        ): sha256_file(path)
        for path in tracked_inputs
    }

    artifact_hashes = {
        str(
            path.relative_to(
                PROJECT_ROOT
            )
        ): sha256_file(path)
        for path in tracked_artifacts
        if path.exists()
    }

    manifest = {
        "experiment_id": experiment_id,
        "created_utc": utc_now(),
        "source_of_truth": (
            "Framework-benchmarked pre-ML repository"
        ),
        "dataset": {
            "records": EXPECTED_RECORD_COUNT,
            "features": EXPECTED_FEATURE_COUNT,
            "train_records": EXPECTED_SPLIT_COUNTS[
                "train"
            ],
            "validation_records": EXPECTED_SPLIT_COUNTS[
                "validation"
            ],
            "test_records": EXPECTED_SPLIT_COUNTS[
                "test"
            ],
            "grouped_split": True,
            "lineage_leakage": False,
        },
        "run_id": data[
            "generation"
        ].get(
            "run_id"
        ),
        "generation_seed": data[
            "generation"
        ].get(
            "seed"
        ),
        "training_seed": SEED,
        "robustness_seed": ROBUSTNESS_SEED,
        "candidate_count": len(
            candidates
        ),
        "candidate_families": [
            "DummyClassifier",
            "LogisticRegression",
            "RandomForestClassifier",
            "HistGradientBoostingClassifier",
        ],
        "excluded_model_family": [
            "ExtraTrees"
        ],
        "cv": {
            "method": "GroupKFold",
            "folds": N_CV_FOLDS,
            "group_column": "group_id",
            "shuffle": False,
            "random_state": (
                "Not applicable when shuffle=False"
            ),
        },
        "selection": {
            "primary": "validation_macro_f1",
            "tie_breakers": [
                "validation_high_risk_recall",
                "validation_min_per_class_f1",
                "validation_lower_log_loss",
                "lower_complexity",
            ],
        },
        "calibration": {
            "method": "sigmoid",
            "fit_split": "validation",
            "validation_labels_used_for_calibration": True,
            "diagnostic_only_on_validation": True,
        },
        "test_policy": {
            "opened_after_model_freeze": True,
            "no_test_retuning": True,
            "no_threshold_retuning_on_test": True,
        },
        "isolation_forest": {
            "training_rows_restricted_to": (
                "ground_truth_label == normal"
            ),
            "scenario_metadata_consulted": False,
            "threshold_selection_split": "validation",
        },
        "forbidden_model_inputs": [
            "ground_truth_label",
            "ground_truth_score",
            "ground_truth_factors",
            "scenario_type",
            "expected_decision",
            "risk_target",
            "target",
            "label",
            "scenario manifests",
            "provenance identifiers",
            "record_id",
            "group_id",
            "run_id",
        ],
        "deterministic_policy_fidelity": (
            policy_fidelity
        ),
        "selected_model": {
            "candidate_index": selected[
                "candidate_index"
            ],
            "family": selected[
                "family"
            ],
            "params": selected[
                "params"
            ],
            "validation_metrics": selected[
                "validation"
            ],
        },
        "classification_test_metrics": test_metrics,
        "classification_test_gates": test_gates,
        "isolation_forest_results": isolation_results,
        "artifact_hashes": artifact_hashes,
        "input_hashes": input_hashes,
        "status": (
            "PASS"
            if (
                test_gates["all_pass"]
                and isolation_results["all_pass"]
                and assertion_results["all_pass"]
            )
            else "REJECTED"
        ),
        "status_interpretation": (
            "This experiment is rejected if any mandatory gate fails. "
            "A rejected experiment is not final acceptance evidence and "
            "must not be represented as a production-ready model."
        ),
        "limitations": [
            (
                "Labels are derived from deterministic policy/risk rules; "
                "the classifier is a surrogate of those rules, not "
                "independent security intelligence."
            ),
            (
                "The dataset is synthetic and does not establish "
                "production generalization."
            ),
            (
                "Framework mappings are benchmark/coverage evidence, "
                "not certification or compliance claims."
            ),
            (
                "ML remains advisory and deterministic hard-failure "
                "precedence is retained."
            ),
        ],
    }

    manifest_path = (
        ARTIFACT_DIR
        / "experiment_manifest.json"
    )

    json_dump(
        manifest,
        manifest_path,
    )

    # -------------------------------------------------------------------------
    # Final summary
    # -------------------------------------------------------------------------

    print(
        "\n============================================================"
    )
    print(
        "EXPERIMENT COMPLETE"
    )
    print(
        "============================================================"
    )

    print(
        "Experiment ID:",
        experiment_id,
    )

    print(
        "Deterministic policy fidelity:",
        f"{policy_fidelity['overall_exact_fidelity']:.6f}",
    )

    print(
        "Selected model:",
        selected[
            "family"
        ],
        selected[
            "params"
        ],
    )

    print(
        "Final test Macro-F1:",
        f"{test_metrics['macro_f1']:.6f}",
    )

    print(
        "Final test high-risk recall:",
        f"{test_metrics['high_risk_recall']:.6f}",
    )

    print(
        "Final test log-loss:",
        f"{test_metrics['log_loss']:.6f}",
    )

    print(
        "Classification gates:",
        "PASS"
        if test_gates["all_pass"]
        else "FAIL",
    )

    print(
        "Isolation Forest gates:",
        "PASS"
        if isolation_results["all_pass"]
        else "FAIL",
    )

    print(
        "ML assertions:",
        "PASS"
        if assertion_results["all_pass"]
        else "FAIL",
    )

    final_status = manifest[
        "status"
    ]

    print(
        "\nFINAL EXPERIMENT STATUS:",
        final_status,
    )

    print(
        "\nArtifacts:",
        ARTIFACT_DIR,
    )

    print(
        "Models:",
        MODEL_DIR,
    )

    print(
        "Manifest:",
        manifest_path,
    )


if __name__ == "__main__":
    main()