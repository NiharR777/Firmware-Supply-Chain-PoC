"""
Feature Engineering
Firmware Supply-Chain PoC

Converts observable firmware supply-chain evidence into
ML-ready features.

IMPORTANT:
Ground-truth fields and decision labels are NOT used here.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]

DATASET_DIR = (
    ROOT
    / "data"
    / "synthetic"
    / "supply_chain_poc"
    / "dataset"
)

INPUT_FILE = DATASET_DIR / "observable_features.csv"
OUTPUT_FILE = DATASET_DIR / "engineered_features.csv"
METADATA_FILE = DATASET_DIR / "feature_metadata.json"


# These are identifiers / metadata and must not become ML features.
NON_FEATURE_COLUMNS = {
    "record_id",
    "package_id",
    "product_id",
    "asset_id",
    "expected_vendor_id",
    "observed_vendor_id",
    "device_type",
    "process_unit",
    "expected_hash",
    "observed_hash",
    "expected_version",
    "observed_version",
    "record_seed",
    "run_id",
}


# Ground-truth / answer-leakage fields are explicitly forbidden.
FORBIDDEN_COLUMNS = {
    "scenario_id",
    "scenario_type",
    "expected_decision",
    "risk_level",
    "risk_score",
    "decision",
    "ground_truth",
    "label",
    "prediction",
}


def bool_to_int(series: pd.Series) -> pd.Series:
    """Convert boolean-like values to 0/1."""

    mapping = {
        True: 1,
        False: 0,
        "True": 1,
        "False": 0,
        "true": 1,
        "false": 0,
        "TRUE": 1,
        "FALSE": 0,
        1: 1,
        0: 0,
    }

    converted = series.map(mapping)

    if converted.isna().any():
        bad_values = series[converted.isna()].unique()
        raise ValueError(
            f"Invalid boolean values found: {bad_values}"
        )

    return converted.astype(int)


def version_difference(
    expected: pd.Series,
    observed: pd.Series,
) -> pd.Series:
    """
    Calculate a simple version difference indicator.

    Returns:
        1 when versions differ
        0 when versions are equal
    """

    return (
        expected.astype(str)
        != observed.astype(str)
    ).astype(int)


def calculate_hash_mismatch(
    expected: pd.Series,
    observed: pd.Series,
) -> pd.Series:
    """Derive hash mismatch directly from observed hash evidence."""

    return (
        expected.astype(str).str.lower()
        != observed.astype(str).str.lower()
    ).astype(int)


def calculate_vendor_mismatch(
    expected: pd.Series,
    observed: pd.Series,
) -> pd.Series:
    """Derive vendor substitution from expected vs observed vendor."""

    return (
        expected.astype(str)
        != observed.astype(str)
    ).astype(int)


def build_features(df: pd.DataFrame) -> pd.DataFrame:

    # Verify forbidden fields are not present in the observable dataset.
    forbidden_present = (
        set(df.columns)
        & FORBIDDEN_COLUMNS
    )

    if forbidden_present:
        raise ValueError(
            "Ground-truth / answer-leakage columns detected: "
            f"{sorted(forbidden_present)}"
        )

    required_columns = {
        "record_id",
        "package_id",
        "expected_vendor_id",
        "observed_vendor_id",
        "expected_hash",
        "observed_hash",
        "hash_match",
        "signature_valid",
        "trusted_root_valid",
        "sbom_present",
        "sbom_complete",
        "expected_version",
        "observed_version",
        "rollback_authorized",
        "vulnerability_present",
        "vulnerability_applicable",
        "unexpected_component",
        "evidence_age_days",
        "record_seed",
        "run_id",
    }

    missing = required_columns - set(df.columns)

    if missing:
        raise ValueError(
            f"Missing required observable columns: "
            f"{sorted(missing)}"
        )

    features = pd.DataFrame()

    # Keep record_id only for traceability.
    features["record_id"] = df["record_id"]

    # Integrity evidence.
    features["hash_mismatch"] = calculate_hash_mismatch(
        df["expected_hash"],
        df["observed_hash"],
    )

    features["hash_match"] = bool_to_int(
        df["hash_match"]
    )

    # Authenticity evidence.
    features["signature_invalid"] = (
        1
        - bool_to_int(df["signature_valid"])
    )

    features["trusted_root_invalid"] = (
        1
        - bool_to_int(df["trusted_root_valid"])
    )

    # Vendor evidence.
    features["vendor_mismatch"] = calculate_vendor_mismatch(
        df["expected_vendor_id"],
        df["observed_vendor_id"],
    )

    # SBOM evidence.
    features["sbom_missing"] = (
        1
        - bool_to_int(df["sbom_present"])
    )

    features["sbom_incomplete"] = (
        1
        - bool_to_int(df["sbom_complete"])
    )

    # Firmware version evidence.
    features["version_changed"] = version_difference(
        df["expected_version"],
        df["observed_version"],
    )

    # Rollback evidence.
    rollback_authorized = bool_to_int(
        df["rollback_authorized"]
    )

    features["unauthorized_rollback"] = (
        (
            df["observed_version"].astype(str)
            != df["expected_version"].astype(str)
        )
        & (rollback_authorized == 0)
    ).astype(int)

    # Vulnerability evidence.
    features["vulnerability_present"] = bool_to_int(
        df["vulnerability_present"]
    )

    features["vulnerability_applicable"] = bool_to_int(
        df["vulnerability_applicable"]
    )

    # Component integrity evidence.
    features["unexpected_component"] = bool_to_int(
        df["unexpected_component"]
    )

    # Evidence freshness.
    features["evidence_age_days"] = pd.to_numeric(
        df["evidence_age_days"],
        errors="raise",
    )

    # Useful derived freshness indicators.
    features["stale_evidence"] = (
        features["evidence_age_days"] > 30
    ).astype(int)

    features["very_stale_evidence"] = (
        features["evidence_age_days"] > 90
    ).astype(int)

    # Combined observable security indicators.
    features["integrity_or_authentication_failure"] = (
        (
            features["hash_mismatch"] == 1
        )
        | (
            features["signature_invalid"] == 1
        )
        | (
            features["trusted_root_invalid"] == 1
        )
    ).astype(int)

    features["supply_chain_identity_mismatch"] = (
        (
            features["vendor_mismatch"] == 1
        )
        | (
            features["hash_mismatch"] == 1
        )
    ).astype(int)

    features["evidence_quality_issue"] = (
        (
            features["sbom_missing"] == 1
        )
        | (
            features["sbom_incomplete"] == 1
        )
        | (
            features["stale_evidence"] == 1
        )
    ).astype(int)

    features["component_risk_indicator"] = (
        (
            features["vulnerability_present"] == 1
        )
        & (
            features["vulnerability_applicable"] == 1
        )
        | (
            features["unexpected_component"] == 1
        )
    ).astype(int)

    return features


def validate_features(
    original: pd.DataFrame,
    features: pd.DataFrame,
) -> None:

    # Same number of records.
    assert len(original) == len(features), (
        "Feature record count does not match "
        "observable dataset"
    )

    # Record IDs must remain traceable.
    assert (
        original["record_id"].tolist()
        == features["record_id"].tolist()
    ), "record_id ordering changed"

    # No forbidden columns.
    forbidden = (
        set(features.columns)
        & FORBIDDEN_COLUMNS
    )

    assert not forbidden, (
        f"Forbidden columns found: {forbidden}"
    )

    # Every feature except record_id must be numeric.
    numeric_columns = [
        column
        for column in features.columns
        if column != "record_id"
    ]

    for column in numeric_columns:
        assert pd.api.types.is_numeric_dtype(
            features[column]
        ), (
            f"Feature is not numeric: {column}"
        )

    # No missing values.
    assert not features.isna().any().any(), (
        "Missing values detected in engineered features"
    )

    # Binary features must contain only 0/1.
    binary_columns = [
        column
        for column in numeric_columns
        if column != "evidence_age_days"
    ]

    for column in binary_columns:
        values = set(
            features[column].unique()
        )

        assert values <= {0, 1}, (
            f"Invalid binary values in {column}: "
            f"{values}"
        )

    print(
        "[PASS] Feature count matches observable dataset"
    )

    print(
        "[PASS] Record IDs remain traceable"
    )

    print(
        "[PASS] No ground-truth leakage detected"
    )

    print(
        "[PASS] All engineered features are numeric"
    )

    print(
        "[PASS] No missing feature values"
    )

    print(
        "[PASS] Binary features contain only 0/1"
    )


def calculate_file_hash(path: Path) -> str:

    sha256 = hashlib.sha256()

    with path.open("rb") as file:

        for chunk in iter(
            lambda: file.read(1024 * 1024),
            b"",
        ):
            sha256.update(chunk)

    return sha256.hexdigest()


def main() -> None:

    print()
    print("==============================================")
    print(" FEATURE ENGINEERING")
    print("==============================================")
    print()

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Observable dataset not found: {INPUT_FILE}"
        )

    df = pd.read_csv(INPUT_FILE)

    print(
        f"Input records : {len(df)}"
    )

    print(
        f"Input columns : {len(df.columns)}"
    )

    features = build_features(df)

    validate_features(
        df,
        features,
    )

    features.to_csv(
        OUTPUT_FILE,
        index=False,
    )

    feature_columns = [
        column
        for column in features.columns
        if column != "record_id"
    ]

    metadata = {
        "generator": "feature_engineering.py",
        "version": "1.0.0",
        "input_file": INPUT_FILE.name,
        "output_file": OUTPUT_FILE.name,
        "record_count": len(features),
        "feature_count": len(feature_columns),
        "features": feature_columns,
        "excluded_columns": sorted(
            NON_FEATURE_COLUMNS
        ),
        "forbidden_ground_truth_columns": sorted(
            FORBIDDEN_COLUMNS
        ),
        "ground_truth_used": False,
        "ml_training_started": False,
        "rule_ml_fusion_implemented": False,
        "output_sha256": None,
    }

    with METADATA_FILE.open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            metadata,
            file,
            indent=2,
        )

    output_hash = calculate_file_hash(
        OUTPUT_FILE
    )

    metadata["output_sha256"] = output_hash

    with METADATA_FILE.open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            metadata,
            file,
            indent=2,
        )

    print()
    print(
        f"Output records : {len(features)}"
    )

    print(
        f"Engineered features : {len(feature_columns)}"
    )

    print()
    print("Features created:")

    for feature in feature_columns:
        print(f"  [OK] {feature}")

    print()
    print(
        f"[OK] Created: {OUTPUT_FILE}"
    )

    print(
        f"[OK] Created: {METADATA_FILE}"
    )

    print()
    print(
        "Ground truth was NOT used."
    )

    print(
        "ML training has NOT been started."
    )

    print(
        "Rule/ML fusion has NOT been implemented."
    )

    print()
    print("==============================================")
    print(" FEATURE ENGINEERING COMPLETE")
    print("==============================================")
    print()


if __name__ == "__main__":
    main()