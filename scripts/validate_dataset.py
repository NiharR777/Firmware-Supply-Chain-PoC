"""Independent acceptance validation for the 5,000-record dataset."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pandas as pd

import generate_dataset as generator


ROOT = Path(__file__).resolve().parents[1]
DATASET_DIR = ROOT / "data" / "synthetic" / "supply_chain_poc" / "dataset"
FORBIDDEN_OBSERVABLE = {
    "scenario_type", "expected_decision", "ground_truth_label", "ground_truth_score",
    "ground_truth_factors", "risk_level", "risk_score", "label", "prediction",
    "approved_vendor_id", "trusted_hash", "approved_version", "attack_parameters",
}


def read(name: str) -> pd.DataFrame:
    path = DATASET_DIR / name
    assert path.exists() and path.stat().st_size > 0, f"Missing/empty file: {name}"
    return pd.read_csv(path, keep_default_na=False)


def assert_frame_content(actual: pd.DataFrame, expected: pd.DataFrame, label: str) -> None:
    actual = actual[expected.columns].reset_index(drop=True)
    expected = expected.reset_index(drop=True)
    pd.testing.assert_frame_equal(actual, expected, check_dtype=False, check_like=False, obj=label)


def main() -> None:
    observed = read("observable_features.csv")
    references = read("reference_data.csv")
    labels = read("ground_truth_labels.csv")
    manifests = read("scenario_manifests.csv")
    splits = read("split_assignments.csv")
    catalog = read("reference_catalog.csv")

    assert len(observed) == len(references) == len(labels) == len(manifests) == len(splits) == 5000
    for frame in [observed, references, labels, manifests, splits]:
        assert frame["record_id"].is_unique
        assert set(frame["record_id"]) == set(observed["record_id"])
    assert not (set(observed.columns) & FORBIDDEN_OBSERVABLE)
    assert {"approved_vendor_id", "trusted_hash", "approved_version"}.issubset(references.columns)
    assert {"scenario_type", "attack_parameters", "injected_conditions"}.issubset(manifests.columns)
    assert manifests["attack_parameters"].map(lambda value: bool(json.loads(value))).all()

    # Regenerate every record directly from the stored record seed.
    regenerated = [
        generator.regenerate_record(int(record_id.split("-")[-1]), int(seed))
        for record_id, seed in zip(observed["record_id"], observed["record_seed"])
    ]
    assert_frame_content(observed, pd.DataFrame([row["observable"] for row in regenerated]), "observable reproducibility")
    assert_frame_content(references, pd.DataFrame([row["reference"] for row in regenerated]), "reference reproducibility")
    assert_frame_content(labels, pd.DataFrame([row["ground_truth"] for row in regenerated]), "label reproducibility")
    assert_frame_content(manifests, pd.DataFrame([row["manifest"] for row in regenerated]), "manifest reproducibility")

    # Recalculate every label from observations and references.
    joined = observed.merge(references, on=["record_id", "package_id", "lineage_id"], validate="one_to_one")
    recalculated = []
    for row in joined.to_dict("records"):
        observable_keys = set(observed.columns)
        reference_keys = set(references.columns)
        observable = {key: row[key] for key in observable_keys}
        reference = {key: row[key] for key in reference_keys}
        score, label, factors = generator.score_evidence(observable, reference)
        recalculated.append((row["record_id"], score, label, ";".join(factors)))
    recalculated_df = pd.DataFrame(recalculated, columns=["record_id", "ground_truth_score", "ground_truth_label", "ground_truth_factors"])
    assert_frame_content(labels, recalculated_df, "rule/label consistency")

    vendor_trust = catalog[catalog["reference_type"] == "vendor"].set_index("reference_id")["trusted"].astype(str).str.lower().map({"true": True, "false": False})
    normal_ids = set(labels.loc[labels["ground_truth_label"] == "normal", "record_id"])
    normal_observed = observed[observed["record_id"].isin(normal_ids)]
    assert normal_observed["observed_vendor_id"].map(vendor_trust).all()

    groups = splits.groupby("group_id").agg(size=("record_id", "size"), split_count=("split", "nunique"))
    assert len(groups) == 500
    assert set(groups["size"]) == {10}
    assert set(groups["split_count"]) == {1}
    assert splits["split"].value_counts().to_dict() == {"train": 3500, "validation": 750, "test": 750}

    feature_file = DATASET_DIR / "engineered_features.csv"
    if feature_file.exists():
        features = pd.read_csv(feature_file)
        assert len(features) == 5000 and features["record_id"].is_unique
        assert not (set(features.columns) & FORBIDDEN_OBSERVABLE)
        assert not features.isna().any().any()

    hash_path = DATASET_DIR / "dataset_file_hashes.json"
    stored_hashes = json.loads(hash_path.read_text(encoding="utf-8"))
    for name, expected_hash in stored_hashes.items():
        path = DATASET_DIR / name
        assert path.exists(), name
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected_hash, name

    print("[PASS] 5,000 aligned records")
    print("[PASS] Observed/reference/manifest/label separation")
    print("[PASS] All records regenerate from their recorded seeds")
    print("[PASS] All labels match deterministic risk policy")
    print("[PASS] Normal records use trusted vendors")
    print("[PASS] 500 lineage groups x 10 records; no cross-split groups")
    print("[PASS] Dataset hashes verified")
    print("Decision distribution:", labels["ground_truth_label"].value_counts().to_dict())
    print("Dataset validation passed; ML training and rule/ML fusion remain unimplemented.")


if __name__ == "__main__":
    main()
