"""Leakage-safe feature engineering from observations plus approved references."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
DATASET_DIR = ROOT / "data" / "synthetic" / "supply_chain_poc" / "dataset"
OBSERVABLE_FILE = DATASET_DIR / "observable_features.csv"
REFERENCE_FILE = DATASET_DIR / "reference_data.csv"
CATALOG_FILE = DATASET_DIR / "reference_catalog.csv"
OUTPUT_FILE = DATASET_DIR / "engineered_features.csv"
METADATA_FILE = DATASET_DIR / "feature_metadata.json"

FORBIDDEN_COLUMNS = {
    "scenario_id", "scenario_type", "expected_decision", "ground_truth_label",
    "ground_truth_score", "ground_truth_factors", "risk_level", "risk_score",
    "decision", "label", "prediction", "injected_conditions", "attack_parameters",
}


def bool_to_int(series: pd.Series) -> pd.Series:
    mapping = {True: 1, False: 0, "True": 1, "False": 0, "true": 1, "false": 0, 1: 1, 0: 0}
    result = series.map(mapping)
    if result.isna().any():
        raise ValueError(f"Invalid boolean values: {series[result.isna()].unique()}")
    return result.astype(int)


def parse_version(value: str) -> tuple[int, int, int]:
    parts = tuple(int(part) for part in str(value).split("."))
    if len(parts) != 3:
        raise ValueError(f"Invalid version: {value}")
    return parts


def build_features(observed: pd.DataFrame, references: pd.DataFrame, catalog: pd.DataFrame) -> pd.DataFrame:
    forbidden = (set(observed.columns) | set(references.columns)) & FORBIDDEN_COLUMNS
    if forbidden:
        raise ValueError(f"Ground-truth leakage columns detected: {sorted(forbidden)}")

    data = observed.merge(references, on=["record_id", "package_id", "lineage_id"], validate="one_to_one")
    vendor_rows = catalog[catalog["reference_type"] == "vendor"][["reference_id", "trusted"]].copy()
    vendor_rows["vendor_untrusted"] = 1 - bool_to_int(vendor_rows["trusted"])
    data = data.merge(vendor_rows[["reference_id", "vendor_untrusted"]], left_on="observed_vendor_id", right_on="reference_id", how="left", validate="many_to_one")
    if data["vendor_untrusted"].isna().any():
        raise ValueError("Observed vendor missing from reference catalog")

    features = pd.DataFrame({"record_id": data["record_id"]})
    features["hash_mismatch"] = (data["observed_hash"].str.lower() != data["trusted_hash"].str.lower()).astype(int)
    features["signature_invalid"] = 1 - bool_to_int(data["signature_valid"])
    features["trusted_root_invalid"] = 1 - bool_to_int(data["trusted_root_valid"])
    features["vendor_mismatch"] = (data["observed_vendor_id"] != data["approved_vendor_id"]).astype(int)
    features["vendor_untrusted"] = data["vendor_untrusted"].astype(int)
    features["sbom_missing"] = 1 - bool_to_int(data["sbom_present"])
    features["sbom_incomplete"] = 1 - bool_to_int(data["sbom_complete"])
    observed_versions = data["observed_version"].map(parse_version)
    approved_versions = data["approved_version"].map(parse_version)
    features["version_changed"] = (data["observed_version"] != data["approved_version"]).astype(int)
    features["version_major_delta"] = [approved[0] - observed[0] for observed, approved in zip(observed_versions, approved_versions)]
    authorized = bool_to_int(data["rollback_authorized"])
    features["unauthorized_rollback"] = pd.Series([observed < approved for observed, approved in zip(observed_versions, approved_versions)], index=data.index).astype(int) * (1 - authorized)
    features["vulnerability_present"] = bool_to_int(data["vulnerability_present"])
    features["vulnerability_applicable"] = bool_to_int(data["vulnerability_applicable"])
    features["unexpected_component"] = bool_to_int(data["unexpected_component"])
    features["evidence_age_days"] = pd.to_numeric(data["evidence_age_days"], errors="raise")
    features["stale_evidence"] = (features["evidence_age_days"] > data["freshness_threshold_days"]).astype(int)
    features["package_size_mb"] = (pd.to_numeric(data["package_size_bytes"], errors="raise") / 1_000_000).round(6)
    features["component_count"] = pd.to_numeric(data["component_count"], errors="raise")
    features["component_count_delta"] = features["component_count"] - pd.to_numeric(data["approved_component_count"], errors="raise")
    features["known_vulnerability_count"] = pd.to_numeric(data["known_vulnerability_count"], errors="raise")
    features["max_cvss_score"] = pd.to_numeric(data["max_cvss_score"], errors="raise")
    features["hard_failure_count"] = features[["hash_mismatch", "signature_invalid", "trusted_root_invalid", "vendor_untrusted", "unauthorized_rollback"]].sum(axis=1)
    features["evidence_issue_count"] = features[["sbom_missing", "sbom_incomplete", "stale_evidence"]].sum(axis=1)
    return features


def validate_features(observed: pd.DataFrame, features: pd.DataFrame) -> None:
    assert len(observed) == len(features) == 5000
    assert observed["record_id"].tolist() == features["record_id"].tolist()
    assert not (set(features.columns) & FORBIDDEN_COLUMNS)
    assert not features.isna().any().any()
    assert features["record_id"].is_unique
    for column in features.columns[1:]:
        assert pd.api.types.is_numeric_dtype(features[column]), column


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    observed = pd.read_csv(OBSERVABLE_FILE)
    references = pd.read_csv(REFERENCE_FILE)
    catalog = pd.read_csv(CATALOG_FILE)
    features = build_features(observed, references, catalog)
    validate_features(observed, features)
    features.to_csv(OUTPUT_FILE, index=False, lineterminator="\n")
    feature_names = [column for column in features.columns if column != "record_id"]
    metadata = {
        "generator": "feature_engineering.py",
        "version": "2.0.0",
        "input_files": [OBSERVABLE_FILE.name, REFERENCE_FILE.name, CATALOG_FILE.name],
        "output_file": OUTPUT_FILE.name,
        "record_count": len(features),
        "feature_count": len(feature_names),
        "features": feature_names,
        "ground_truth_used": False,
        "ml_training_started": False,
        "rule_ml_fusion_implemented": False,
        "output_sha256": sha256(OUTPUT_FILE),
    }
    METADATA_FILE.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    hash_file = DATASET_DIR / "dataset_file_hashes.json"
    hashes = json.loads(hash_file.read_text(encoding="utf-8"))
    hashes[OUTPUT_FILE.name] = sha256(OUTPUT_FILE)
    hashes[METADATA_FILE.name] = sha256(METADATA_FILE)
    hash_file.write_text(json.dumps(hashes, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"Created {len(features)} leakage-safe feature rows with {len(feature_names)} features")


if __name__ == "__main__":
    main()
