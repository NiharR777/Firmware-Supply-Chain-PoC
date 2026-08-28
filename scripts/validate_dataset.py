"""
Dataset Validation
Firmware Supply-Chain PoC

Validates the synthetic ML dataset before feature engineering/training.
"""

from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

DATASET_DIR = (
    ROOT
    / "data"
    / "synthetic"
    / "supply_chain_poc"
    / "dataset"
)

EXPECTED_RECORDS = 5000

EXPECTED_DECISIONS = {
    "normal",
    "investigate",
    "high_risk",
}

REQUIRED_OBSERVABLE_COLUMNS = {
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

FORBIDDEN_OBSERVABLE_COLUMNS = {
    "scenario_type",
    "expected_decision",
    "risk_level",
    "risk_score",
    "ground_truth",
    "label",
    "target",
    "prediction",
}

REQUIRED_LABEL_COLUMNS = {
    "record_id",
    "scenario_type",
    "expected_decision",
}


def read_csv(filename: str) -> list[dict]:
    path = DATASET_DIR / filename

    assert path.exists(), f"Missing file: {path}"

    with path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        return list(csv.DictReader(file))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def check_required_files() -> None:

    required_files = [
        "reference_data.csv",
        "observable_features.csv",
        "ground_truth_labels.csv",
        "scenario_manifests.csv",
        "generation_parameters.json",
        "split_assignments.csv",
    ]

    for filename in required_files:
        path = DATASET_DIR / filename

        assert path.exists(), f"Missing required file: {filename}"
        assert path.stat().st_size > 0, f"Empty file: {filename}"

    print("[PASS] Required dataset files exist")


def check_record_count(observable, labels, manifests, splits) -> None:

    assert len(observable) == EXPECTED_RECORDS, (
        f"Observable record count is {len(observable)}, "
        f"expected {EXPECTED_RECORDS}"
    )

    assert len(labels) == EXPECTED_RECORDS
    assert len(manifests) == EXPECTED_RECORDS
    assert len(splits) == EXPECTED_RECORDS

    print(
        f"[PASS] Record count = {EXPECTED_RECORDS}"
    )


def check_columns(observable, labels) -> None:

    observable_columns = set(observable[0].keys())
    label_columns = set(labels[0].keys())

    missing_observable = (
        REQUIRED_OBSERVABLE_COLUMNS
        - observable_columns
    )

    missing_labels = (
        REQUIRED_LABEL_COLUMNS
        - label_columns
    )

    forbidden = (
        FORBIDDEN_OBSERVABLE_COLUMNS
        & observable_columns
    )

    assert not missing_observable, (
        f"Missing observable columns: {missing_observable}"
    )

    assert not missing_labels, (
        f"Missing label columns: {missing_labels}"
    )

    assert not forbidden, (
        f"GROUND-TRUTH LEAKAGE detected in observable_features.csv: "
        f"{forbidden}"
    )

    print("[PASS] Required columns present")
    print("[PASS] No forbidden ground-truth columns in observable features")


def check_record_ids(observable, labels, manifests, splits) -> None:

    observable_ids = [
        row["record_id"]
        for row in observable
    ]

    label_ids = [
        row["record_id"]
        for row in labels
    ]

    manifest_ids = [
        row["record_id"]
        for row in manifests
    ]

    split_ids = [
        row["record_id"]
        for row in splits
    ]

    assert len(observable_ids) == len(set(observable_ids)), (
        "Duplicate record IDs in observable features"
    )

    assert set(observable_ids) == set(label_ids)
    assert set(observable_ids) == set(manifest_ids)
    assert set(observable_ids) == set(split_ids)

    print("[PASS] Record IDs are unique and consistent")


def check_hash_integrity(observable) -> None:

    for row in observable:

        expected_hash = row["expected_hash"]
        observed_hash = row["observed_hash"]

        assert len(expected_hash) == 64
        assert len(observed_hash) == 64

        calculated_match = (
            expected_hash == observed_hash
        )

        stored_match = (
            row["hash_match"].lower()
            == "true"
        )

        assert calculated_match == stored_match, (
            f"Hash-match inconsistency for {row['record_id']}"
        )

    print("[PASS] Hash evidence is internally consistent")


def check_boolean_fields(observable) -> None:

    boolean_fields = [
        "hash_match",
        "signature_valid",
        "trusted_root_valid",
        "sbom_present",
        "sbom_complete",
        "rollback_authorized",
        "vulnerability_present",
        "vulnerability_applicable",
        "unexpected_component",
    ]

    valid_values = {"true", "false"}

    for row in observable:

        for field in boolean_fields:

            value = row[field].strip().lower()

            assert value in valid_values, (
                f"Invalid boolean '{value}' "
                f"for {field} in {row['record_id']}"
            )

    print("[PASS] Boolean evidence fields are valid")


def check_decision_labels(labels) -> None:

    decisions = {
        row["expected_decision"]
        for row in labels
    }

    assert decisions <= EXPECTED_DECISIONS

    missing_classes = (
        EXPECTED_DECISIONS - decisions
    )

    assert not missing_classes, (
        f"Missing decision classes: {missing_classes}"
    )

    print(
        "[PASS] All decision classes are represented: "
        + ", ".join(sorted(decisions))
    )


def check_label_distribution(labels) -> None:

    counts = {
        decision: 0
        for decision in EXPECTED_DECISIONS
    }

    for row in labels:
        counts[row["expected_decision"]] += 1

    print("[PASS] Decision distribution:")

    for decision in [
        "normal",
        "investigate",
        "high_risk",
    ]:
        print(
            f"       {decision:12s}: "
            f"{counts[decision]}"
        )


def check_split_integrity(splits) -> None:

    expected_splits = {
        "train",
        "validation",
        "test",
    }

    actual_splits = {
        row["split"]
        for row in splits
    }

    assert actual_splits == expected_splits, (
        f"Invalid split values: {actual_splits}"
    )

    counts = {
        split: 0
        for split in expected_splits
    }

    for row in splits:
        counts[row["split"]] += 1

    assert sum(counts.values()) == EXPECTED_RECORDS

    print("[PASS] Split assignments are valid")

    for split in [
        "train",
        "validation",
        "test",
    ]:
        print(
            f"       {split:12s}: "
            f"{counts[split]}"
        )


def check_group_leakage(splits) -> None:

    groups_by_split = {
        "train": set(),
        "validation": set(),
        "test": set(),
    }

    for row in splits:

        groups_by_split[
            row["split"]
        ].add(row["group_id"])

    train_validation_overlap = (
        groups_by_split["train"]
        & groups_by_split["validation"]
    )

    train_test_overlap = (
        groups_by_split["train"]
        & groups_by_split["test"]
    )

    validation_test_overlap = (
        groups_by_split["validation"]
        & groups_by_split["test"]
    )

    assert not train_validation_overlap
    assert not train_test_overlap
    assert not validation_test_overlap

    print(
        "[PASS] No group leakage between train/validation/test"
    )


def check_reproducibility(observable) -> None:

    seeds = {
        row["record_seed"]
        for row in observable
    }

    run_ids = {
        row["run_id"]
        for row in observable
    }

    assert len(seeds) == EXPECTED_RECORDS
    assert len(run_ids) == 1

    print("[PASS] Every record has a unique reproducible seed")
    print(
        f"[PASS] Single dataset run ID: "
        f"{next(iter(run_ids))}"
    )


def check_generation_parameters() -> None:

    path = (
        DATASET_DIR
        / "generation_parameters.json"
    )

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        parameters = json.load(file)

    assert parameters["record_count"] == EXPECTED_RECORDS
    assert "seed" in parameters
    assert "run_id" in parameters
    assert "generator_version" in parameters

    print("[PASS] Generation parameters are valid")


def check_no_empty_values(observable) -> None:

    critical_fields = [
        "record_id",
        "package_id",
        "product_id",
        "asset_id",
        "expected_vendor_id",
        "observed_vendor_id",
        "expected_hash",
        "observed_hash",
        "run_id",
    ]

    for row in observable:

        for field in critical_fields:

            assert row[field].strip() != "", (
                f"Empty value in {field} "
                f"for {row['record_id']}"
            )

    print("[PASS] Critical observable fields contain no empty values")


def check_file_hashes() -> None:

    files_to_hash = [
        "reference_data.csv",
        "observable_features.csv",
        "ground_truth_labels.csv",
        "scenario_manifests.csv",
        "generation_parameters.json",
        "split_assignments.csv",
    ]

    hashes = {}

    for filename in files_to_hash:

        path = DATASET_DIR / filename

        hashes[filename] = sha256_file(path)

    print("[PASS] Dataset files successfully hashed")

    hash_file = (
        DATASET_DIR
        / "dataset_file_hashes.json"
    )

    with hash_file.open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            hashes,
            file,
            indent=2,
        )

    print(
        "[PASS] dataset_file_hashes.json created"
    )


def main() -> None:

    print()
    print("==============================================")
    print(" SYNTHETIC DATASET VALIDATION")
    print("==============================================")
    print()
    print(f"Dataset directory: {DATASET_DIR}")
    print()

    check_required_files()

    observable = read_csv(
        "observable_features.csv"
    )

    labels = read_csv(
        "ground_truth_labels.csv"
    )

    manifests = read_csv(
        "scenario_manifests.csv"
    )

    splits = read_csv(
        "split_assignments.csv"
    )

    check_record_count(
        observable,
        labels,
        manifests,
        splits,
    )

    check_columns(
        observable,
        labels,
    )

    check_record_ids(
        observable,
        labels,
        manifests,
        splits,
    )

    check_hash_integrity(
        observable
    )

    check_boolean_fields(
        observable
    )

    check_decision_labels(
        labels
    )

    check_label_distribution(
        labels
    )

    check_split_integrity(
        splits
    )

    check_group_leakage(
        splits
    )

    check_reproducibility(
        observable
    )

    check_generation_parameters()

    check_no_empty_values(
        observable
    )

    check_file_hashes()

    print()
    print("==============================================")
    print(" DATASET VALIDATION PASSED")
    print("==============================================")
    print()
    print("The dataset is ready for the next validation stage.")
    print("ML training has NOT been started.")
    print("Rule/ML fusion has NOT been implemented.")
    print()


if __name__ == "__main__":
    main()