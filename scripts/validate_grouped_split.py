"""
Grouped Split Validation
Firmware Supply-Chain PoC

Validates that package groups do not cross train/validation/test splits.
"""

from __future__ import annotations

import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

DATASET_DIR = (
    ROOT
    / "data"
    / "synthetic"
    / "supply_chain_poc"
    / "dataset"
)

SPLIT_FILE = DATASET_DIR / "split_assignments.csv"
OBSERVABLE_FILE = DATASET_DIR / "observable_features.csv"

EXPECTED_SPLITS = {
    "train",
    "validation",
    "test",
}


def read_csv(path: Path) -> list[dict]:
    assert path.exists(), f"Missing file: {path}"

    with path.open(
        "r",
        encoding="utf-8",
        newline="",
    ) as file:
        return list(csv.DictReader(file))


def validate_columns(rows: list[dict]) -> None:

    required = {
        "record_id",
        "package_id",
        "split",
        "group_id",
        "run_id",
    }

    actual = set(rows[0].keys())

    missing = required - actual

    assert not missing, (
        f"Missing columns: {missing}"
    )

    print("[PASS] Required split columns are present")


def validate_record_count(rows: list[dict]) -> None:

    observable = read_csv(OBSERVABLE_FILE)

    assert len(rows) == len(observable), (
        "Split record count does not match observable dataset"
    )

    print(
        f"[PASS] Split contains {len(rows)} records"
    )


def validate_unique_records(rows: list[dict]) -> None:

    record_ids = [
        row["record_id"]
        for row in rows
    ]

    assert len(record_ids) == len(set(record_ids)), (
        "Duplicate record_id detected"
    )

    print("[PASS] All record IDs are unique")


def validate_splits(rows: list[dict]) -> None:

    actual = {
        row["split"]
        for row in rows
    }

    assert actual == EXPECTED_SPLITS, (
        f"Unexpected split values: {actual}"
    )

    print(
        "[PASS] Valid split values: "
        "train, validation, test"
    )


def validate_group_integrity(rows: list[dict]) -> None:

    groups = {
        "train": set(),
        "validation": set(),
        "test": set(),
    }

    for row in rows:

        group_id = row["group_id"]
        split = row["split"]

        groups[split].add(group_id)

    train_validation = (
        groups["train"]
        & groups["validation"]
    )

    train_test = (
        groups["train"]
        & groups["test"]
    )

    validation_test = (
        groups["validation"]
        & groups["test"]
    )

    assert not train_validation, (
        f"Train/validation group leakage: "
        f"{train_validation}"
    )

    assert not train_test, (
        f"Train/test group leakage: "
        f"{train_test}"
    )

    assert not validation_test, (
        f"Validation/test group leakage: "
        f"{validation_test}"
    )

    print(
        "[PASS] No group appears in multiple splits"
    )


def validate_package_grouping(rows: list[dict]) -> None:

    package_to_splits = {}

    for row in rows:

        package_id = row["package_id"]
        split = row["split"]

        package_to_splits.setdefault(
            package_id,
            set(),
        ).add(split)

    leaked_packages = {
        package_id: splits
        for package_id, splits
        in package_to_splits.items()
        if len(splits) > 1
    }

    assert not leaked_packages, (
        "Package leakage detected: "
        f"{leaked_packages}"
    )

    print(
        "[PASS] Package groups remain within one split"
    )


def validate_run_id(rows: list[dict]) -> None:

    run_ids = {
        row["run_id"]
        for row in rows
    }

    assert len(run_ids) == 1, (
        f"Expected one run ID, found: {run_ids}"
    )

    print(
        f"[PASS] Single dataset run ID: "
        f"{next(iter(run_ids))}"
    )


def print_distribution(rows: list[dict]) -> None:

    counts = {
        "train": 0,
        "validation": 0,
        "test": 0,
    }

    for row in rows:
        counts[row["split"]] += 1

    print()
    print("Split distribution:")

    for split in [
        "train",
        "validation",
        "test",
    ]:
        print(
            f"  {split:12s}: "
            f"{counts[split]}"
        )

    total = sum(counts.values())

    print(
        f"  {'total':12s}: "
        f"{total}"
    )

    assert total == len(rows)


def main() -> None:

    print()
    print("==============================================")
    print(" GROUPED SPLIT VALIDATION")
    print("==============================================")
    print()

    rows = read_csv(SPLIT_FILE)

    validate_columns(rows)
    validate_record_count(rows)
    validate_unique_records(rows)
    validate_splits(rows)
    validate_group_integrity(rows)
    validate_package_grouping(rows)
    validate_run_id(rows)

    print_distribution(rows)

    print()
    print("==============================================")
    print(" GROUPED SPLIT VALIDATION PASSED")
    print("==============================================")
    print()
    print(
        "No package/group leakage exists between "
        "train, validation and test."
    )
    print()
    print(
        "Dataset is ready for feature engineering."
    )
    print()


if __name__ == "__main__":
    main()