"""Validate lineage-grouped train/validation/test assignments."""

from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
DATASET_DIR = ROOT / "data" / "synthetic" / "supply_chain_poc" / "dataset"


def main() -> None:
    splits = pd.read_csv(DATASET_DIR / "split_assignments.csv")
    labels = pd.read_csv(DATASET_DIR / "ground_truth_labels.csv")
    observed = pd.read_csv(DATASET_DIR / "observable_features.csv")
    assert len(splits) == len(labels) == len(observed) == 5000
    assert splits["record_id"].is_unique
    assert set(splits["split"]) == {"train", "validation", "test"}
    assert (splits["group_id"] == observed.set_index("record_id").loc[splits["record_id"], "lineage_id"].to_numpy()).all()

    groups = splits.groupby("group_id").agg(records=("record_id", "size"), splits=("split", "nunique"))
    assert len(groups) == 500
    assert set(groups["records"]) == {10}
    assert set(groups["splits"]) == {1}
    assert splits["split"].value_counts().to_dict() == {"train": 3500, "validation": 750, "test": 750}

    joined = splits[["record_id", "split"]].merge(labels, on="record_id", validate="one_to_one")
    for split_name in ["train", "validation", "test"]:
        classes = set(joined.loc[joined["split"] == split_name, "ground_truth_label"])
        assert classes == {"normal", "investigate", "high_risk"}

    print("[PASS] 500 independent lineages, each containing 10 assessments")
    print("[PASS] No lineage crosses train/validation/test")
    print("[PASS] Split sizes: train=3500, validation=750, test=750")
    print("[PASS] Every split contains all three decision classes")


if __name__ == "__main__":
    main()
