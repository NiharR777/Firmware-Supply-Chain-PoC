from pathlib import Path
import csv


# =========================================================
# Project paths
# =========================================================

BASE_DIR = Path("data/synthetic/supply_chain_poc")

GROUND_TRUTH_FILE = (
    BASE_DIR
    / "ground_truth"
    / "scenario_ground_truth.csv"
)


# =========================================================
# ML feature definitions
# =========================================================

FEATURE_NAMES = [
    "hash_mismatch",
    "signature_failure",
    "trusted_root_failure",
    "vulnerable_component",
    "rollback_detected",
    "rollback_unauthorized",
    "missing_sbom",
    "unexpected_component",
    "untrusted_vendor",
    "stale_evidence",
]


# =========================================================
# Feature extraction
# =========================================================

def build_features(scenario_type):
    """
    Convert a refinery scenario type into
    a deterministic ML feature vector.
    """

    features = {
        feature: 0
        for feature in FEATURE_NAMES
    }

    if scenario_type == "hash_mismatch":
        features["hash_mismatch"] = 1

    elif scenario_type == "invalid_signature":
        features["signature_failure"] = 1
        features["trusted_root_failure"] = 1

    elif scenario_type == "vulnerable_component":
        features["vulnerable_component"] = 1

    elif scenario_type == "rollback":
        features["rollback_detected"] = 1
        features["rollback_unauthorized"] = 1

    elif scenario_type == "missing_sbom":
        features["missing_sbom"] = 1

    elif scenario_type == "unexpected_component":
        features["unexpected_component"] = 1

    elif scenario_type == "untrusted_vendor":
        features["untrusted_vendor"] = 1

    elif scenario_type == "stale_evidence":
        features["stale_evidence"] = 1

    return [
        features[feature]
        for feature in FEATURE_NAMES
    ]


# =========================================================
# Load ground truth
# =========================================================

def load_ground_truth():

    if not GROUND_TRUTH_FILE.exists():
        raise FileNotFoundError(
            f"Ground truth file not found: "
            f"{GROUND_TRUTH_FILE}"
        )

    scenarios = []

    with open(
        GROUND_TRUTH_FILE,
        "r",
        encoding="utf-8",
        newline=""
    ) as file:

        reader = csv.DictReader(file)

        required_columns = {
            "scenario_id",
            "scenario_type",
            "expected_decision",
        }

        if not required_columns.issubset(
            reader.fieldnames or []
        ):
            raise ValueError(
                "Ground truth CSV is missing "
                "required columns."
            )

        for row in reader:

            scenarios.append({
                "scenario_id":
                    row["scenario_id"].strip(),

                "scenario_type":
                    row["scenario_type"].strip(),

                "expected_decision":
                    row["expected_decision"].strip(),
            })

    return scenarios


# =========================================================
# Generate ML feature dataset
# =========================================================

def generate_feature_dataset():

    print()
    print(
        "===== REFINERY ML FEATURE DATASET ====="
    )

    scenarios = load_ground_truth()

    dataset = []

    for scenario in scenarios:

        scenario_id = scenario[
            "scenario_id"
        ]

        scenario_type = scenario[
            "scenario_type"
        ]

        expected_decision = scenario[
            "expected_decision"
        ]

        feature_vector = build_features(
            scenario_type
        )

        feature_dict = dict(
            zip(
                FEATURE_NAMES,
                feature_vector
            )
        )

        dataset.append({
            "scenario_id":
                scenario_id,

            "scenario_type":
                scenario_type,

            "expected_decision":
                expected_decision,

            "features":
                feature_dict,
        })

        print()
        print(
            f"{scenario_id} | "
            f"Type: {scenario_type} | "
            f"Expected: {expected_decision}"
        )

        print("  Features:")

        active_features = [
            feature
            for feature, value
            in feature_dict.items()
            if value == 1
        ]

        if active_features:

            for feature in active_features:

                print(
                    f"    {feature}: 1"
                )

        else:

            print("    None")

    print()
    print(
        "===== FEATURE EXTRACTION COMPLETE ====="
    )

    return dataset


# =========================================================
# Main
# =========================================================

if __name__ == "__main__":
    generate_feature_dataset()