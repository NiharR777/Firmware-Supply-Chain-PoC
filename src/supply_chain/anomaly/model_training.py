from pathlib import Path
import csv
import json

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report


# =========================================================
# Project paths
# =========================================================

BASE_DIR = Path("data/synthetic/supply_chain_poc")

GROUND_TRUTH_FILE = (
    BASE_DIR
    / "ground_truth"
    / "scenario_ground_truth.csv"
)

MODEL_DIR = (
    BASE_DIR
    / "generated"
    / "ml_models"
)

MODEL_INFO_FILE = (
    MODEL_DIR
    / "model_info.json"
)


# =========================================================
# Feature definitions
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
# Feature extraction from scenario type
# =========================================================

def build_features(scenario_type):
    """
    Convert the synthetic refinery scenario type
    into the ML feature vector.
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

def load_training_data():

    if not GROUND_TRUTH_FILE.exists():
        raise FileNotFoundError(
            f"Ground truth file not found: "
            f"{GROUND_TRUTH_FILE}"
        )

    X = []
    y = []
    scenario_ids = []

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

            scenario_id = row[
                "scenario_id"
            ].strip()

            scenario_type = row[
                "scenario_type"
            ].strip()

            expected_decision = row[
                "expected_decision"
            ].strip()

            features = build_features(
                scenario_type
            )

            X.append(features)
            y.append(expected_decision)
            scenario_ids.append(scenario_id)

    return X, y, scenario_ids


# =========================================================
# Train ML model
# =========================================================

def train_model():

    print()
    print(
        "===== REFINERY ML RISK MODEL TRAINING ====="
    )

    X, y, scenario_ids = (
        load_training_data()
    )

    print()
    print(
        f"Training samples: {len(X)}"
    )

    print(
        f"Features: {len(FEATURE_NAMES)}"
    )

    print(
        f"Classes: {sorted(set(y))}"
    )

    # -----------------------------------------------------
    # Encode target labels
    # -----------------------------------------------------

    label_encoder = LabelEncoder()

    y_encoded = label_encoder.fit_transform(y)

    # -----------------------------------------------------
    # Train Random Forest
    # -----------------------------------------------------

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight="balanced",
    )

    model.fit(
        X,
        y_encoded
    )

    # -----------------------------------------------------
    # Training-set evaluation
    # -----------------------------------------------------

    predictions = model.predict(X)

    accuracy = accuracy_score(
        y_encoded,
        predictions
    )

    print()
    print(
        f"Training Accuracy: "
        f"{accuracy:.2f}"
    )

    print()
    print("===== CLASSIFICATION REPORT =====")

    print(
        classification_report(
            y_encoded,
            predictions,
            target_names=label_encoder.classes_,
            zero_division=0,
        )
    )

    # -----------------------------------------------------
    # Feature importance
    # -----------------------------------------------------

    print(
        "===== FEATURE IMPORTANCE ====="
    )

    feature_importance = {}

    for feature, importance in zip(
        FEATURE_NAMES,
        model.feature_importances_
    ):

        feature_importance[
            feature
        ] = round(
            float(importance),
            4
        )

        print(
            f"{feature}: "
            f"{importance:.4f}"
        )

    # -----------------------------------------------------
    # Save model information
    #
    # We keep the model metadata in JSON for this PoC.
    # The actual model will be reconstructed during
    # prediction using the same deterministic configuration.
    # -----------------------------------------------------

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    model_info = {
        "model_type": "RandomForestClassifier",
        "random_state": 42,
        "n_estimators": 100,
        "feature_names": FEATURE_NAMES,
        "classes": label_encoder.classes_.tolist(),
        "training_samples": len(X),
        "training_accuracy": round(
            float(accuracy),
            4
        ),
        "feature_importance": feature_importance,
        "scenario_ids": scenario_ids,
        "data_provenance": "SYNTHETIC",
    }

    with open(
        MODEL_INFO_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            model_info,
            file,
            indent=2
        )

    print()
    print(
        "Model training completed successfully."
    )

    print(
        f"Model information: "
        f"{MODEL_INFO_FILE}"
    )

    print(
        "=========================================="
    )


# =========================================================
# Main
# =========================================================

if __name__ == "__main__":
    train_model()