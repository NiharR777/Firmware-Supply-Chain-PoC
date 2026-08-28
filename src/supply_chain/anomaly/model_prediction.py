from pathlib import Path
import csv
import json

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder

from .feature_engineering import (
    build_features,
    FEATURE_NAMES,
)

from ..decision_engine import evaluate_scenario


# =========================================================
# Project paths
# =========================================================

BASE_DIR = Path("data/synthetic/supply_chain_poc")

GROUND_TRUTH_FILE = (
    BASE_DIR
    / "ground_truth"
    / "scenario_ground_truth.csv"
)

OUTPUT_DIR = (
    BASE_DIR
    / "generated"
    / "ml_predictions"
)

OUTPUT_FILE = (
    OUTPUT_DIR
    / "ml_risk_predictions.json"
)


# =========================================================
# Load ground-truth training data
# =========================================================

def load_training_data():

    X = []
    y = []

    if not GROUND_TRUTH_FILE.exists():
        raise FileNotFoundError(
            f"Ground truth file not found: "
            f"{GROUND_TRUTH_FILE}"
        )

    with open(
        GROUND_TRUTH_FILE,
        "r",
        encoding="utf-8",
        newline=""
    ) as file:

        reader = csv.DictReader(file)

        for row in reader:

            scenario_type = (
                row["scenario_type"].strip()
            )

            expected_decision = (
                row["expected_decision"].strip()
            )

            X.append(
                build_features(scenario_type)
            )

            y.append(
                expected_decision
            )

    return X, y


# =========================================================
# Train prediction model
# =========================================================

def train_prediction_model():

    X, y = load_training_data()

    label_encoder = LabelEncoder()

    y_encoded = label_encoder.fit_transform(y)

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight="balanced",
    )

    model.fit(
        X,
        y_encoded
    )

    return model, label_encoder


# =========================================================
# Generate ML predictions
# =========================================================

def generate_predictions():

    print()
    print(
        "===== REFINERY ML RISK PREDICTION ====="
    )

    model, label_encoder = (
        train_prediction_model()
    )

    prediction_rows = []

    # -----------------------------------------------------
    # Evaluate all refinery scenarios
    # -----------------------------------------------------

    for number in range(1, 11):

        scenario_id = (
            f"SC-{number:03d}"
        )

        # -------------------------------------------------
        # Read scenario information
        # -------------------------------------------------

        scenario_type = None
        expected_decision = None

        with open(
            GROUND_TRUTH_FILE,
            "r",
            encoding="utf-8",
            newline=""
        ) as file:

            reader = csv.DictReader(file)

            for row in reader:

                if (
                    row["scenario_id"].strip()
                    == scenario_id
                ):

                    scenario_type = (
                        row["scenario_type"].strip()
                    )

                    expected_decision = (
                        row["expected_decision"].strip()
                    )

                    break

        if scenario_type is None:
            print(
                f"{scenario_id} | "
                "ERROR: Scenario not found"
            )
            continue

        # -------------------------------------------------
        # Build ML features
        # -------------------------------------------------

        features = build_features(
            scenario_type
        )

        # -------------------------------------------------
        # ML prediction
        # -------------------------------------------------

        prediction_encoded = model.predict(
            [features]
        )[0]

        ml_prediction = (
            label_encoder.inverse_transform(
                [prediction_encoded]
            )[0]
        )

        # -------------------------------------------------
        # Prediction probability
        # -------------------------------------------------

        probabilities = (
            model.predict_proba(
                [features]
            )[0]
        )

        class_probabilities = {}

        for class_name, probability in zip(
            label_encoder.classes_,
            probabilities
        ):

            class_probabilities[
                class_name
            ] = round(
                float(probability),
                4
            )

        confidence = round(
            float(max(probabilities)),
            4
        )

        # -------------------------------------------------
        # Rule-based decision
        # -------------------------------------------------

        rule_result = evaluate_scenario(
            scenario_id
        )

        rule_decision = rule_result.get(
            "risk_level",
            "unknown"
        )

        # -------------------------------------------------
        # Compare ML and rule engine
        # -------------------------------------------------

        agreement = (
            ml_prediction
            == rule_decision
        )

        prediction_rows.append({

            "scenario_id":
                scenario_id,

            "scenario_type":
                scenario_type,

            "expected_decision":
                expected_decision,

            "ml_prediction":
                ml_prediction,

            "ml_confidence":
                confidence,

            "class_probabilities":
                class_probabilities,

            "rule_based_decision":
                rule_decision,

            "rule_based_score":
                rule_result.get(
                    "risk_score",
                    0
                ),

            "risk_factors":
                rule_result.get(
                    "risk_factors",
                    []
                ),

            "ml_rule_agreement":
                agreement,

            "data_provenance":
                "SYNTHETIC",
        })

        # -------------------------------------------------
        # Console output
        # -------------------------------------------------

        print()
        print(
            f"{scenario_id} | "
            f"Type: {scenario_type}"
        )

        print(
            f"  Expected: "
            f"{expected_decision}"
        )

        print(
            f"  ML Prediction: "
            f"{ml_prediction}"
        )

        print(
            f"  ML Confidence: "
            f"{confidence:.2f}"
        )

        print(
            f"  Rule-Based Risk: "
            f"{rule_decision}"
        )

        print(
            f"  Rule-Based Score: "
            f"{rule_result.get('risk_score', 0)}"
        )

        print(
            f"  ML/Rule Agreement: "
            f"{agreement}"
        )

    # =====================================================
    # Save predictions
    # =====================================================

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    output = {
        "model_type":
            "RandomForestClassifier",

        "feature_names":
            FEATURE_NAMES,

        "scenario_count":
            len(prediction_rows),

        "predictions":
            prediction_rows,

        "data_provenance":
            "SYNTHETIC",
    }

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            output,
            file,
            indent=2
        )

    # =====================================================
    # Summary
    # =====================================================

    agreement_count = sum(
        1
        for row in prediction_rows
        if row["ml_rule_agreement"]
    )

    print()
    print(
        "===== ML PREDICTION SUMMARY ====="
    )

    print(
        f"Total Scenarios: "
        f"{len(prediction_rows)}"
    )

    print(
        f"ML/Rule Agreements: "
        f"{agreement_count}"
    )

    print(
        f"ML/Rule Disagreements: "
        f"{len(prediction_rows) - agreement_count}"
    )

    print()
    print(
        "Prediction results saved to:"
    )

    print(
        OUTPUT_FILE
    )

    print()
    print(
        "===== ML PREDICTION COMPLETE ====="
    )


# =========================================================
# Main
# =========================================================

if __name__ == "__main__":
    generate_predictions()