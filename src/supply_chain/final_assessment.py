from pathlib import Path
import csv
import json

from .decision_engine import evaluate_scenario


# ---------------------------------------------------------
# Project paths
# ---------------------------------------------------------

BASE_DIR = Path("data/synthetic/supply_chain_poc")

MITRE_FILE = BASE_DIR / "mitre_attack_mapping.csv"

REPORT_DIR = BASE_DIR / "generated" / "reports"

FINAL_REPORT_FILE = (
    REPORT_DIR / "final_refinery_assessment.csv"
)

FINAL_JSON_FILE = (
    REPORT_DIR / "final_refinery_assessment.json"
)


# ---------------------------------------------------------
# Load MITRE ATT&CK mapping
# ---------------------------------------------------------

def load_mitre_mapping():

    if not MITRE_FILE.exists():
        raise FileNotFoundError(
            f"MITRE mapping file not found: {MITRE_FILE}"
        )

    mapping = {}

    with open(
        MITRE_FILE,
        "r",
        encoding="utf-8",
        newline=""
    ) as file:

        reader = csv.DictReader(file)

        required_columns = {
            "scenario_id",
            "scenario_type",
            "attack_description",
            "mitre_tactic",
            "mitre_technique"
        }

        if not required_columns.issubset(
            reader.fieldnames or []
        ):
            raise ValueError(
                "MITRE mapping CSV is missing required columns."
            )

        for row in reader:

            scenario_id = row["scenario_id"].strip()

            mapping[scenario_id] = {
                "scenario_type":
                    row["scenario_type"].strip(),

                "attack_description":
                    row["attack_description"].strip(),

                "mitre_tactic":
                    row["mitre_tactic"].strip(),

                "mitre_technique":
                    row["mitre_technique"].strip()
            }

    return mapping


# ---------------------------------------------------------
# Build final assessment
# ---------------------------------------------------------

def build_final_assessment():

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    mitre_mapping = load_mitre_mapping()

    assessments = []

    print()
    print("===== FINAL REFINERY SUPPLY-CHAIN ASSESSMENT =====")

    # -----------------------------------------------------
    # Evaluate all refinery scenarios
    # -----------------------------------------------------

    for number in range(1, 11):

        scenario_id = f"SC-{number:03d}"

        try:
            result = evaluate_scenario(
                scenario_id
            )

        except Exception as error:

            print(
                f"{scenario_id} | ERROR: {error}"
            )

            continue

        mitre = mitre_mapping.get(
            scenario_id,
            {}
        )

        risk_factors = result.get(
            "risk_factors",
            []
        )

        assessment = {

            "scenario_id":
                scenario_id,

            "scenario_type":
                mitre.get(
                    "scenario_type",
                    "N/A"
                ),

            "package_id":
                result.get(
                    "package_id",
                    "N/A"
                ),

            "asset_id":
                result.get(
                    "asset_id",
                    "N/A"
                ),

            "device_type":
                result.get(
                    "device_type",
                    "N/A"
                ),

            "process_unit":
                result.get(
                    "process_unit",
                    "N/A"
                ),

            "attack_description":
                mitre.get(
                    "attack_description",
                    "N/A"
                ),

            "mitre_tactic":
                mitre.get(
                    "mitre_tactic",
                    "N/A"
                ),

            "mitre_technique":
                mitre.get(
                    "mitre_technique",
                    "N/A"
                ),

            "risk_score":
                result.get(
                    "risk_score",
                    0
                ),

            "risk_level":
                result.get(
                    "risk_level",
                    "unknown"
                ),

            "risk_factors":
                "; ".join(risk_factors)
                if risk_factors
                else "None",

            "recommendation":
                result.get(
                    "recommendation",
                    "N/A"
                ),

            "deployment_allowed":
                result.get(
                    "deployment_allowed",
                    False
                ),

            "human_approval_required":
                result.get(
                    "human_approval_required",
                    True
                ),

            "real_action_executed":
                result.get(
                    "real_action_executed",
                    False
                )
        }

        assessments.append(assessment)

        # -------------------------------------------------
        # Console output
        # -------------------------------------------------

        print()
        print(
            f"{scenario_id} | "
            f"{assessment['package_id']} | "
            f"{assessment['asset_id']}"
        )

        print(
            f"  Device: "
            f"{assessment['device_type']}"
        )

        print(
            f"  Process Unit: "
            f"{assessment['process_unit']}"
        )

        print(
            f"  Risk: "
            f"{assessment['risk_level']} | "
            f"Score: "
            f"{assessment['risk_score']}"
        )

        print(
            f"  Attack: "
            f"{assessment['attack_description']}"
        )

        print(
            f"  MITRE: "
            f"{assessment['mitre_tactic']} -> "
            f"{assessment['mitre_technique']}"
        )

        print(
            f"  Risk Factors: "
            f"{assessment['risk_factors']}"
        )

        print(
            f"  Recommendation: "
            f"{assessment['recommendation']}"
        )

        print(
            f"  Deployment Allowed: "
            f"{assessment['deployment_allowed']}"
        )

        print(
            f"  Human Approval Required: "
            f"{assessment['human_approval_required']}"
        )

        print(
            f"  Real Action Executed: "
            f"{assessment['real_action_executed']}"
        )

    # -----------------------------------------------------
    # Validate results
    # -----------------------------------------------------

    if not assessments:
        raise RuntimeError(
            "No refinery assessments were generated."
        )

    # -----------------------------------------------------
    # CSV output
    # -----------------------------------------------------

    fieldnames = [
        "scenario_id",
        "scenario_type",
        "package_id",
        "asset_id",
        "device_type",
        "process_unit",
        "attack_description",
        "mitre_tactic",
        "mitre_technique",
        "risk_score",
        "risk_level",
        "risk_factors",
        "recommendation",
        "deployment_allowed",
        "human_approval_required",
        "real_action_executed"
    ]

    with open(
        FINAL_REPORT_FILE,
        "w",
        encoding="utf-8",
        newline=""
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        writer.writerows(
            assessments
        )

    # -----------------------------------------------------
    # JSON output
    # -----------------------------------------------------

    with open(
        FINAL_JSON_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            {
                "assessment_type":
                    "REFINERY_FIRMWARE_SUPPLY_CHAIN",

                "data_provenance":
                    "SYNTHETIC",

                "scenario_count":
                    len(assessments),

                "assessments":
                    assessments
            },
            file,
            indent=2
        )

    # -----------------------------------------------------
    # Summary
    # -----------------------------------------------------

    high_risk_count = sum(
        1
        for item in assessments
        if item["risk_level"] == "high_risk"
    )

    investigate_count = sum(
        1
        for item in assessments
        if item["risk_level"] == "investigate"
    )

    normal_count = sum(
        1
        for item in assessments
        if item["risk_level"] == "normal"
    )

    blocked_count = sum(
        1
        for item in assessments
        if not item["deployment_allowed"]
    )

    # -----------------------------------------------------
    # Final summary
    # -----------------------------------------------------

    print()
    print("===== ASSESSMENT SUMMARY =====")

    print(
        f"Total Scenarios: {len(assessments)}"
    )

    print(
        f"High Risk: {high_risk_count}"
    )

    print(
        f"Investigate: {investigate_count}"
    )

    print(
        f"Normal: {normal_count}"
    )

    print(
        f"Deployment Blocked: {blocked_count}"
    )

    print()
    print(
        "Final CSV:"
    )

    print(
        FINAL_REPORT_FILE
    )

    print()
    print(
        "Final JSON:"
    )

    print(
        FINAL_JSON_FILE
    )

    print()
    print(
        "===== FINAL ASSESSMENT COMPLETE ====="
    )


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

if __name__ == "__main__":

    build_final_assessment()