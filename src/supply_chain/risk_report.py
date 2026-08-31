from pathlib import Path
import csv

from .decision_engine import evaluate_scenario


# ---------------------------------------------------------
# Project paths
# ---------------------------------------------------------

BASE_DIR = Path("data/synthetic/supply_chain_poc")

MITRE_FILE = BASE_DIR / "mitre_attack_mapping.csv"

REPORT_DIR = (
    BASE_DIR
    / "generated"
    / "reports"
)

REPORT_FILE = (
    REPORT_DIR
    / "risk_assessment_report.csv"
)


# ---------------------------------------------------------
# Load MITRE ATT&CK mapping
# ---------------------------------------------------------

def load_mitre_mapping():

    mitre_mapping = {}

    if not MITRE_FILE.exists():
        raise FileNotFoundError(
            f"MITRE mapping file not found: {MITRE_FILE}"
        )

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
                "MITRE mapping CSV is missing "
                "required columns."
            )

        for row in reader:

            scenario_id = row["scenario_id"].strip()

            mitre_mapping[scenario_id] = {
                "scenario_type":
                    row["scenario_type"].strip(),

                "attack_description":
                    row["attack_description"].strip(),

                "mitre_tactic":
                    row["mitre_tactic"].strip(),

                "mitre_technique":
                    row["mitre_technique"].strip()
            }

    return mitre_mapping


# ---------------------------------------------------------
# Generate risk assessment report
# ---------------------------------------------------------

def generate_report():

    print()
    print(
        "===== GENERATING REFINERY RISK ASSESSMENT ====="
    )

    # -----------------------------------------------------
    # Create report directory
    # -----------------------------------------------------

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # -----------------------------------------------------
    # Load MITRE mapping
    # -----------------------------------------------------

    mitre_mapping = load_mitre_mapping()

    report_rows = []

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

            print()
            print(
                f"{scenario_id} | ERROR: {error}"
            )

            continue

        # -------------------------------------------------
        # Get MITRE information
        # -------------------------------------------------

        mitre = mitre_mapping.get(
            scenario_id,
            {}
        )

        # -------------------------------------------------
        # Get refinery asset information
        # -------------------------------------------------

        asset_id = result.get(
            "affected_asset",
            "N/A"
        )

        device_type = result.get(
            "device_type",
            "N/A"
        )

        process_unit = result.get(
            "process_unit",
            "N/A"
        )

        # -------------------------------------------------
        # Get risk factors
        # -------------------------------------------------

        risk_factors = result.get(
            "risk_factors",
            []
        )

        # -------------------------------------------------
        # Build report row
        # -------------------------------------------------

        report_rows.append({

            "scenario_id":
                scenario_id,

            "package_id":
                result.get(
                    "package_id",
                    "N/A"
                ),

            "asset_id":
                asset_id,

            "device_type":
                device_type,

            "process_unit":
                process_unit,

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
                "; ".join(
                    risk_factors
                ),

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
        })

    # -----------------------------------------------------
    # Validate results
    # -----------------------------------------------------

    if not report_rows:

        raise RuntimeError(
            "No risk assessment results were generated."
        )

    # -----------------------------------------------------
    # CSV columns
    # -----------------------------------------------------

    fieldnames = [

        "scenario_id",

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

    # -----------------------------------------------------
    # Write CSV report
    # -----------------------------------------------------

    with open(
        REPORT_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()

        writer.writerows(
            report_rows
        )

    # -----------------------------------------------------
    # Console report
    # -----------------------------------------------------

    print()
    print(
        "===== RISK ASSESSMENT REPORT ====="
    )

    for row in report_rows:

        print()

        print(
            f"{row['scenario_id']} | "
            f"Package: {row['package_id']} | "
            f"Risk: {row['risk_level']} | "
            f"Score: {row['risk_score']}"
        )

        print(
            f"  Asset ID: "
            f"{row['asset_id']}"
        )

        print(
            f"  Device Type: "
            f"{row['device_type']}"
        )

        print(
            f"  Process Unit: "
            f"{row['process_unit']}"
        )

        print(
            f"  Attack Type: "
            f"{row['attack_description']}"
        )

        print(
            f"  MITRE: "
            f"{row['mitre_tactic']} -> "
            f"{row['mitre_technique']}"
        )

        print(
            f"  Risk Factors: "
            f"{row['risk_factors'] or 'None'}"
        )

        print(
            f"  Recommendation: "
            f"{row['recommendation']}"
        )

        print(
            f"  Deployment Allowed: "
            f"{row['deployment_allowed']}"
        )

        print(
            f"  Human Approval Required: "
            f"{row['human_approval_required']}"
        )

        print(
            f"  Real Action Executed: "
            f"{row['real_action_executed']}"
        )

    # -----------------------------------------------------
    # Completion message
    # -----------------------------------------------------

    print()

    print(
        "Report generated successfully."
    )

    print(
        f"Report file: {REPORT_FILE}"
    )

    print(
        "==================================="
    )


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

if __name__ == "__main__":

    generate_report()
