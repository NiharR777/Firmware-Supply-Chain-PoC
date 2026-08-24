from pathlib import Path
import json
import csv

from risk_model import calculate_risk_score


# ---------------------------------------------------------
# Project paths
# ---------------------------------------------------------

BASE_DIR = Path("data/synthetic/supply_chain_poc")

EVIDENCE_DIR = (
    BASE_DIR / "generated" / "evidence_bundles"
)

MITRE_MAPPING_FILE = (
    BASE_DIR / "mitre_attack_mapping.csv"
)


# ---------------------------------------------------------
# Load JSON
# ---------------------------------------------------------

def load_json(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


# ---------------------------------------------------------
# Load MITRE mapping
# ---------------------------------------------------------

def load_mitre_mapping():
    mapping = {}

    if not MITRE_MAPPING_FILE.exists():
        return mapping

    with open(
        MITRE_MAPPING_FILE,
        "r",
        encoding="utf-8",
        newline=""
    ) as file:

        reader = csv.DictReader(file)

        for row in reader:
            mapping[row["scenario_id"]] = row

    return mapping


# ---------------------------------------------------------
# Decision Engine
# ---------------------------------------------------------

def evaluate_scenario(scenario_id):

    bundle_dir = EVIDENCE_DIR / scenario_id

    if not bundle_dir.exists():
        raise ValueError(
            f"Evidence bundle {scenario_id} not found."
        )

    package = load_json(
        bundle_dir / "package.json"
    )

    hash_evidence = load_json(
        bundle_dir / "hash_evidence.json"
    )

    signature = load_json(
        bundle_dir / "signature_evidence.json"
    )

    sbom = load_json(
        bundle_dir / "sbom.json"
    )

    asset = load_json(
        bundle_dir / "asset_mapping.json"
    )

    # -----------------------------------------------------
    # Basic information
    # -----------------------------------------------------

    scenario_type = package.get("scenario_type")

    reasons = []

    risk_factors = []

    deployment_allowed = True

    # -----------------------------------------------------
    # 1. HASH INTEGRITY
    # -----------------------------------------------------

    if hash_evidence.get("hash_match") is False:

        risk_factors.append(
            "hash_integrity_failure"
        )

        deployment_allowed = False

        reasons.append(
            "Firmware package hash does not match "
            "the trusted vendor hash."
        )

    # -----------------------------------------------------
    # 2. SIGNATURE
    # -----------------------------------------------------

    if signature.get("signature_status") in [
        "invalid",
        "untrusted"
    ]:

        risk_factors.append(
            "signature_failure"
        )

        deployment_allowed = False

        reasons.append(
            "Firmware package signature is invalid "
            "or not trusted."
        )

    # -----------------------------------------------------
    # 3. TRUSTED ROOT
    # -----------------------------------------------------

    if signature.get("trusted_root_status") in [
        "untrusted",
        "invalid"
    ]:

        risk_factors.append(
            "trusted_root_failure"
        )

        deployment_allowed = False

        reasons.append(
            "Firmware package is not anchored "
            "to a trusted vendor root."
        )

    # -----------------------------------------------------
    # 4. SBOM
    # -----------------------------------------------------

    if sbom.get("sbom_status") in [
        "missing",
        "incomplete"
    ]:

        risk_factors.append(
            "missing_sbom"
        )

        deployment_allowed = False

        reasons.append(
            "SBOM evidence is missing or incomplete."
        )

    # -----------------------------------------------------
    # 5. VULNERABLE COMPONENT
    # -----------------------------------------------------

    if (
        sbom.get("vulnerability_status") == "affected"
        or
        sbom.get("vex_status") == "affected"
        or
        scenario_type == "vulnerable_component"
    ):

        risk_factors.append(
            "vulnerable_component"
        )

        deployment_allowed = False

        reasons.append(
            "A vulnerable component affects "
            "the firmware package."
        )

    # -----------------------------------------------------
    # 6. UNEXPECTED COMPONENT
    # -----------------------------------------------------

    if (
        sbom.get("unexpected_component") is True
        or
        scenario_type == "unexpected_component"
    ):

        risk_factors.append(
            "unexpected_component"
        )

        deployment_allowed = False

        reasons.append(
            "An unexpected component change was "
            "detected in the firmware package."
        )

    # -----------------------------------------------------
    # 7. UNTRUSTED VENDOR
    # -----------------------------------------------------

    if (
        signature.get("vendor_trust") == "untrusted"
        or
        package.get("vendor_trust") == "untrusted"
        or
        scenario_type == "untrusted_vendor"
    ):

        risk_factors.append(
            "untrusted_vendor"
        )

        deployment_allowed = False

        reasons.append(
            "Firmware package is associated "
            "with an untrusted vendor."
        )

    # -----------------------------------------------------
    # 8. UNAUTHORIZED ROLLBACK
    # -----------------------------------------------------

    if scenario_type == "rollback":

        risk_factors.append(
            "unauthorized_rollback"
        )

        deployment_allowed = False

        reasons.append(
            "Unauthorized rollback to an older "
            "firmware version was detected."
        )

    # -----------------------------------------------------
    # 9. STALE SECURITY EVIDENCE
    # -----------------------------------------------------

    if (
        scenario_type == "stale_evidence"
        or
        sbom.get("evidence_freshness") == "stale"
    ):

        risk_factors.append(
            "stale_evidence"
        )

        deployment_allowed = False

        reasons.append(
            "Security evidence is stale and requires "
            "review before deployment."
        )

    # -----------------------------------------------------
    # 10. CALCULATE EXPLAINABLE RISK
    # -----------------------------------------------------

    risk_result = calculate_risk_score(
        risk_factors
    )

    risk_score = risk_result["risk_score"]

    risk_level = risk_result["risk_level"]

    risk_breakdown = risk_result["breakdown"]

    # -----------------------------------------------------
    # 11. LOAD MITRE INFORMATION
    # -----------------------------------------------------

    mitre_mapping = load_mitre_mapping()

    mitre_data = mitre_mapping.get(
        scenario_id,
        {}
    )

    attack_description = mitre_data.get(
        "attack_description",
        "Not mapped"
    )

    mitre_tactic = mitre_data.get(
        "mitre_tactic",
        "Not mapped"
    )

    mitre_technique = mitre_data.get(
        "mitre_technique",
        "Not mapped"
    )

    # -----------------------------------------------------
    # 12. FINAL RECOMMENDATION
    # -----------------------------------------------------

    if risk_level == "high_risk":

        recommendation = "quarantine_review"

    elif risk_level == "investigate":

        recommendation = "investigate"

    else:

        recommendation = "allow_after_human_review"

    # -----------------------------------------------------
    # 13. FINAL DECISION OBJECT
    # -----------------------------------------------------

    decision = {

        "scenario_id":
            scenario_id,

        "package_id":
            package.get("package_id"),

        "asset_id":
            asset.get("asset_id"),

        "device_type":
            asset.get("device_type"),

        "process_unit":
            asset.get("process_unit"),

        # Explainable risk information
        "risk_score":
            risk_score,

        "risk_level":
            risk_level,

        "risk_factors":
            risk_factors,

        "risk_breakdown":
            risk_breakdown,

        # MITRE information
        "attack_description":
            attack_description,

        "mitre_tactic":
            mitre_tactic,

        "mitre_technique":
            mitre_technique,

        "deployment_allowed":
            deployment_allowed,

        "recommendation":
            recommendation,

        "reasons":
            reasons,

        "human_approval_required":
            True,

        "real_action_executed":
            False,

        "data_provenance":
            "SYNTHETIC GROUND TRUTH"
    }

    return decision


# ---------------------------------------------------------
# Test all refinery scenarios
# ---------------------------------------------------------

if __name__ == "__main__":

    print()

    print(
        "===== REFINERY FIRMWARE SUPPLY-CHAIN "
        "RISK DECISION ====="
    )

    for number in range(1, 11):

        scenario_id = f"SC-{number:03d}"

        try:

            result = evaluate_scenario(
                scenario_id
            )

            print()

            print(
                f"{scenario_id} | "
                f"Package: {result['package_id']} | "
                f"Score: {result['risk_score']} | "
                f"Risk: {result['risk_level']} | "
                f"Deployment: "
                f"{result['deployment_allowed']} | "
                f"Recommendation: "
                f"{result['recommendation']}"
            )

            print(
                f"  Attack Type: "
                f"{result['attack_description']}"
            )

            print(
                f"  MITRE Tactic: "
                f"{result['mitre_tactic']}"
            )

            print(
                f"  MITRE Technique: "
                f"{result['mitre_technique']}"
            )

            print(
                f"  Risk Factors: "
                f"{result['risk_factors']}"
            )

            print(
                f"  Risk Breakdown: "
                f"{result['risk_breakdown']}"
            )

            for reason in result["reasons"]:

                print(
                    f"  - {reason}"
                )

        except Exception as error:

            print()

            print(
                f"{scenario_id} | ERROR: {error}"
            )

    print()

    print(
        "===== RISK DECISION EVALUATION COMPLETE ====="
    )