from pathlib import Path
import json


# ---------------------------------------------------------
# Project paths
# ---------------------------------------------------------

BASE_DIR = Path("data/synthetic/supply_chain_poc")

EVIDENCE_DIR = (
    BASE_DIR / "generated" / "evidence_bundles"
)


# ---------------------------------------------------------
# Load JSON
# ---------------------------------------------------------

def load_json(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


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

    decision_data = load_json(
        bundle_dir / "decision.json"
    )

    # -----------------------------------------------------
    # Basic information
    # -----------------------------------------------------

    scenario_type = package.get("scenario_type")

    reasons = []

    risk_level = "normal"
    deployment_allowed = True

    # -----------------------------------------------------
    # 1. HASH INTEGRITY
    # -----------------------------------------------------

    if hash_evidence.get("hash_match") is False:

        risk_level = "high_risk"
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

        risk_level = "high_risk"
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

        risk_level = "high_risk"
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

        if risk_level != "high_risk":
            risk_level = "investigate"

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

        if risk_level != "high_risk":
            risk_level = "investigate"

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

        if risk_level != "high_risk":
            risk_level = "investigate"

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

        risk_level = "high_risk"
        deployment_allowed = False

        reasons.append(
            "Firmware package is associated "
            "with an untrusted vendor."
        )

    # -----------------------------------------------------
    # 8. UNAUTHORIZED ROLLBACK
    # -----------------------------------------------------

    if scenario_type == "rollback":

        risk_level = "high_risk"
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

        if risk_level != "high_risk":
            risk_level = "investigate"

        deployment_allowed = False

        reasons.append(
            "Security evidence is stale and requires "
            "review before deployment."
        )

    # -----------------------------------------------------
    # Final recommendation
    # -----------------------------------------------------

    if risk_level == "high_risk":

        recommendation = "quarantine_review"

    elif risk_level == "investigate":

        recommendation = "investigate"

    else:

        recommendation = "allow_after_human_review"

    # -----------------------------------------------------
    # Final decision object
    # -----------------------------------------------------

    decision = {

        "scenario_id": scenario_id,

        "package_id":
            package.get("package_id"),

        "asset_id":
            asset.get("asset_id"),

        "device_type":
            asset.get("device_type"),

        "process_unit":
            asset.get("process_unit"),

        "risk_level":
            risk_level,

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
    print("===== REFINERY FIRMWARE SUPPLY-CHAIN DECISION =====")

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
                f"Risk: {result['risk_level']} | "
                f"Deployment: "
                f"{result['deployment_allowed']} | "
                f"Recommendation: "
                f"{result['recommendation']}"
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
    print("===== DECISION EVALUATION COMPLETE =====")