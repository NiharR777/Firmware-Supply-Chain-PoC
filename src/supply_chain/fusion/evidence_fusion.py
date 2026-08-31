from pathlib import Path
import json

from ..decision_engine import evaluate_scenario


# ---------------------------------------------------------
# Project paths
# ---------------------------------------------------------

BASE_DIR = Path("data/synthetic/supply_chain_poc")

EVIDENCE_DIR = (
    BASE_DIR
    / "generated"
    / "evidence_bundles"
)


# ---------------------------------------------------------
# JSON loader
# ---------------------------------------------------------

def load_json(file_path: Path) -> dict:
    """
    Load a JSON evidence file.
    """

    if not file_path.exists():
        return {}

    with open(
        file_path,
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


# ---------------------------------------------------------
# Load evidence bundle
# ---------------------------------------------------------

def load_evidence_bundle(scenario_id: str) -> dict:
    """
    Load all available evidence associated with
    a refinery scenario.
    """

    bundle_dir = EVIDENCE_DIR / scenario_id

    if not bundle_dir.exists():
        raise FileNotFoundError(
            f"Evidence bundle not found: {bundle_dir}"
        )

    evidence = {
        "reference": load_json(
            bundle_dir / "reference_evidence.json"
        ),
        "hash": load_json(
            bundle_dir / "hash_evidence.json"
        ),

        "signature": load_json(
            bundle_dir / "signature_evidence.json"
        ),

        "sbom": load_json(
            bundle_dir / "sbom.json"
        ),

        "asset": load_json(
            bundle_dir / "asset_mapping.json"
        ),

        "rollback": load_json(
            bundle_dir / "rollback_evidence.json"
        ),

        "vendor": load_json(
            bundle_dir / "vendor_evidence.json"
        ),

        "freshness": load_json(
            bundle_dir / "freshness_evidence.json"
        ),
    }

    return evidence


# ---------------------------------------------------------
# Evidence fusion
# ---------------------------------------------------------

def fuse_evidence(
    scenario_id: str
) -> dict:
    """
    Combine evidence from the refinery evidence bundle
    with the decision engine result.
    """

    evidence = load_evidence_bundle(
        scenario_id
    )

    decision = evaluate_scenario(
        scenario_id
    )

    hash_evidence = evidence["hash"]
    signature_evidence = evidence["signature"]
    sbom_evidence = evidence["sbom"]
    asset_evidence = evidence["asset"]
    rollback_evidence = evidence["rollback"]
    freshness_evidence = evidence["freshness"]

    # -----------------------------------------------------
    # Evidence status
    # -----------------------------------------------------

    hash_status = (
        "passed"
        if hash_evidence.get("hash_match") is True
        else "failed"
    )

    signature_status = signature_evidence.get(
        "signature_status",
        "unknown"
    )

    trusted_root_status = signature_evidence.get(
        "trusted_root_status",
        "unknown"
    )

    sbom_status = sbom_evidence.get(
        "sbom_status",
        "unknown"
    )

    vulnerability_status = sbom_evidence.get(
        "vulnerability_status",
        "unknown"
    )

    vex_status = sbom_evidence.get(
        "vex_status",
        "unknown"
    )

    evidence_freshness = (
        "stale"
        if freshness_evidence.get("evidence_age_days", 0)
        > freshness_evidence.get("freshness_threshold_days", 30)
        else "current"
    )

    rollback_detected = "unauthorized_rollback" in decision.get(
        "risk_factors", []
    )

    rollback_authorized = rollback_evidence.get(
        "rollback_authorized",
        True
    )

    # -----------------------------------------------------
    # Build fused result
    # -----------------------------------------------------

    fused_result = {
        "scenario_id": scenario_id,

        "package_id": decision.get(
            "package_id"
        ),

        "asset_id": decision.get(
            "affected_asset"
        ),

        "device_type": decision.get(
            "device_type"
        ),

        "process_unit": decision.get(
            "process_unit"
        ),

        "hash_status": hash_status,

        "signature_status": signature_status,

        "trusted_root_status": trusted_root_status,

        "sbom_status": sbom_status,

        "vulnerability_status": vulnerability_status,

        "vex_status": vex_status,

        "evidence_freshness": evidence_freshness,

        "rollback_detected": rollback_detected,

        "rollback_authorized": rollback_authorized,

        "risk_score": decision.get(
            "risk_score",
            0
        ),

        "risk_level": decision.get(
            "risk_level",
            "unknown"
        ),

        "risk_factors": decision.get(
            "risk_factors",
            []
        ),

        "recommendation": decision.get(
            "recommendation",
            "N/A"
        ),

        "deployment_allowed": decision.get(
            "deployment_allowed",
            False
        ),

        "human_approval_required": decision.get(
            "human_approval_required",
            True
        ),

        "real_action_executed": decision.get(
            "real_action_executed",
            False
        ),

        "evidence_sources": [
            "reference_evidence.json",
            "hash_evidence.json",
            "signature_evidence.json",
            "sbom.json",
            "asset_mapping.json",
            "rollback_evidence.json",
            "vendor_evidence.json",
            "freshness_evidence.json",
        ],

        "data_provenance": "SYNTHETIC FUSED OBSERVED EVIDENCE",
    }

    return fused_result


# ---------------------------------------------------------
# Save fused evidence
# ---------------------------------------------------------

def save_fused_evidence(
    scenario_id: str
) -> dict:
    """
    Save the fused evidence result for a scenario.
    """

    result = fuse_evidence(
        scenario_id
    )

    output_dir = (
        BASE_DIR
        / "generated"
        / "reports"
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    output_file = (
        output_dir
        / f"{scenario_id}_fused_evidence.json"
    )

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:
        json.dump(
            result,
            file,
            indent=2
        )

    return result


# ---------------------------------------------------------
# Console display
# ---------------------------------------------------------

def print_fused_result(
    result: dict
) -> None:

    print()

    print(
        f"{result['scenario_id']} | "
        f"Package: {result['package_id']}"
    )

    print(
        f"  Asset ID: "
        f"{result.get('asset_id')}"
    )

    print(
        f"  Device Type: "
        f"{result.get('device_type')}"
    )

    print(
        f"  Process Unit: "
        f"{result.get('process_unit')}"
    )

    print(
        f"  Hash: "
        f"{result['hash_status']}"
    )

    print(
        f"  Signature: "
        f"{result['signature_status']}"
    )

    print(
        f"  Trusted Root: "
        f"{result['trusted_root_status']}"
    )

    print(
        f"  SBOM: "
        f"{result['sbom_status']}"
    )

    print(
        f"  Vulnerability Status: "
        f"{result['vulnerability_status']}"
    )

    print(
        f"  VEX Status: "
        f"{result['vex_status']}"
    )

    print(
        f"  Evidence Freshness: "
        f"{result['evidence_freshness']}"
    )

    print(
        f"  Rollback Detected: "
        f"{result['rollback_detected']}"
    )

    print(
        f"  Rollback Authorized: "
        f"{result['rollback_authorized']}"
    )

    print(
        f"  Risk: "
        f"{result['risk_level']} | "
        f"Score: {result['risk_score']}"
    )

    print(
        f"  Risk Factors: "
        f"{result['risk_factors']}"
    )

    print(
        f"  Recommendation: "
        f"{result['recommendation']}"
    )

    print(
        f"  Deployment Allowed: "
        f"{result['deployment_allowed']}"
    )

    print(
        f"  Human Approval Required: "
        f"{result['human_approval_required']}"
    )

    print(
        f"  Real Action Executed: "
        f"{result['real_action_executed']}"
    )


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

if __name__ == "__main__":

    print()

    print(
        "===== REFINERY EVIDENCE FUSION ====="
    )

    for number in range(1, 11):

        scenario_id = (
            f"SC-{number:03d}"
        )

        try:

            result = save_fused_evidence(
                scenario_id
            )

            print_fused_result(
                result
            )

        except Exception as error:

            print()

            print(
                f"{scenario_id} | ERROR: "
                f"{error}"
            )

    print()

    print(
        "===== EVIDENCE FUSION COMPLETE ====="
    )
