from pathlib import Path
import sys
import json


# ---------------------------------------------------------
# Make supply_chain directory available for imports
# ---------------------------------------------------------

CURRENT_DIR = Path(__file__).resolve().parent
SUPPLY_CHAIN_DIR = CURRENT_DIR.parent

if str(SUPPLY_CHAIN_DIR) not in sys.path:
    sys.path.insert(0, str(SUPPLY_CHAIN_DIR))


from decision_engine import evaluate_scenario


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
    with open(
        file_path,
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


# ---------------------------------------------------------
# Evidence Fusion
# ---------------------------------------------------------

def fuse_evidence(scenario_id):

    bundle_dir = EVIDENCE_DIR / scenario_id

    if not bundle_dir.exists():
        raise ValueError(
            f"Evidence bundle {scenario_id} not found."
        )

    # -----------------------------------------------------
    # Load evidence sources
    # -----------------------------------------------------

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
    # Get risk decision from decision engine
    # -----------------------------------------------------

    decision = evaluate_scenario(
        scenario_id
    )

    # -----------------------------------------------------
    # Extract evidence states
    # -----------------------------------------------------

    hash_status = (
        "PASS"
        if hash_evidence.get("hash_match") is True
        else "FAIL"
    )

    signature_status = signature.get(
        "signature_status",
        "unknown"
    )

    trusted_root_status = signature.get(
        "trusted_root_status",
        "unknown"
    )

    vendor_trust = (
        signature.get("vendor_trust")
        or package.get("vendor_trust")
        or "unknown"
    )

    sbom_status = sbom.get(
        "sbom_status",
        "unknown"
    )

    vulnerability_status = sbom.get(
        "vulnerability_status",
        "unknown"
    )

    vex_status = sbom.get(
        "vex_status",
        "unknown"
    )

    evidence_freshness = sbom.get(
        "evidence_freshness",
        "unknown"
    )

    unexpected_component = sbom.get(
        "unexpected_component",
        False
    )

    # -----------------------------------------------------
    # Identify evidence failures
    # -----------------------------------------------------

    evidence_failures = []

    if hash_status == "FAIL":
        evidence_failures.append(
            "hash_integrity"
        )

    if signature_status in (
        "invalid",
        "untrusted"
    ):
        evidence_failures.append(
            "signature"
        )

    if trusted_root_status in (
        "invalid",
        "untrusted"
    ):
        evidence_failures.append(
            "trusted_root"
        )

    if vendor_trust == "untrusted":
        evidence_failures.append(
            "vendor_trust"
        )

    if sbom_status in (
        "missing",
        "incomplete"
    ):
        evidence_failures.append(
            "sbom"
        )

    if vulnerability_status == "affected":
        evidence_failures.append(
            "vulnerability"
        )

    if vex_status == "affected":
        evidence_failures.append(
            "vex"
        )

    if unexpected_component is True:
        evidence_failures.append(
            "unexpected_component"
        )

    if evidence_freshness == "stale":
        evidence_failures.append(
            "evidence_freshness"
        )

    # -----------------------------------------------------
    # Determine overall evidence state
    # -----------------------------------------------------

    if not evidence_failures:
        overall_status = "PASS"
    else:
        overall_status = "REVIEW_REQUIRED"

    # -----------------------------------------------------
    # Create unified evidence object
    # -----------------------------------------------------

    fused_evidence = {

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

        # -------------------------------------------------
        # Integrity
        # -------------------------------------------------

        "hash_integrity":
            hash_status,

        # -------------------------------------------------
        # Cryptographic assurance
        # -------------------------------------------------

        "signature_status":
            signature_status,

        "trusted_root_status":
            trusted_root_status,

        # -------------------------------------------------
        # Vendor trust
        # -------------------------------------------------

        "vendor_trust":
            vendor_trust,

        # -------------------------------------------------
        # Software composition
        # -------------------------------------------------

        "sbom_status":
            sbom_status,

        "vulnerability_status":
            vulnerability_status,

        "vex_status":
            vex_status,

        "unexpected_component":
            unexpected_component,

        "evidence_freshness":
            evidence_freshness,

        # -------------------------------------------------
        # Unified evidence result
        # -------------------------------------------------

        "overall_evidence_status":
            overall_status,

        "evidence_failures":
            evidence_failures,

        # -------------------------------------------------
        # Risk decision
        # -------------------------------------------------

        "risk_score":
            decision.get("risk_score"),

        "risk_level":
            decision.get("risk_level"),

        "recommendation":
            decision.get("recommendation"),

        "deployment_allowed":
            decision.get(
                "deployment_allowed",
                False
            ),

        "human_approval_required":
            decision.get(
                "human_approval_required",
                True
            ),

        "real_action_executed":
            decision.get(
                "real_action_executed",
                False
            ),

        # -------------------------------------------------
        # Data provenance
        # -------------------------------------------------

        "data_provenance":
            "SYNTHETIC GROUND TRUTH"
    }

    return fused_evidence


# ---------------------------------------------------------
# Test all refinery scenarios
# ---------------------------------------------------------

if __name__ == "__main__":

    print()
    print(
        "===== REFINERY EVIDENCE FUSION ====="
    )

    for number in range(1, 11):

        scenario_id = f"SC-{number:03d}"

        try:

            result = fuse_evidence(
                scenario_id
            )

            print()

            print(
                f"{scenario_id} | "
                f"Package: {result['package_id']} | "
                f"Asset: {result['asset_id']}"
            )

            print(
                f"  Device: "
                f"{result['device_type']}"
            )

            print(
                f"  Process Unit: "
                f"{result['process_unit']}"
            )

            print(
                f"  Hash Integrity: "
                f"{result['hash_integrity']}"
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
                f"  Vendor Trust: "
                f"{result['vendor_trust']}"
            )

            print(
                f"  SBOM: "
                f"{result['sbom_status']}"
            )

            print(
                f"  Vulnerability: "
                f"{result['vulnerability_status']}"
            )

            print(
                f"  VEX: "
                f"{result['vex_status']}"
            )

            print(
                f"  Unexpected Component: "
                f"{result['unexpected_component']}"
            )

            print(
                f"  Evidence Freshness: "
                f"{result['evidence_freshness']}"
            )

            print(
                f"  Overall Evidence: "
                f"{result['overall_evidence_status']}"
            )

            print(
                f"  Risk: "
                f"{result['risk_level']} "
                f"({result['risk_score']})"
            )

            print(
                f"  Recommendation: "
                f"{result['recommendation']}"
            )

            if result["evidence_failures"]:

                print(
                    f"  Evidence Failures: "
                    f"{', '.join(result['evidence_failures'])}"
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

        except Exception as error:

            print()

            print(
                f"{scenario_id} | ERROR: {error}"
            )

    print()

    print(
        "===== EVIDENCE FUSION COMPLETE ====="
    )