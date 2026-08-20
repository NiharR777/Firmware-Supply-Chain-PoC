from pathlib import Path
import json

BASE_DIR = Path("data/synthetic/supply_chain_poc")
BUNDLE_DIR = BASE_DIR / "generated" / "evidence_bundles" / "SC-001"


def load_json(filename):
    file_path = BUNDLE_DIR / filename

    if not file_path.exists():
        raise FileNotFoundError(f"Missing file: {filename}")

    with open(file_path, "r", encoding="utf-8") as file:
        return json.load(file)


def verify_bundle():
    print("Verifying SC-001 evidence bundle...\n")

    package = load_json("package.json")
    hash_evidence = load_json("hash_evidence.json")
    signature = load_json("signature_evidence.json")
    sbom = load_json("sbom.json")
    asset = load_json("asset_mapping.json")
    decision = load_json("decision.json")

    checks = []

    # 1. Package
    checks.append(
        package["package_id"] == "PKG-001"
    )

    # 2. Hash integrity
    checks.append(
        hash_evidence["hash_match"] is False
        and hash_evidence["integrity_status"] == "FAILED"
    )

    # 3. Signature
    checks.append(
        signature["signature_status"] == "valid"
    )

    # 4. SBOM
    checks.append(
        sbom["sbom_status"] == "complete"
    )

    # 5. Asset mapping
    checks.append(
        asset["asset_id"] == "CDU-PLC-001"
        and asset["device_type"] == "PLC"
        and asset["process_unit"] == "Crude Distillation Unit"
    )

    # 6. Decision
    checks.append(
        decision["decision"] == "high_risk"
        and decision["recommendation"] == "quarantine_review"
    )

    # 7. Safety
    checks.append(
        decision["human_approval_required"] is True
        and decision["deployment_allowed"] is False
        and decision["real_action_executed"] is False
    )

    if all(checks):
        print("SC-001 verification PASSED")
        print("Integrity failure detected.")
        print("High-risk decision confirmed.")
        print("Quarantine review recommended.")
        print("Human approval required.")
        print("No real action executed.")
    else:
        print("SC-001 verification FAILED")
        print("Check the evidence bundle files.")


if __name__ == "__main__":
    verify_bundle()