from pathlib import Path
import json
import hashlib
import pandas as pd


# ---------------------------------------------------------
# Project paths
# ---------------------------------------------------------

BASE_DIR = Path("data/synthetic/supply_chain_poc")

SCENARIO_FILE = BASE_DIR / "scenario_catalog.csv"

PACKAGE_MANIFEST = (
    BASE_DIR / "generated" / "generated_package_manifest.csv"
)

PACKAGE_FILE = (
    BASE_DIR / "schemas" / "packages.csv"
)

OUTPUT_DIR = (
    BASE_DIR / "generated" / "scenarios"
)

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------
# Load existing data
# ---------------------------------------------------------

scenarios = pd.read_csv(SCENARIO_FILE)
manifest = pd.read_csv(PACKAGE_MANIFEST)
packages = pd.read_csv(PACKAGE_FILE)


# ---------------------------------------------------------
# Helper functions
# ---------------------------------------------------------

def get_package(package_id):
    """Get package information from generated manifest."""

    matches = manifest[
        manifest["package_id"] == package_id
    ]

    if matches.empty:
        raise ValueError(
            f"Package {package_id} was not found in manifest."
        )

    return matches.iloc[0]


def get_package_details(package_id):
    """Get package metadata from packages.csv."""

    matches = packages[
        packages["package_id"] == package_id
    ]

    if matches.empty:
        raise ValueError(
            f"Package {package_id} was not found in packages.csv."
        )

    return matches.iloc[0]


def calculate_sha256(file_path):
    """Calculate SHA-256 hash of a package file."""

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        while True:

            chunk = file.read(8192)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


# ---------------------------------------------------------
# Create scenario
# ---------------------------------------------------------

def create_scenario(row):

    package = get_package(row["package_id"])

    package_details = get_package_details(
        row["package_id"]
    )

    package_file = Path(package["package_file"])

    actual_hash = calculate_sha256(package_file)

    scenario_type = row["scenario_type"]

    package_id = row["package_id"]


    # -----------------------------------------------------
    # Default evidence
    # -----------------------------------------------------

    evidence = {

        "hash_status": "valid",

        "expected_hash": package["sha256"],

        "calculated_hash": actual_hash,

        "signature_status": "valid",

        "trusted_root_status": "trusted",

        "sbom_status": "complete",

        "vendor_trust": "trusted",

        "evidence_freshness": "current",

        "recommendation": "normal"

    }


    # -----------------------------------------------------
    # SC-001
    # Tampered PLC firmware
    # Crude Distillation Unit
    # -----------------------------------------------------

    if row["scenario_id"] == "SC-001":

        evidence["hash_status"] = "mismatch"

        evidence["expected_hash"] = package["sha256"]

        evidence["calculated_hash"] = actual_hash

        evidence["tampered_hash"] = "0" * 64

        evidence["signature_status"] = "valid"

        evidence["trusted_root_status"] = "trusted"

        evidence["sbom_status"] = "complete"

        evidence["vendor_trust"] = "trusted"

        evidence["affected_asset"] = "CDU-PLC-001"

        evidence["device_type"] = "PLC"

        evidence["process_unit"] = "Crude Distillation Unit"

        evidence["integrity_failure"] = True

        evidence["recommendation"] = "quarantine_review"

        evidence["human_approval_required"] = True

        evidence["real_action_executed"] = False


    # -----------------------------------------------------
    # Hash mismatch
    # -----------------------------------------------------

    elif scenario_type == "hash_mismatch":

        evidence["hash_status"] = "mismatch"

        evidence["expected_hash"] = package["sha256"]

        evidence["calculated_hash"] = actual_hash

        evidence["tampered_hash"] = "0" * 64

        evidence["integrity_failure"] = True

        evidence["recommendation"] = "high_risk"

        evidence["human_approval_required"] = True


    # -----------------------------------------------------
    # Invalid signature
    # -----------------------------------------------------

    elif scenario_type == "invalid_signature":

        evidence["signature_status"] = "invalid"

        evidence["trusted_root_status"] = "untrusted"

        evidence["attestation_status"] = "invalid"

        evidence["recommendation"] = "high_risk"

        evidence["human_approval_required"] = True


    # -----------------------------------------------------
    # Vulnerable component
    # -----------------------------------------------------

    elif scenario_type == "vulnerable_component":

        evidence["vulnerable_component"] = True

        evidence["vulnerability_severity"] = "high"

        evidence["vex_status"] = "affected"

        evidence["component_id"] = row["component_id"]

        evidence["vulnerability_id"] = row["vulnerability_id"]

        evidence["recommendation"] = "investigate"

        evidence["human_approval_required"] = True


    # -----------------------------------------------------
    # Missing SBOM
    # -----------------------------------------------------

    elif scenario_type == "missing_sbom":

        evidence["sbom_status"] = "missing"

        evidence["component_visibility"] = "unknown"

        evidence["recommendation"] = "investigate"

        evidence["human_approval_required"] = True


    # -----------------------------------------------------
    # Unexpected component
    # -----------------------------------------------------

    elif scenario_type == "unexpected_component":

        evidence["unexpected_component"] = True

        evidence["component_change"] = "added"

        evidence["component_id"] = row["component_id"]

        evidence["recommendation"] = "investigate"

        evidence["human_approval_required"] = True


    # -----------------------------------------------------
    # Untrusted vendor
    # -----------------------------------------------------

    elif scenario_type == "untrusted_vendor":

        evidence["vendor_trust"] = "untrusted"

        evidence["provenance_status"] = "incomplete"

        evidence["recommendation"] = "high_risk"

        evidence["human_approval_required"] = True


    # -----------------------------------------------------
    # Unauthorized rollback
    # -----------------------------------------------------

    elif scenario_type == "rollback":

        evidence["version_status"] = "rollback_detected"

        evidence["current_version"] = (
            package_details["current_version"]
        )

        evidence["previous_version"] = (
            package_details["previous_version"]
        )

        evidence["expected_version"] = (
            package_details["current_version"]
        )

        evidence["rollback_version"] = (
            package_details["previous_version"]
        )

        evidence["recommendation"] = "high_risk"

        evidence["human_approval_required"] = True


    # -----------------------------------------------------
    # Stale evidence
    # -----------------------------------------------------

    elif scenario_type == "stale_evidence":

        evidence["evidence_freshness"] = "stale"

        evidence["component_identity"] = "unresolved"

        evidence["component_id"] = row["component_id"]

        evidence["recommendation"] = "investigate"

        evidence["human_approval_required"] = True


    # -----------------------------------------------------
    # Final scenario object
    # -----------------------------------------------------

    scenario = {

        "scenario_id": row["scenario_id"],

        "scenario_type": scenario_type,

        "package_id": package_id,

        "product_id": row["product_id"],

        "vendor_id": row["vendor_id"],

        "evidence": evidence,

        "expected_decision": row["expected_decision"],

        "data_provenance": "SYNTHETIC GROUND TRUTH",

        "real_action_executed": False,

        "human_approval_required": True

    }


    # -----------------------------------------------------
    # Save scenario JSON
    # -----------------------------------------------------

    output_file = (
        OUTPUT_DIR / f"{row['scenario_id']}.json"
    )

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            scenario,
            file,
            indent=2
        )


    return scenario


# ---------------------------------------------------------
# Generate all scenarios
# ---------------------------------------------------------

generated = []

for _, row in scenarios.iterrows():

    generated.append(
        create_scenario(row)
    )


# ---------------------------------------------------------
# Create scenario summary
# ---------------------------------------------------------

summary = pd.DataFrame(

    [

        {
            "scenario_id":
                scenario["scenario_id"],

            "scenario_type":
                scenario["scenario_type"],

            "expected_decision":
                scenario["expected_decision"]

        }

        for scenario in generated

    ]

)


summary_file = (
    OUTPUT_DIR / "scenario_summary.csv"
)


summary.to_csv(
    summary_file,
    index=False
)


# ---------------------------------------------------------
# Final output
# ---------------------------------------------------------

print(
    "Refinery scenario evidence generated successfully."
)

print(
    f"Scenarios generated: {len(generated)}"
)

print(
    f"Output directory: {OUTPUT_DIR}"
)

print(
    f"Summary file: {summary_file}"
)