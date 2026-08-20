from pathlib import Path
import json
import pandas as pd


# ---------------------------------------------------------
# Project paths
# ---------------------------------------------------------

BASE_DIR = Path("data/synthetic/supply_chain_poc")

SCENARIO_FILE = BASE_DIR / "scenario_catalog.csv"

OUTPUT_DIR = (
    BASE_DIR
    / "generated"
    / "evidence_bundles"
)

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------
# Load scenario catalog
# ---------------------------------------------------------

scenarios = pd.read_csv(SCENARIO_FILE)


# ---------------------------------------------------------
# Refinery asset mapping
# ---------------------------------------------------------

ASSET_MAPPING = {
    "SC-001": {
        "asset_id": "CDU-PLC-001",
        "device_type": "PLC",
        "process_unit": "Crude Distillation Unit",
        "location": "Refinery CDU",
    },
    "SC-002": {
        "asset_id": "CDU-DCS-001",
        "device_type": "DCS Controller",
        "process_unit": "Crude Distillation Unit",
        "location": "Refinery CDU",
    },
    "SC-003": {
        "asset_id": "SIS-001",
        "device_type": "Safety Controller/SIS",
        "process_unit": "Reactor/Hydrocracker Unit",
        "location": "Refinery Safety System",
    },
    "SC-004": {
        "asset_id": "OPC-GW-001",
        "device_type": "Industrial OPC Gateway",
        "process_unit": "Pump or Compressor Area",
        "location": "Refinery OT Network",
    },
    "SC-005": {
        "asset_id": "CDU-PLC-001",
        "device_type": "PLC",
        "process_unit": "Crude Distillation Unit",
        "location": "Refinery CDU",
    },
    "SC-006": {
        "asset_id": "CDU-DCS-001",
        "device_type": "DCS Controller",
        "process_unit": "Crude Distillation Unit",
        "location": "Refinery CDU",
    },
    "SC-007": {
        "asset_id": "OPC-GW-001",
        "device_type": "Industrial OPC Gateway",
        "process_unit": "Pump or Compressor Area",
        "location": "Refinery OT Network",
    },
    "SC-008": {
        "asset_id": "TANK-RTU-001",
        "device_type": "Pipeline/Tank-Farm RTU",
        "process_unit": "Tank Farm",
        "location": "Refinery Tank Farm",
    },
    "SC-009": {
        "asset_id": "TANK-RTU-001",
        "device_type": "Pipeline/Tank-Farm RTU",
        "process_unit": "Tank Farm",
        "location": "Refinery Tank Farm",
    },
    "SC-010": {
        "asset_id": "TANK-RTU-001",
        "device_type": "Pipeline/Tank-Farm RTU",
        "process_unit": "Tank Farm",
        "location": "Refinery Tank Farm",
    },
}


# ---------------------------------------------------------
# Create evidence bundle
# ---------------------------------------------------------

def create_bundle(row):

    scenario_id = row["scenario_id"]
    scenario_type = row["scenario_type"]
    package_id = row["package_id"]

    bundle_dir = OUTPUT_DIR / scenario_id
    bundle_dir.mkdir(parents=True, exist_ok=True)

    asset = ASSET_MAPPING.get(
        scenario_id,
        {
            "asset_id": "UNKNOWN",
            "device_type": "UNKNOWN",
            "process_unit": "UNKNOWN",
            "location": "UNKNOWN",
        },
    )

    # -----------------------------------------------------
    # 1. package.json
    # -----------------------------------------------------

    package_data = {
        "scenario_id": scenario_id,
        "package_id": package_id,
        "product_id": row["product_id"],
        "vendor_id": row["vendor_id"],
        "scenario_type": scenario_type,
        "package_status": "SYNTHETIC",
        "data_provenance": "SYNTHETIC",
    }

    # -----------------------------------------------------
    # 2. hash_evidence.json
    # -----------------------------------------------------

    hash_match = scenario_type not in [
        "hash_mismatch"
    ]

    hash_evidence = {
        "scenario_id": scenario_id,
        "package_id": package_id,
        "hash_algorithm": "SHA-256",
        "trusted_vendor_hash": "SYNTHETIC_TRUSTED_HASH",
        "calculated_package_hash": (
            "SYNTHETIC_CALCULATED_HASH"
        ),
        "hash_match": hash_match,
        "integrity_status": (
            "PASSED"
            if hash_match
            else "FAILED"
        ),
        "data_provenance": "SYNTHETIC",
    }

    # -----------------------------------------------------
    # 3. signature_evidence.json
    # -----------------------------------------------------

    signature_valid = (
        scenario_type != "invalid_signature"
    )

    signature_evidence = {
        "scenario_id": scenario_id,
        "package_id": package_id,
        "signature_algorithm": "SYNTHETIC-SIGNATURE",
        "signature_status": (
            "valid"
            if signature_valid
            else "invalid"
        ),
        "trusted_root_status": (
            "trusted"
            if signature_valid
            else "untrusted"
        ),
        "human_verification_required": True,
        "data_provenance": "SYNTHETIC",
    }

    # -----------------------------------------------------
    # 4. sbom.json
    # -----------------------------------------------------

    if scenario_type == "missing_sbom":
        sbom_status = "incomplete"
    else:
        sbom_status = "complete"

    sbom = {
        "scenario_id": scenario_id,
        "package_id": package_id,
        "sbom_format": "SPDX",
        "sbom_status": sbom_status,
        "component_count": (
            0 if sbom_status == "incomplete" else 3
        ),
        "components": [
            {
                "component_id": "COMP-SYN-001",
                "name": "OpenSSL",
                "version": "3.0.12",
            },
            {
                "component_id": "COMP-SYN-002",
                "name": "cURL",
                "version": "8.4.0",
            },
            {
                "component_id": "COMP-SYN-003",
                "name": "zlib",
                "version": "1.3",
            },
        ]
        if sbom_status == "complete"
        else [],
        "data_provenance": "SYNTHETIC",
    }

    # -----------------------------------------------------
    # Scenario-specific SBOM changes
    # -----------------------------------------------------

    if scenario_type == "unexpected_component":
        sbom["unexpected_component"] = True
        sbom["component_change"] = "added"
        sbom["added_component"] = {
            "component_id": "COMP-006",
            "name": "Device Driver Pack",
            "version": "2.2.0",
        }

    # -----------------------------------------------------
    # 5. asset_mapping.json
    # -----------------------------------------------------

    asset_mapping = {
        "scenario_id": scenario_id,
        "package_id": package_id,
        "product_id": row["product_id"],
        "vendor_id": row["vendor_id"],
        "asset_id": asset["asset_id"],
        "device_type": asset["device_type"],
        "process_unit": asset["process_unit"],
        "location": asset["location"],
        "deployment_status": "NOT_EXECUTED",
        "data_provenance": "SYNTHETIC",
    }

    # -----------------------------------------------------
    # 6. Decision logic
    # -----------------------------------------------------

    decision = row["expected_decision"]

    recommendation = "investigate"

    if decision == "high_risk":
        recommendation = "quarantine_review"

    if scenario_type == "hash_mismatch":
        reason = (
            "Calculated firmware package hash does not "
            "match the trusted vendor hash."
        )

    elif scenario_type == "invalid_signature":
        reason = (
            "Firmware signature is invalid or not "
            "trusted by the configured trusted root."
        )

    elif scenario_type == "vulnerable_component":
        reason = (
            "Firmware contains a vulnerable component "
            "with applicable VEX status."
        )

    elif scenario_type == "rollback":
        reason = (
            "Firmware version indicates an unauthorized "
            "rollback to an older version."
        )

    elif scenario_type == "missing_sbom":
        reason = (
            "SBOM is missing or incomplete, preventing "
            "complete component verification."
        )

    elif scenario_type == "unexpected_component":
        reason = (
            "An unexpected component was detected in "
            "the firmware package."
        )

    elif scenario_type == "untrusted_vendor":
        reason = (
            "Firmware package is associated with an "
            "untrusted vendor."
        )

    elif scenario_type == "stale_evidence":
        reason = (
            "Security evidence is stale or component "
            "identity cannot be resolved."
        )

    else:
        reason = (
            "Scenario requires review according to "
            "synthetic ground truth."
        )

    # -----------------------------------------------------
    # Vulnerability / VEX information
    # -----------------------------------------------------

    vulnerability_info = {}

    if scenario_type == "vulnerable_component":
        vulnerability_info = {
            "vulnerable_component": True,
            "component_id": row["component_id"],
            "vulnerability_id": row["vulnerability_id"],
            "vex_status": "affected",
            "severity": "high",
        }

    # -----------------------------------------------------
    # Rollback information
    # -----------------------------------------------------

    rollback_info = {}

    if scenario_type == "rollback":
        rollback_info = {
            "version_status": "rollback_detected",
            "current_version": "4.0.1",
            "rollback_version": "3.9.8",
        }

    # -----------------------------------------------------
    # Decision evidence
    # -----------------------------------------------------

    decision_data = {
        "scenario_id": scenario_id,
        "package_id": package_id,
        "decision": decision,
        "integrity_failure": (
            scenario_type == "hash_mismatch"
        ),
        "recommendation": recommendation,
        "reason": reason,
        "affected_asset": asset["asset_id"],
        "device_type": asset["device_type"],
        "process_unit": asset["process_unit"],
        "human_approval_required": True,
        "deployment_allowed": False,
        "real_action_executed": False,
        "data_provenance": "SYNTHETIC GROUND TRUTH",
    }

    decision_data.update(vulnerability_info)
    decision_data.update(rollback_info)

    # -----------------------------------------------------
    # Write all files
    # -----------------------------------------------------

    files = {
        "package.json": package_data,
        "hash_evidence.json": hash_evidence,
        "signature_evidence.json": signature_evidence,
        "sbom.json": sbom,
        "asset_mapping.json": asset_mapping,
        "decision.json": decision_data,
    }

    for filename, data in files.items():

        output_file = bundle_dir / filename

        with open(
            output_file,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                data,
                file,
                indent=2,
            )

    return scenario_id


# ---------------------------------------------------------
# Generate bundles
# ---------------------------------------------------------

generated = []

for _, row in scenarios.iterrows():

    generated.append(
        create_bundle(row)
    )


# ---------------------------------------------------------
# Final output
# ---------------------------------------------------------

print(
    "Refinery evidence bundles generated successfully."
)

print(
    f"Bundles generated: {len(generated)}"
)

print(
    f"Output directory: {OUTPUT_DIR}"
)

print(
    "Each bundle contains:"
)

print(
    "package.json"
)

print(
    "hash_evidence.json"
)

print(
    "signature_evidence.json"
)

print(
    "sbom.json"
)

print(
    "asset_mapping.json"
)

print(
    "decision.json"
)