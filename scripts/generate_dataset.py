"""
Synthetic Firmware Supply-Chain ML Dataset Generator

Generates a leakage-safe synthetic dataset for the refinery/petrochemical
firmware supply-chain PoC.

Outputs:
    data/synthetic/supply_chain_poc/dataset/
        reference_data.csv
        observable_features.csv
        ground_truth_labels.csv
        scenario_manifests.csv
        generation_parameters.json
        split_assignments.csv

No real firmware, malware, or operational deployment is involved.
"""

from __future__ import annotations

import csv
import hashlib
import json
import random
import uuid
from pathlib import Path
from datetime import datetime, timezone


# ---------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------

ROOT = Path(__file__).resolve().parents[1]

OUTPUT_DIR = (
    ROOT
    / "data"
    / "synthetic"
    / "supply_chain_poc"
    / "dataset"
)

NUM_RECORDS = 5000
SEED = 20260828
GENERATOR_VERSION = "1.0.0"

RUN_ID = f"RUN-{SEED}-{uuid.uuid5(uuid.NAMESPACE_DNS, str(SEED)).hex[:8]}"

random.seed(SEED)


# ---------------------------------------------------------------------
# REFERENCE DATA
# ---------------------------------------------------------------------

VENDORS = [
    ("VEND-001", "Industrial Controls Vendor A", True),
    ("VEND-002", "Safety Systems Vendor B", True),
    ("VEND-003", "Industrial Gateway Vendor C", True),
    ("VEND-004", "Unknown / Untrusted Vendor", False),
]

PRODUCTS = [
    ("PROD-001", "PLC Controller", "Crude Distillation Unit"),
    ("PROD-002", "DCS Controller", "Crude Distillation Unit"),
    ("PROD-003", "SIS Safety Controller", "Safety Instrumented System"),
    ("PROD-004", "Industrial OPC Gateway", "Pump or Compressor Area"),
    ("PROD-005", "RTU Controller", "Tank Farm"),
]

ASSETS = [
    ("ASSET-PLC-001", "PLC", "Crude Distillation Unit"),
    ("ASSET-DCS-001", "DCS", "Crude Distillation Unit"),
    ("ASSET-SIS-001", "SIS Controller", "Safety Instrumented System"),
    ("ASSET-OPC-001", "Industrial OPC Gateway", "Pump or Compressor Area"),
    ("ASSET-RTU-001", "RTU", "Tank Farm"),
]

COMPONENTS = [
    ("COMP-001", "OpenSSL", "3.0.12"),
    ("COMP-002", "cURL", "8.4.0"),
    ("COMP-003", "zlib", "1.3"),
    ("COMP-004", "BusyBox", "1.36.1"),
    ("COMP-005", "libxml2", "2.11.5"),
    ("COMP-006", "Unexpected Utility", "2.0.0"),
    ("COMP-007", "SQLite", "3.43.1"),
    ("COMP-008", "OpenSSH", "9.5"),
]

SCENARIO_TYPES = [
    "valid",
    "benign_exception",
    "vulnerable_component",
    "hash_mismatch",
    "invalid_signature",
    "missing_sbom",
    "unexpected_component",
    "untrusted_vendor",
    "rollback",
    "stale_evidence",
]

DECISIONS = {
    "valid": "normal",
    "benign_exception": "normal",
    "vulnerable_component": "investigate",
    "hash_mismatch": "high_risk",
    "invalid_signature": "high_risk",
    "missing_sbom": "investigate",
    "unexpected_component": "investigate",
    "untrusted_vendor": "high_risk",
    "rollback": "investigate",
    "stale_evidence": "investigate",
}


# ---------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------

def stable_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def choose_weighted_scenario(rng: random.Random) -> str:
    """
    Distribution intentionally contains all three target classes.
    """

    scenario = rng.choices(
        population=SCENARIO_TYPES,
        weights=[
            28,  # valid
            8,   # benign exception
            10,  # vulnerable component
            12,  # hash mismatch
            8,   # invalid signature
            8,   # missing SBOM
            7,   # unexpected component
            7,   # untrusted vendor
            6,   # rollback
            6,   # stale evidence
        ],
        k=1,
    )[0]

    return scenario


def build_record(record_number: int, rng: random.Random) -> dict:
    scenario_type = choose_weighted_scenario(rng)

    package_number = record_number

    package_id = f"PKG-{package_number:05d}"
    product_id, product_name, process_unit = rng.choice(PRODUCTS)
    asset_id, device_type, asset_process = rng.choice(ASSETS)

    # Keep product/process reasonably aligned.
    process_unit = asset_process

    expected_vendor_id, _, vendor_is_trusted = rng.choice(VENDORS)

    observed_vendor_id = expected_vendor_id

    # ---------------------------------------------------------------
    # Observable evidence
    # ---------------------------------------------------------------

    expected_hash = stable_hash(
        f"{package_id}|clean|{SEED}"
    )

    observed_hash = expected_hash

    signature_valid = True
    trusted_root_valid = True

    sbom_present = True
    sbom_complete = True

    expected_version = f"{rng.randint(1, 4)}.{rng.randint(0, 9)}.{rng.randint(0, 9)}"
    observed_version = expected_version

    rollback_authorized = True

    vulnerability_present = False
    vulnerability_applicable = False

    unexpected_component = False

    evidence_age_days = rng.randint(0, 30)

    # ---------------------------------------------------------------
    # Apply observable conditions according to scenario
    # ---------------------------------------------------------------

    if scenario_type == "hash_mismatch":
        manipulated_marker = f"{package_id}|manipulated|{SEED}"
        observed_hash = stable_hash(manipulated_marker)

    elif scenario_type == "invalid_signature":
        signature_valid = False
        trusted_root_valid = False

    elif scenario_type == "vulnerable_component":
        vulnerability_present = True
        vulnerability_applicable = True

    elif scenario_type == "missing_sbom":
        sbom_present = False
        sbom_complete = False

    elif scenario_type == "unexpected_component":
        unexpected_component = True

    elif scenario_type == "untrusted_vendor":
        observed_vendor_id = "VEND-004"
        trusted_root_valid = False

    elif scenario_type == "rollback":
        major = rng.randint(1, 3)
        expected_version = f"{major + 1}.0.0"
        observed_version = f"{major}.0.0"
        rollback_authorized = False

    elif scenario_type == "stale_evidence":
        evidence_age_days = rng.randint(91, 365)

    elif scenario_type == "benign_exception":
        # Observable exception remains safe.
        rollback_authorized = True
        evidence_age_days = rng.randint(0, 30)

    # ---------------------------------------------------------------
    # Derived ground truth
    # ---------------------------------------------------------------

    expected_decision = DECISIONS[scenario_type]

    record_id = f"REC-{record_number:05d}"

    record_seed = SEED + record_number

    scenario_manifest_id = f"MANIFEST-{record_number:05d}"

    return {
        "record_id": record_id,
        "package_id": package_id,
        "product_id": product_id,
        "asset_id": asset_id,
        "expected_vendor_id": expected_vendor_id,
        "observed_vendor_id": observed_vendor_id,
        "device_type": device_type,
        "process_unit": process_unit,

        # Observable evidence
        "expected_hash": expected_hash,
        "observed_hash": observed_hash,
        "hash_match": expected_hash == observed_hash,
        "signature_valid": signature_valid,
        "trusted_root_valid": trusted_root_valid,
        "sbom_present": sbom_present,
        "sbom_complete": sbom_complete,
        "expected_version": expected_version,
        "observed_version": observed_version,
        "rollback_authorized": rollback_authorized,
        "vulnerability_present": vulnerability_present,
        "vulnerability_applicable": vulnerability_applicable,
        "unexpected_component": unexpected_component,
        "evidence_age_days": evidence_age_days,

        # Dataset metadata
        "record_seed": record_seed,
        "run_id": RUN_ID,

        # Ground truth kept separately later
        "scenario_type": scenario_type,
        "expected_decision": expected_decision,

        "scenario_manifest_id": scenario_manifest_id,

        "vendor_expected_trusted": vendor_is_trusted,
    }


# ---------------------------------------------------------------------
# CSV WRITER
# ---------------------------------------------------------------------

def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
            extrasaction="ignore",
        )

        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------
# MAIN GENERATOR
# ---------------------------------------------------------------------

def main() -> None:

    print()
    print("===== SYNTHETIC DATASET GENERATION =====")
    print(f"Generator version : {GENERATOR_VERSION}")
    print(f"Run ID            : {RUN_ID}")
    print(f"Seed              : {SEED}")
    print(f"Records           : {NUM_RECORDS}")
    print(f"Output directory   : {OUTPUT_DIR}")
    print()

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    rng = random.Random(SEED)

    records = [
        build_record(i, rng)
        for i in range(1, NUM_RECORDS + 1)
    ]

    # ---------------------------------------------------------------
    # 1. Observable features
    # ---------------------------------------------------------------

    observable_fields = [
        "record_id",
        "package_id",
        "product_id",
        "asset_id",
        "expected_vendor_id",
        "observed_vendor_id",
        "device_type",
        "process_unit",
        "expected_hash",
        "observed_hash",
        "hash_match",
        "signature_valid",
        "trusted_root_valid",
        "sbom_present",
        "sbom_complete",
        "expected_version",
        "observed_version",
        "rollback_authorized",
        "vulnerability_present",
        "vulnerability_applicable",
        "unexpected_component",
        "evidence_age_days",
        "record_seed",
        "run_id",
    ]

    observable_rows = [
        {
            key: record[key]
            for key in observable_fields
        }
        for record in records
    ]

    write_csv(
        OUTPUT_DIR / "observable_features.csv",
        observable_rows,
        observable_fields,
    )

    # ---------------------------------------------------------------
    # 2. Ground truth
    # ---------------------------------------------------------------

    ground_truth_fields = [
        "record_id",
        "scenario_type",
        "expected_decision",
    ]

    ground_truth_rows = [
        {
            "record_id": record["record_id"],
            "scenario_type": record["scenario_type"],
            "expected_decision": record["expected_decision"],
        }
        for record in records
    ]

    write_csv(
        OUTPUT_DIR / "ground_truth_labels.csv",
        ground_truth_rows,
        ground_truth_fields,
    )

    # ---------------------------------------------------------------
    # 3. Reference data
    # ---------------------------------------------------------------

    reference_rows = []

    for vendor_id, vendor_name, trusted in VENDORS:
        reference_rows.append(
            {
                "reference_type": "vendor",
                "reference_id": vendor_id,
                "name": vendor_name,
                "trusted": trusted,
            }
        )

    for product_id, product_name, process_unit in PRODUCTS:
        reference_rows.append(
            {
                "reference_type": "product",
                "reference_id": product_id,
                "name": product_name,
                "trusted": "",
                "process_unit": process_unit,
            }
        )

    for asset_id, device_type, process_unit in ASSETS:
        reference_rows.append(
            {
                "reference_type": "asset",
                "reference_id": asset_id,
                "name": device_type,
                "trusted": "",
                "process_unit": process_unit,
            }
        )

    for component_id, name, version in COMPONENTS:
        reference_rows.append(
            {
                "reference_type": "component",
                "reference_id": component_id,
                "name": name,
                "trusted": "",
                "version": version,
            }
        )

    reference_fields = [
        "reference_type",
        "reference_id",
        "name",
        "trusted",
        "process_unit",
        "version",
    ]

    write_csv(
        OUTPUT_DIR / "reference_data.csv",
        reference_rows,
        reference_fields,
    )

    # ---------------------------------------------------------------
    # 4. Scenario manifests
    # ---------------------------------------------------------------

    manifest_fields = [
        "scenario_manifest_id",
        "record_id",
        "package_id",
        "product_id",
        "asset_id",
        "generator_version",
        "record_seed",
        "run_id",
    ]

    manifest_rows = [
        {
            "scenario_manifest_id": record["scenario_manifest_id"],
            "record_id": record["record_id"],
            "package_id": record["package_id"],
            "product_id": record["product_id"],
            "asset_id": record["asset_id"],
            "generator_version": GENERATOR_VERSION,
            "record_seed": record["record_seed"],
            "run_id": RUN_ID,
        }
        for record in records
    ]

    write_csv(
        OUTPUT_DIR / "scenario_manifests.csv",
        manifest_rows,
        manifest_fields,
    )

    # ---------------------------------------------------------------
    # 5. Generation parameters
    # ---------------------------------------------------------------

    parameters = {
        "generator_name": "synthetic_firmware_supply_chain_dataset",
        "generator_version": GENERATOR_VERSION,
        "run_id": RUN_ID,
        "seed": SEED,
        "record_count": NUM_RECORDS,
        "generated_at_utc": datetime.now(
            timezone.utc
        ).isoformat(),

        "scenario_distribution": {
            scenario: sum(
                1
                for record in records
                if record["scenario_type"] == scenario
            )
            for scenario in SCENARIO_TYPES
        },

        "decision_distribution": {
            decision: sum(
                1
                for record in records
                if record["expected_decision"] == decision
            )
            for decision in sorted(set(DECISIONS.values()))
        },

        "safety_statement": (
            "Synthetic data only. No real firmware was deployed, "
            "modified, executed, or transmitted."
        ),
    }

    with (
        OUTPUT_DIR / "generation_parameters.json"
    ).open(
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            parameters,
            file,
            indent=2,
        )

    # ---------------------------------------------------------------
    # 6. Deterministic split assignments
    # ---------------------------------------------------------------

    # Split at package lineage level.
    # Since every package is unique in this synthetic dataset,
    # package_id itself acts as the grouping key.

    split_rng = random.Random(SEED + 999)

    package_ids = [
        record["package_id"]
        for record in records
    ]

    split_rng.shuffle(package_ids)

    total = len(package_ids)

    train_end = int(total * 0.70)
    validation_end = int(total * 0.85)

    split_map = {}

    for package_id in package_ids[:train_end]:
        split_map[package_id] = "train"

    for package_id in package_ids[
        train_end:validation_end
    ]:
        split_map[package_id] = "validation"

    for package_id in package_ids[
        validation_end:
    ]:
        split_map[package_id] = "test"

    split_fields = [
        "record_id",
        "package_id",
        "split",
        "group_id",
        "run_id",
    ]

    split_rows = [
        {
            "record_id": record["record_id"],
            "package_id": record["package_id"],
            "split": split_map[record["package_id"]],
            "group_id": record["package_id"],
            "run_id": RUN_ID,
        }
        for record in records
    ]

    write_csv(
        OUTPUT_DIR / "split_assignments.csv",
        split_rows,
        split_fields,
    )

    # ---------------------------------------------------------------
    # Summary
    # ---------------------------------------------------------------

    print("Dataset generated successfully.")
    print()

    print("Files created:")
    for filename in [
        "reference_data.csv",
        "observable_features.csv",
        "ground_truth_labels.csv",
        "scenario_manifests.csv",
        "generation_parameters.json",
        "split_assignments.csv",
    ]:
        print(f"  [OK] {filename}")

    print()
    print("Record count:", len(records))

    print()
    print("Decision distribution:")

    for decision in [
        "normal",
        "investigate",
        "high_risk",
    ]:
        count = sum(
            1
            for record in records
            if record["expected_decision"] == decision
        )

        print(
            f"  {decision:12s}: {count}"
        )

    print()
    print("Split distribution:")

    for split in [
        "train",
        "validation",
        "test",
    ]:
        count = sum(
            1
            for row in split_rows
            if row["split"] == split
        )

        print(
            f"  {split:12s}: {count}"
        )

    print()
    print("Ground truth is separated from observable features.")
    print("No real firmware deployment was performed.")
    print("No malware was created or executed.")
    print()
    print("===== DATASET GENERATION COMPLETE =====")


if __name__ == "__main__":
    main()