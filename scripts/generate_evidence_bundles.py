"""
Generate evidence-driven firmware supply-chain bundles.

Important design rules:
- scenario_type and expected_decision are NEVER written to evidence inputs.
- Ground truth is kept separately.
- Evidence is generated first.
- Decision artifacts are generated only after evidence exists.
- Hashes are calculated from real harmless synthetic package bytes.
- SBOM uses CycloneDX 1.5.
- All generated data is synthetic and advisory only.
"""

from __future__ import annotations

import csv
import hashlib
import json
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path


# ============================================================
# Configuration
# ============================================================

BASE_DIR = Path("data/synthetic/supply_chain_poc")

CATALOG_FILE = BASE_DIR / "scenario_catalog.csv"

GENERATED_DIR = BASE_DIR / "generated"
BUNDLE_DIR = GENERATED_DIR / "evidence_bundles"
SCENARIO_DIR = GENERATED_DIR / "scenarios"
GROUND_TRUTH_DIR = BASE_DIR / "ground_truth"

PACKAGE_DIR = BASE_DIR / "packages"
SBOM_DIR = BASE_DIR / "sbom"

FIXTURE_DIR = GENERATED_DIR / "fixtures"

GROUND_TRUTH_FILE = GROUND_TRUTH_DIR / "scenario_ground_truth.csv"
MANIFEST_FILE = GENERATED_DIR / "generation_manifest.json"


GENERATOR_VERSION = "2.0.0"
DEFAULT_SEED = 20260827


# ============================================================
# Utility functions
# ============================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)


def read_catalog() -> list[dict]:
    if not CATALOG_FILE.exists():
        raise FileNotFoundError(
            f"Canonical scenario catalog not found: {CATALOG_FILE}"
        )

    with CATALOG_FILE.open("r", encoding="utf-8-sig", newline="") as file:
        rows = list(csv.DictReader(file))

    required = {
        "scenario_id",
        "scenario_type",
        "description",
        "package_id",
        "product_id",
        "vendor_id",
        "component_id",
        "vulnerability_id",
        "expected_decision",
    }

    if not rows:
        raise ValueError("Scenario catalog is empty.")

    missing = required - set(rows[0].keys())

    if missing:
        raise ValueError(
            f"Scenario catalog missing columns: {sorted(missing)}"
        )

    ids = [row["scenario_id"] for row in rows]

    if any(not value for value in ids):
        raise ValueError("Scenario catalog contains an empty scenario_id.")

    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate scenario_id detected in scenario catalog.")

    return rows


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        writer.writeheader()
        writer.writerows(rows)


# ============================================================
# Canonical refinery asset mapping
# ============================================================

ASSETS = {
    "PKG-001": {
        "asset_id": "ASSET-001",
        "asset_name": "Crude Distillation Unit PLC",
        "device_type": "PLC",
        "process_unit": "Crude Distillation Unit",
        "location": "Refinery OT Network",
    },
    "PKG-002": {
        "asset_id": "ASSET-003",
        "asset_name": "Crude Distillation Unit DCS Controller",
        "device_type": "DCS Controller",
        "process_unit": "Crude Distillation Unit",
        "location": "Refinery OT Network",
    },
    "PKG-003": {
        "asset_id": "ASSET-004",
        "asset_name": "Safety Instrumented System Controller",
        "device_type": "SIS Controller",
        "process_unit": "Safety Instrumented System",
        "location": "Refinery OT Network",
    },
    "PKG-004": {
        "asset_id": "ASSET-005",
        "asset_name": "Industrial OPC Gateway",
        "device_type": "OPC Gateway",
        "process_unit": "Pump and Compressor Area",
        "location": "Refinery OT Network",
    },
    "PKG-005": {
        "asset_id": "ASSET-006",
        "asset_name": "Tank Farm RTU",
        "device_type": "RTU",
        "process_unit": "Tank Farm",
        "location": "Refinery OT Network",
    },
}


# ============================================================
# Package definitions
# ============================================================

PACKAGES = {
    "PKG-001": {
        "product_id": "PROD-001",
        "vendor_id": "VEND-001",
        "firmware_version": "2.4.1",
        "trusted_version": "2.4.1",
        "bytes": (
            b"SYNTHETIC REFINERY PLC FIRMWARE\n"
            b"PACKAGE PKG-001\n"
            b"VERSION 2.4.1\n"
            b"CLEAN BASELINE\n"
        ),
    },
    "PKG-002": {
        "product_id": "PROD-002",
        "vendor_id": "VEND-001",
        "firmware_version": "3.1.0",
        "trusted_version": "3.1.0",
        "bytes": (
            b"SYNTHETIC REFINERY DCS FIRMWARE\n"
            b"PACKAGE PKG-002\n"
            b"VERSION 3.1.0\n"
            b"CLEAN BASELINE\n"
        ),
    },
    "PKG-003": {
        "product_id": "PROD-003",
        "vendor_id": "VEND-002",
        "firmware_version": "1.8.2",
        "trusted_version": "1.8.2",
        "bytes": (
            b"SYNTHETIC REFINERY SIS FIRMWARE\n"
            b"PACKAGE PKG-003\n"
            b"VERSION 1.8.2\n"
            b"CLEAN BASELINE\n"
        ),
    },
    "PKG-004": {
        "product_id": "PROD-004",
        "vendor_id": "VEND-003",
        "firmware_version": "5.2.0",
        "trusted_version": "5.2.0",
        "bytes": (
            b"SYNTHETIC INDUSTRIAL OPC GATEWAY FIRMWARE\n"
            b"PACKAGE PKG-004\n"
            b"VERSION 5.2.0\n"
            b"CLEAN BASELINE\n"
        ),
    },
    "PKG-005": {
        "product_id": "PROD-005",
        "vendor_id": "VEND-002",
        "firmware_version": "4.0.1",
        "trusted_version": "4.0.1",
        "bytes": (
            b"SYNTHETIC TANK FARM RTU FIRMWARE\n"
            b"PACKAGE PKG-005\n"
            b"VERSION 4.0.1\n"
            b"CLEAN BASELINE\n"
        ),
    },
}


# ============================================================
# Scenario evidence rules
# ============================================================

def build_hash_evidence(
    scenario_id: str,
    package_id: str,
    scenario_type: str,
) -> dict:

    package = PACKAGES[package_id]

    clean_dir = FIXTURE_DIR / "clean"
    modified_dir = FIXTURE_DIR / "modified"

    clean_dir.mkdir(parents=True, exist_ok=True)
    modified_dir.mkdir(parents=True, exist_ok=True)

    clean_file = (
        clean_dir
        / f"{package_id}_{package['firmware_version']}_clean.bin"
    )

    clean_file.write_bytes(package["bytes"])

    expected_hash = sha256_file(clean_file)

    if scenario_type == "hash_mismatch":
        observed_file = (
            modified_dir
            / f"{scenario_id}_{package_id}_modified.bin"
        )

        modified_bytes = (
            package["bytes"]
            + b"\nSYNTHETIC_SAFE_TEST_MARKER:HASH_VARIANT_001\n"
        )

        observed_file.write_bytes(modified_bytes)

    else:
        observed_file = clean_file

    observed_hash = sha256_file(observed_file)

    return {
        "package_id": package_id,
        "hash_algorithm": "SHA-256",
        "expected_hash": expected_hash,
        "observed_hash": observed_hash,
        "hash_match": expected_hash == observed_hash,
        "expected_package_path": str(
            clean_file.as_posix()
        ),
        "observed_package_path": str(
            observed_file.as_posix()
        ),
        "expected_package_size_bytes": clean_file.stat().st_size,
        "observed_package_size_bytes": observed_file.stat().st_size,
        "calculation_timestamp": utc_now(),
        "integrity_status": (
            "PASSED"
            if expected_hash == observed_hash
            else "FAILED"
        ),
        "data_provenance": "SYNTHETIC OBSERVED EVIDENCE",
    }


def build_signature_evidence(
    package_id: str,
    scenario_type: str,
) -> dict:

    if scenario_type == "invalid_signature":
        signature_status = "invalid"
        trusted_root_status = "untrusted"
    else:
        signature_status = "valid"
        trusted_root_status = "trusted"

    # SC-008 is vendor substitution. The signature itself can
    # remain valid while the observed vendor differs.
    if scenario_type == "untrusted_vendor":
        signature_status = "valid"
        trusted_root_status = "trusted"

    return {
        "package_id": package_id,
        "signature_algorithm": "SYNTHETIC-SIGNATURE",
        "signature_status": signature_status,
        "trusted_root_status": trusted_root_status,
        "signature_verified": signature_status == "valid",
        "trusted_root_verified": trusted_root_status == "trusted",
        "data_provenance": "SYNTHETIC OBSERVED EVIDENCE",
    }


def build_sbom(
    scenario_id: str,
    package_id: str,
    scenario_type: str,
) -> dict:

    if scenario_type == "missing_sbom":
        return {
            "package_id": package_id,
            "sbom_present": False,
            "sbom_format": None,
            "sbom_path": None,
            "sbom_sha256": None,
            "sbom_status": "missing",
            "missing_reason": "SBOM artifact was not supplied",
            "data_provenance": "SYNTHETIC OBSERVED EVIDENCE",
        }

    base_components = [
        {
            "type": "library",
            "bom-ref": "pkg:generic/openssl@3.0.12",
            "name": "OpenSSL",
            "version": "3.0.12",
        },
        {
            "type": "library",
            "bom-ref": "pkg:generic/curl@8.4.0",
            "name": "cURL",
            "version": "8.4.0",
        },
        {
            "type": "library",
            "bom-ref": "pkg:generic/zlib@1.3",
            "name": "zlib",
            "version": "1.3",
        },
    ]

    components = list(base_components)

    if scenario_type == "unexpected_component":
        components.append(
            {
                "type": "library",
                "bom-ref": "pkg:generic/unknown-test-component@9.9.9",
                "name": "UnexpectedTestComponent",
                "version": "9.9.9",
            }
        )

    vulnerabilities = []

    if scenario_type == "vulnerable_component":
        vulnerabilities.append(
            {
                "id": "VULN-002",
                "source": {
                    "name": "Synthetic Vulnerability Database"
                },
                "ratings": [
                    {
                        "severity": "high"
                    }
                ],
                "affects": [
                    {
                        "ref": "pkg:generic/curl@8.4.0"
                    }
                ],
            }
        )

    baseline_sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": (
            "urn:uuid:"
            + str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    f"urai.example/firmware-sbom/{package_id}",
                )
            )
        ),
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": package_id,
                "version": PACKAGES[package_id]["firmware_version"],
            }
        },
        "components": base_components,
        "vulnerabilities": [],
    }

    sbom = dict(baseline_sbom)
    sbom["components"] = components
    sbom["vulnerabilities"] = vulnerabilities

    if scenario_type in {"unexpected_component", "vulnerable_component"}:
        sbom["serialNumber"] = "urn:uuid:" + str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"urai.example/firmware-sbom/{scenario_id}/{package_id}",
            )
        )

    source_file = (
        SBOM_DIR
        / f"{package_id}_sbom.json"
    )

    source_file.parent.mkdir(parents=True, exist_ok=True)

    # Scenario-modified SBOMs are distinct observed artifacts.
    # The canonical package SBOM always remains a clean baseline.
    if scenario_type in {"unexpected_component", "vulnerable_component"}:
        observed_file = (
            FIXTURE_DIR
            / "modified_sbom"
            / f"{scenario_id}_{package_id}_sbom.json"
        )
    else:
        observed_file = source_file

    observed_file.parent.mkdir(parents=True, exist_ok=True)

    write_json(source_file, baseline_sbom)

    if observed_file != source_file:
        write_json(observed_file, sbom)

    digest = sha256_file(observed_file)

    vulnerability_status = (
        "affected"
        if scenario_type == "vulnerable_component"
        else "not_affected"
    )

    return {
        "package_id": package_id,
        "sbom_present": True,
        "sbom_format": "CycloneDX",
        "spec_version": "1.5",
        "sbom_path": str(observed_file.as_posix()),
        "sbom_sha256": digest,
        "sbom_status": "complete",
        "component_count": len(components),
        "components": components,
        "vulnerability_status": vulnerability_status,
        "vulnerabilities": vulnerabilities,
        "unexpected_component_observed": (
            scenario_type == "unexpected_component"
        ),
        "data_provenance": "SYNTHETIC OBSERVED EVIDENCE",
    }


def build_rollback_evidence(
    package_id: str,
    scenario_type: str,
) -> dict:

    package = PACKAGES[package_id]

    if scenario_type in {"rollback"}:
        observed_version = "1.0.0"
        expected_version = package["trusted_version"]
        authorized = False
    else:
        observed_version = package["firmware_version"]
        expected_version = package["trusted_version"]
        authorized = True

    return {
        "package_id": package_id,
        "expected_version": expected_version,
        "observed_version": observed_version,
        "rollback_authorized": authorized,
        "version_comparison": (
            "older_than_expected"
            if observed_version != expected_version
            else "equal_to_expected"
        ),
        "data_provenance": "SYNTHETIC OBSERVED EVIDENCE",
    }


def build_vendor_evidence(
    package_id: str,
    scenario_type: str,
) -> dict:

    canonical_vendor = PACKAGES[package_id]["vendor_id"]

    if scenario_type == "untrusted_vendor":
        observed_vendor = "VEND-004"
    else:
        observed_vendor = canonical_vendor

    return {
        "package_id": package_id,
        "expected_vendor_id": canonical_vendor,
        "observed_vendor_id": observed_vendor,
        "vendor_match": canonical_vendor == observed_vendor,
        "vendor_trust_status": (
            "trusted"
            if canonical_vendor == observed_vendor
            else "untrusted"
        ),
        "data_provenance": "SYNTHETIC OBSERVED EVIDENCE",
    }


def build_freshness_evidence(
    package_id: str,
    scenario_type: str,
) -> dict:

    if scenario_type == "stale_evidence":
        age_days = 120
        status = "stale"
    else:
        age_days = 2
        status = "current"

    return {
        "package_id": package_id,
        "evidence_age_days": age_days,
        "freshness_status": status,
        "freshness_threshold_days": 30,
        "data_provenance": "SYNTHETIC OBSERVED EVIDENCE",
    }


def build_asset_mapping(package_id: str) -> dict:
    asset = ASSETS[package_id]

    return {
        "package_id": package_id,
        "product_id": PACKAGES[package_id]["product_id"],
        "vendor_id": PACKAGES[package_id]["vendor_id"],
        "asset_id": asset["asset_id"],
        "asset_name": asset["asset_name"],
        "device_type": asset["device_type"],
        "process_unit": asset["process_unit"],
        "location": asset["location"],
        "deployment_status": "NOT_EXECUTED",
        "data_provenance": "SYNTHETIC OBSERVED EVIDENCE",
    }


# ============================================================
# Ground truth
# ============================================================

def generate_ground_truth(catalog: list[dict]) -> None:
    rows = []

    for row in catalog:
        rows.append(
            {
                "scenario_id": row["scenario_id"],
                "scenario_type": row["scenario_type"],
                "expected_decision": row["expected_decision"],
            }
        )

    write_csv(
        GROUND_TRUTH_FILE,
        rows,
        [
            "scenario_id",
            "scenario_type",
            "expected_decision",
        ],
    )


# ============================================================
# Scenario manifests
# ============================================================

def generate_scenario_manifests(catalog: list[dict]) -> None:
    SCENARIO_DIR.mkdir(parents=True, exist_ok=True)

    for row in catalog:
        package_id = row["package_id"]

        scenario = {
            "scenario_id": row["scenario_id"],
            "package_id": package_id,
            "product_id": row["product_id"],
            "vendor_id": row["vendor_id"],
            "description": row["description"],
            "generator_version": GENERATOR_VERSION,
            "seed": DEFAULT_SEED,
            "data_provenance": "SYNTHETIC SCENARIO MANIFEST",
        }

        # Intentionally NO:
        # scenario_type
        # expected_decision

        write_json(
            SCENARIO_DIR
            / f"{row['scenario_id']}.json",
            scenario,
        )


# ============================================================
# Evidence bundles
# ============================================================

def generate_evidence_bundles(catalog: list[dict]) -> None:

    if BUNDLE_DIR.exists():
        shutil.rmtree(BUNDLE_DIR)

    BUNDLE_DIR.mkdir(parents=True, exist_ok=True)

    for row in catalog:

        scenario_id = row["scenario_id"]
        scenario_type = row["scenario_type"]
        package_id = row["package_id"]

        bundle_dir = BUNDLE_DIR / scenario_id
        bundle_dir.mkdir(parents=True, exist_ok=True)

        package = PACKAGES[package_id]

        package_data = {
            "package_id": package_id,
            "product_id": package["product_id"],
            "vendor_id": package["vendor_id"],
            "firmware_version": package["firmware_version"],
            "package_status": "SYNTHETIC",
            "data_provenance": "SYNTHETIC OBSERVED EVIDENCE",
        }

        hash_evidence = build_hash_evidence(
            scenario_id,
            package_id,
            scenario_type,
        )

        signature_evidence = build_signature_evidence(
            package_id,
            scenario_type,
        )

        sbom = build_sbom(
            scenario_id,
            package_id,
            scenario_type,
        )

        rollback = build_rollback_evidence(
            package_id,
            scenario_type,
        )

        vendor = build_vendor_evidence(
            package_id,
            scenario_type,
        )

        freshness = build_freshness_evidence(
            package_id,
            scenario_type,
        )

        asset = build_asset_mapping(package_id)

        # Trusted/approved reference facts are isolated from
        # runtime-observed evidence. The decision engine joins this
        # file by package_id; labels and scenario recipes are never
        # placed in the evidence bundle.
        reference_evidence = {
            "package_id": package_id,
            "trusted_sha256": hash_evidence.pop("expected_hash"),
            "trusted_package_path": hash_evidence.pop(
                "expected_package_path"
            ),
            "trusted_package_size_bytes": hash_evidence.pop(
                "expected_package_size_bytes"
            ),
            "approved_vendor_id": vendor.pop("expected_vendor_id"),
            "approved_version": rollback.pop("expected_version"),
            "data_provenance": "SYNTHETIC REFERENCE DATA",
        }

        write_json(
            bundle_dir / "package.json",
            package_data,
        )

        write_json(
            bundle_dir / "reference_evidence.json",
            reference_evidence,
        )

        write_json(
            bundle_dir / "hash_evidence.json",
            hash_evidence,
        )

        write_json(
            bundle_dir / "signature_evidence.json",
            signature_evidence,
        )

        write_json(
            bundle_dir / "sbom.json",
            sbom,
        )

        write_json(
            bundle_dir / "rollback_evidence.json",
            rollback,
        )

        write_json(
            bundle_dir / "vendor_evidence.json",
            vendor,
        )

        write_json(
            bundle_dir / "freshness_evidence.json",
            freshness,
        )

        write_json(
            bundle_dir / "asset_mapping.json",
            asset,
        )


# ============================================================
# Generation manifest
# ============================================================

def generate_manifest(catalog: list[dict]) -> None:

    manifest = {
        "generator_version": GENERATOR_VERSION,
        "seed": DEFAULT_SEED,
        "generated_timestamp": utc_now(),
        "scenario_count": len(catalog),
        "scenario_ids": [
            row["scenario_id"]
            for row in catalog
        ],
        "data_provenance": "SYNTHETIC",
        "safety_boundary": {
            "real_action_executed": False,
            "firmware_deployment_executed": False,
            "malware_created": False,
            "malware_executed": False,
        },
    }

    write_json(
        MANIFEST_FILE,
        manifest,
    )


# ============================================================
# Main
# ============================================================

def main() -> None:

    catalog = read_catalog()

    expected_ids = {
        f"SC-{number:03d}"
        for number in range(1, 11)
    }

    actual_ids = {
        row["scenario_id"]
        for row in catalog
    }

    if actual_ids != expected_ids:
        raise ValueError(
            "Canonical catalog must contain exactly SC-001 through SC-010."
        )

    generate_ground_truth(catalog)
    generate_scenario_manifests(catalog)
    generate_evidence_bundles(catalog)
    generate_manifest(catalog)

    print()
    print("===== REFINERY EVIDENCE GENERATION =====")
    print(f"Generator version : {GENERATOR_VERSION}")
    print(f"Seed              : {DEFAULT_SEED}")
    print(f"Scenarios         : {len(catalog)}")
    print(f"Evidence output   : {BUNDLE_DIR}")
    print(f"Ground truth      : {GROUND_TRUTH_FILE}")
    print(f"Manifest          : {MANIFEST_FILE}")
    print()
    print("Evidence generated successfully.")
    print("No real firmware deployment was performed.")
    print("No malware was created or executed.")
    print()


if __name__ == "__main__":
    main()
