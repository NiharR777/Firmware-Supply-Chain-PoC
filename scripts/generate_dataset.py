"""Reproducible synthetic firmware supply-chain assessment generator.

Creates 5,000 assessments across 500 package lineages. Approved reference
facts, observations, generation recipes, labels, and splits are isolated.
"""

from __future__ import annotations

import csv
import hashlib
import json
import random
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "data" / "synthetic" / "supply_chain_poc" / "dataset"
NUM_RECORDS = 5000
NUM_LINEAGES = 500
RECORDS_PER_LINEAGE = 10
SEED = 20260828
GENERATOR_VERSION = "2.0.0"
RUN_ID = f"RUN-{SEED}-{uuid.uuid5(uuid.NAMESPACE_DNS, str(SEED)).hex[:8]}"
GENERATED_AT_UTC = "2026-08-28T00:00:00+00:00"

VENDORS = [
    ("VEND-001", "Industrial Controls Vendor A", True),
    ("VEND-002", "Safety Systems Vendor B", True),
    ("VEND-003", "Industrial Gateway Vendor C", True),
    ("VEND-004", "Unknown / Untrusted Vendor", False),
]
TRUSTED_VENDOR_IDS = [v for v, _, trusted in VENDORS if trusted]
VENDOR_TRUST = {v: trusted for v, _, trusted in VENDORS}
PRODUCT_ASSETS = [
    ("PROD-001", "PLC Controller", "ASSET-PLC", "PLC", "Crude Distillation Unit"),
    ("PROD-002", "DCS Controller", "ASSET-DCS", "DCS", "Crude Distillation Unit"),
    ("PROD-003", "SIS Safety Controller", "ASSET-SIS", "SIS Controller", "Safety Instrumented System"),
    ("PROD-004", "Industrial OPC Gateway", "ASSET-OPC", "OPC Gateway", "Pump or Compressor Area"),
    ("PROD-005", "RTU Controller", "ASSET-RTU", "RTU", "Tank Farm"),
]
COMPONENTS = [
    ("COMP-001", "OpenSSL", "3.0.12"),
    ("COMP-002", "cURL", "8.4.0"),
    ("COMP-003", "zlib", "1.3"),
    ("COMP-004", "BusyBox", "1.36.1"),
    ("COMP-005", "libxml2", "2.11.5"),
    ("COMP-006", "Device Driver Pack", "2.2.0"),
    ("COMP-007", "SQLite", "3.43.1"),
    ("COMP-008", "OpenSSH", "9.5"),
]
SCENARIO_TYPES = [
    "valid", "benign_exception", "vulnerable_component", "hash_mismatch",
    "invalid_signature", "missing_sbom", "unexpected_component",
    "untrusted_vendor", "rollback", "stale_evidence",
]
RISK_WEIGHTS = {
    "hash_integrity_failure": 40,
    "signature_failure": 30,
    "trusted_root_failure": 20,
    "untrusted_vendor": 40,
    "unauthorized_rollback": 40,
    "vulnerable_component": 20,
    "unexpected_component": 20,
    "missing_sbom": 15,
    "stale_evidence": 10,
}


def stable_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def version_tuple(value: str) -> tuple[int, int, int]:
    return tuple(int(part) for part in value.split("."))


def score_evidence(observed: dict, reference: dict) -> tuple[int, str, list[str]]:
    factors: list[str] = []
    if observed["observed_hash"] != reference["trusted_hash"]:
        factors.append("hash_integrity_failure")
    if not observed["signature_valid"]:
        factors.append("signature_failure")
    if not observed["trusted_root_valid"]:
        factors.append("trusted_root_failure")
    if observed["observed_vendor_id"] != reference["approved_vendor_id"] or not VENDOR_TRUST[observed["observed_vendor_id"]]:
        factors.append("untrusted_vendor")
    if version_tuple(observed["observed_version"]) < version_tuple(reference["approved_version"]) and not observed["rollback_authorized"]:
        factors.append("unauthorized_rollback")
    if not observed["sbom_present"] or not observed["sbom_complete"]:
        factors.append("missing_sbom")
    if observed["vulnerability_present"] and observed["vulnerability_applicable"]:
        factors.append("vulnerable_component")
    if observed["unexpected_component"]:
        factors.append("unexpected_component")
    if observed["evidence_age_days"] > reference["freshness_threshold_days"]:
        factors.append("stale_evidence")
    score = min(100, sum(RISK_WEIGHTS[factor] for factor in factors))
    label = "high_risk" if score >= 40 else "investigate" if score > 0 else "normal"
    return score, label, factors


def build_lineage(lineage_number: int) -> dict:
    lineage_id = f"LINEAGE-{lineage_number:04d}"
    lineage_seed = SEED + lineage_number * 100_000
    rng = random.Random(lineage_seed)
    product_id, product_name, asset_prefix, device_type, process_unit = rng.choice(PRODUCT_ASSETS)
    return {
        "lineage_id": lineage_id,
        "lineage_seed": lineage_seed,
        "product_id": product_id,
        "product_name": product_name,
        "asset_id": f"{asset_prefix}-{lineage_number:04d}",
        "device_type": device_type,
        "process_unit": process_unit,
        "approved_vendor_id": rng.choice(TRUSTED_VENDOR_IDS),
        "approved_version": f"{rng.randint(2, 6)}.{rng.randint(0, 9)}.{rng.randint(0, 9)}",
        "base_component_count": rng.randint(8, 35),
    }


def scenario_for_record(record_number: int, lineage: dict) -> str:
    scenarios = list(SCENARIO_TYPES)
    random.Random(lineage["lineage_seed"] + 17).shuffle(scenarios)
    return scenarios[(record_number - 1) % RECORDS_PER_LINEAGE]


def regenerate_record(record_number: int, record_seed: int) -> dict:
    lineage_number = ((record_number - 1) // RECORDS_PER_LINEAGE) + 1
    lineage = build_lineage(lineage_number)
    rng = random.Random(record_seed)
    scenario_type = scenario_for_record(record_number, lineage)
    record_id = f"REC-{record_number:05d}"
    package_id = f"PKG-{lineage_number:04d}-{((record_number - 1) % 10) + 1:02d}"
    trusted_hash = stable_hash(f"{lineage['lineage_id']}|{package_id}|trusted|{lineage['approved_version']}|{SEED}")
    reference = {
        "record_id": record_id,
        "package_id": package_id,
        "lineage_id": lineage["lineage_id"],
        "approved_vendor_id": lineage["approved_vendor_id"],
        "trusted_hash": trusted_hash,
        "approved_version": lineage["approved_version"],
        "freshness_threshold_days": 30,
        "approved_component_count": lineage["base_component_count"],
        "reference_profile_version": "REF-2.0.0",
    }
    observed = {
        "record_id": record_id,
        "package_id": package_id,
        "lineage_id": lineage["lineage_id"],
        "product_id": lineage["product_id"],
        "asset_id": lineage["asset_id"],
        "observed_vendor_id": lineage["approved_vendor_id"],
        "observed_hash": trusted_hash,
        "signature_valid": True,
        "trusted_root_valid": True,
        "sbom_present": True,
        "sbom_complete": True,
        "observed_version": lineage["approved_version"],
        "rollback_authorized": True,
        "vulnerability_present": False,
        "vulnerability_applicable": False,
        "unexpected_component": False,
        "evidence_age_days": rng.randint(0, 30),
        "package_size_bytes": rng.randint(50_000, 5_000_000),
        "component_count": lineage["base_component_count"],
        "known_vulnerability_count": 0,
        "max_cvss_score": 0.0,
        "record_seed": record_seed,
        "run_id": RUN_ID,
    }
    injected: list[str] = []
    parameters: dict[str, object] = {"scenario_type": scenario_type}
    if scenario_type == "hash_mismatch":
        marker = f"SAFE-MANIPULATION-{record_seed}-{rng.randint(1000, 9999)}"
        observed["observed_hash"] = stable_hash(f"{trusted_hash}|{marker}")
        injected.append("hash_integrity_failure")
        parameters.update({"mutation": "append_safe_marker", "marker": marker})
    elif scenario_type == "invalid_signature":
        observed["signature_valid"] = False
        observed["trusted_root_valid"] = False
        injected.extend(["signature_failure", "trusted_root_failure"])
        parameters.update({"signature_status": "invalid", "trust_chain": "untrusted"})
    elif scenario_type == "vulnerable_component":
        observed["vulnerability_present"] = True
        observed["vulnerability_applicable"] = True
        observed["known_vulnerability_count"] = rng.randint(1, 4)
        observed["max_cvss_score"] = round(rng.uniform(4.0, 9.8), 1)
        injected.append("vulnerable_component")
        parameters.update({"vulnerability_applicable": True, "max_cvss_score": observed["max_cvss_score"]})
    elif scenario_type == "missing_sbom":
        observed["sbom_present"] = False
        observed["sbom_complete"] = False
        observed["component_count"] = 0
        injected.append("missing_sbom")
        parameters.update({"sbom_action": "omit", "missing_reason": "not_supplied"})
    elif scenario_type == "unexpected_component":
        added = rng.randint(1, 3)
        observed["unexpected_component"] = True
        observed["component_count"] += added
        injected.append("unexpected_component")
        parameters.update({"component_action": "add", "added_component_count": added})
    elif scenario_type == "untrusted_vendor":
        observed["observed_vendor_id"] = "VEND-004"
        injected.append("untrusted_vendor")
        parameters.update({"vendor_substitution": "VEND-004", "signature_remains_valid": True})
    elif scenario_type == "rollback":
        major, _, _ = version_tuple(lineage["approved_version"])
        observed["observed_version"] = f"{max(0, major - 1)}.{rng.randint(0, 9)}.{rng.randint(0, 9)}"
        observed["rollback_authorized"] = False
        injected.append("unauthorized_rollback")
        parameters.update({"version_action": "downgrade", "rollback_authorized": False})
    elif scenario_type == "stale_evidence":
        observed["evidence_age_days"] = rng.randint(31, 365)
        injected.append("stale_evidence")
        parameters.update({"evidence_age_days": observed["evidence_age_days"], "threshold_days": 30})
    elif scenario_type == "benign_exception":
        if rng.random() < 0.5:
            observed["vulnerability_present"] = True
            observed["vulnerability_applicable"] = False
            observed["known_vulnerability_count"] = rng.randint(1, 3)
            observed["max_cvss_score"] = round(rng.uniform(3.0, 8.0), 1)
            parameters.update({"exception": "vulnerability_not_applicable"})
        else:
            major, _, _ = version_tuple(lineage["approved_version"])
            observed["observed_version"] = f"{max(0, major - 1)}.{rng.randint(0, 9)}.{rng.randint(0, 9)}"
            observed["rollback_authorized"] = True
            parameters.update({"exception": "authorized_rollback"})
    else:
        parameters["mutation"] = "none"

    risk_score, label, factors = score_evidence(observed, reference)
    ground_truth = {
        "record_id": record_id,
        "ground_truth_label": label,
        "ground_truth_score": risk_score,
        "ground_truth_factors": ";".join(factors),
    }
    manifest = {
        "scenario_manifest_id": f"MANIFEST-{record_number:05d}",
        "record_id": record_id,
        "package_id": package_id,
        "lineage_id": lineage["lineage_id"],
        "scenario_type": scenario_type,
        "injected_conditions": ";".join(injected),
        "attack_parameters": json.dumps(parameters, sort_keys=True, separators=(",", ":")),
        "generator_version": GENERATOR_VERSION,
        "record_seed": record_seed,
        "run_id": RUN_ID,
    }
    return {"observable": observed, "reference": reference, "ground_truth": ground_truth, "manifest": manifest}


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def write_reference_catalog() -> None:
    rows: list[dict] = []
    for vendor_id, name, trusted in VENDORS:
        rows.append({"reference_type": "vendor", "reference_id": vendor_id, "name": name, "trusted": trusted, "version": ""})
    for component_id, name, version in COMPONENTS:
        rows.append({"reference_type": "component", "reference_id": component_id, "name": name, "trusted": "", "version": version})
    write_csv(OUTPUT_DIR / "reference_catalog.csv", rows, ["reference_type", "reference_id", "name", "trusted", "version"])


def write_hash_manifest(names: list[str]) -> None:
    hashes = {name: hashlib.sha256((OUTPUT_DIR / name).read_bytes()).hexdigest() for name in names}
    (OUTPUT_DIR / "dataset_file_hashes.json").write_text(json.dumps(hashes, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    records = [regenerate_record(number, SEED + number) for number in range(1, NUM_RECORDS + 1)]
    observable = [record["observable"] for record in records]
    references = [record["reference"] for record in records]
    labels = [record["ground_truth"] for record in records]
    manifests = [record["manifest"] for record in records]
    write_csv(OUTPUT_DIR / "observable_features.csv", observable, list(observable[0]))
    write_csv(OUTPUT_DIR / "reference_data.csv", references, list(references[0]))
    write_csv(OUTPUT_DIR / "ground_truth_labels.csv", labels, list(labels[0]))
    write_csv(OUTPUT_DIR / "scenario_manifests.csv", manifests, list(manifests[0]))
    write_reference_catalog()

    lineages = [f"LINEAGE-{number:04d}" for number in range(1, NUM_LINEAGES + 1)]
    random.Random(SEED + 999).shuffle(lineages)
    split_map = {lineage: "train" for lineage in lineages[:350]}
    split_map.update({lineage: "validation" for lineage in lineages[350:425]})
    split_map.update({lineage: "test" for lineage in lineages[425:]})
    split_rows = [{
        "record_id": row["record_id"], "package_id": row["package_id"],
        "split": split_map[row["lineage_id"]], "group_id": row["lineage_id"],
        "run_id": RUN_ID,
    } for row in observable]
    write_csv(OUTPUT_DIR / "split_assignments.csv", split_rows, list(split_rows[0]))

    label_counts = {label: sum(row["ground_truth_label"] == label for row in labels) for label in ["normal", "investigate", "high_risk"]}
    scenario_counts = {scenario: sum(row["scenario_type"] == scenario for row in manifests) for scenario in SCENARIO_TYPES}
    parameters = {
        "generator_name": "synthetic_firmware_supply_chain_dataset",
        "generator_version": GENERATOR_VERSION,
        "run_id": RUN_ID,
        "seed": SEED,
        "record_count": NUM_RECORDS,
        "lineage_count": NUM_LINEAGES,
        "records_per_lineage": RECORDS_PER_LINEAGE,
        "generated_at_utc": GENERATED_AT_UTC,
        "scenario_distribution": scenario_counts,
        "decision_distribution": label_counts,
        "reproducibility": "Each record is regenerated by regenerate_record(record_number, record_seed).",
        "safety_statement": "Synthetic data only; no firmware was deployed or executed.",
    }
    (OUTPUT_DIR / "generation_parameters.json").write_text(json.dumps(parameters, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    core = ["reference_data.csv", "reference_catalog.csv", "observable_features.csv", "ground_truth_labels.csv", "scenario_manifests.csv", "generation_parameters.json", "split_assignments.csv"]
    write_hash_manifest(core)
    print(f"Generated {NUM_RECORDS} records across {NUM_LINEAGES} lineages")
    print("Class distribution:", label_counts)


if __name__ == "__main__":
    main()
