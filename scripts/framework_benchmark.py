"""Reproducible standards benchmark for the synthetic firmware dataset.

This checks conformance and evidence coverage. It does not certify compliance,
prove production security, or compare against a real-world firmware corpus.
"""

from __future__ import annotations

import csv
import hashlib
import json
import warnings
from collections import Counter
from pathlib import Path

import pandas as pd
warnings.filterwarnings("ignore", category=DeprecationWarning)
from jsonschema import Draft7Validator, RefResolver


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "data" / "synthetic" / "supply_chain_poc"
DATASET = BASE / "dataset"
BENCHMARK = ROOT / "benchmarks" / "frameworks"
SCHEMAS = BENCHMARK / "schemas"
RESULTS = BENCHMARK / "results"
SCHEMA_SOURCE = "https://cyclonedx.org/schema/bom-1.5.schema.json"
BENCHMARK_DATE = "2026-09-01"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")


def cyclone_validator() -> Draft7Validator:
    schema_path = SCHEMAS / "bom-1.5.schema.json"
    jsf_path = SCHEMAS / "jsf-0.82.schema.json"
    assert schema_path.exists() and jsf_path.exists(), "Official CycloneDX schemas are missing"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsf = json.loads(jsf_path.read_text(encoding="utf-8"))
    store = {
        "jsf-0.82.schema.json": jsf,
        "http://cyclonedx.org/schema/jsf-0.82.schema.json": jsf,
        "https://cyclonedx.org/schema/jsf-0.82.schema.json": jsf,
    }
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        resolver = RefResolver.from_schema(schema, store=store)
    return Draft7Validator(schema, resolver=resolver)


def validate_cyclonedx() -> dict:
    validator = cyclone_validator()
    files = sorted((BASE / "sbom").glob("*.json"))
    files += sorted((BASE / "generated" / "fixtures" / "modified_sbom").glob("*.json"))
    assert files, "No raw CycloneDX documents found"
    documents = []
    for path in files:
        value = json.loads(path.read_text(encoding="utf-8"))
        errors = sorted(validator.iter_errors(value), key=lambda error: list(error.path))
        documents.append({
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": sha256(path),
            "valid": not errors,
            "errors": [
                {"path": "/".join(str(part) for part in error.path), "message": error.message}
                for error in errors
            ],
        })

    references = []
    for bundle in sorted((BASE / "generated" / "evidence_bundles").glob("SC-*")):
        envelope_path = bundle / "sbom.json"
        envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
        if not envelope.get("sbom_present"):
            references.append({
                "scenario_id": bundle.name,
                "status": "expected_missing",
                "path": None,
                "hash_match": None,
            })
            continue
        raw_path = ROOT / envelope["sbom_path"]
        references.append({
            "scenario_id": bundle.name,
            "status": "present",
            "path": raw_path.relative_to(ROOT).as_posix(),
            "hash_match": raw_path.exists() and sha256(raw_path) == envelope["sbom_sha256"],
        })

    return {
        "framework": "CycloneDX",
        "version": "1.5",
        "official_schema_source": SCHEMA_SOURCE,
        "official_schema_sha256": sha256(SCHEMAS / "bom-1.5.schema.json"),
        "jsf_schema_sha256": sha256(SCHEMAS / "jsf-0.82.schema.json"),
        "documents_checked": len(documents),
        "documents_valid": sum(document["valid"] for document in documents),
        "all_documents_valid": all(document["valid"] for document in documents),
        "all_present_references_match": all(
            reference["hash_match"] is not False for reference in references
        ),
        "documents": documents,
        "evidence_references": references,
    }


def validate_dataset_coverage() -> dict:
    observed = pd.read_csv(DATASET / "observable_features.csv", keep_default_na=False)
    references = pd.read_csv(DATASET / "reference_data.csv", keep_default_na=False)
    labels = pd.read_csv(DATASET / "ground_truth_labels.csv", keep_default_na=False)
    manifests = pd.read_csv(DATASET / "scenario_manifests.csv", keep_default_na=False)
    splits = pd.read_csv(DATASET / "split_assignments.csv", keep_default_na=False)
    features = pd.read_csv(DATASET / "engineered_features.csv", keep_default_na=False)

    ids = set(observed["record_id"])
    assert len(observed) == 5000 and observed["record_id"].is_unique
    assert all(set(frame["record_id"]) == ids for frame in (references, labels, manifests, splits, features))
    groups = splits.groupby("group_id").agg(size=("record_id", "size"), splits=("split", "nunique"))
    scenario_counts = manifests["scenario_type"].value_counts().sort_index().to_dict()
    label_counts = labels["ground_truth_label"].value_counts().sort_index().to_dict()
    split_counts = splits["split"].value_counts().sort_index().to_dict()

    required_observed = {
        "observed_hash", "signature_valid", "trusted_root_valid", "sbom_present",
        "sbom_complete", "observed_vendor_id", "observed_version", "rollback_authorized",
        "vulnerability_present", "vulnerability_applicable", "unexpected_component",
        "evidence_age_days", "record_seed", "run_id",
    }
    required_reference = {
        "approved_vendor_id", "trusted_hash", "approved_version",
        "freshness_threshold_days", "approved_component_count",
    }
    assert required_observed.issubset(observed.columns)
    assert required_reference.issubset(references.columns)
    assert set(scenario_counts.values()) == {500} and len(scenario_counts) == 10
    assert len(groups) == 500 and set(groups["size"]) == {10} and set(groups["splits"]) == {1}

    return {
        "record_count": len(observed),
        "lineage_count": len(groups),
        "records_per_lineage": 10,
        "engineered_feature_count": len(features.columns) - 1,
        "scenario_distribution": scenario_counts,
        "label_distribution": label_counts,
        "split_distribution": split_counts,
        "required_observed_fields_present": sorted(required_observed),
        "required_reference_fields_present": sorted(required_reference),
        "external_real_world_dataset_used": False,
        "realism_status": "synthetic_only",
        "realism_limitation": (
            "The benchmark verifies standards representation and internal invariants. "
            "It does not establish that synthetic feature distributions match deployed firmware ecosystems."
        ),
    }


def flatten_framework_coverage() -> list[dict]:
    source = json.loads((BENCHMARK / "framework_requirements.json").read_text(encoding="utf-8"))
    rows = []
    for framework in source["frameworks"]:
        for requirement in framework["requirements"]:
            row = {
                "framework": framework["framework"],
                "version": framework["version"],
                "official_url": framework["official_url"],
                **requirement,
            }
            assert row["status"] in {"covered", "partial", "gap"}
            rows.append(row)
    assert len({row["requirement_id"] for row in rows}) == len(rows)
    return rows


def write_coverage_csv(rows: list[dict], output: Path) -> None:
    fields = ["framework", "version", "requirement_id", "requirement", "status", "evidence", "official_url"]
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def build_report(cyclonedx: dict, dataset: dict, rows: list[dict]) -> str:
    status_counts = Counter(row["status"] for row in rows)
    by_framework: dict[str, Counter] = {}
    for row in rows:
        by_framework.setdefault(row["framework"], Counter())[row["status"]] += 1
    lines = [
        "# Firmware dataset framework benchmark",
        "",
        f"Benchmark date: {BENCHMARK_DATE}",
        "",
        "> This is a reproducible conformance and coverage assessment. It is not a certification, production compliance claim, or proof that synthetic distributions match real firmware fleets.",
        "",
        "## Acceptance result",
        "",
        f"- CycloneDX 1.5 raw documents valid: {cyclonedx['documents_valid']}/{cyclonedx['documents_checked']}.",
        f"- SBOM evidence references and hashes consistent: {str(cyclonedx['all_present_references_match']).lower()}.",
        f"- Dataset records assessed: {dataset['record_count']} across {dataset['lineage_count']} grouped lineages.",
        f"- Framework controls: {status_counts['covered']} covered, {status_counts['partial']} partial, {status_counts['gap']} gaps.",
        "",
        "## Framework coverage summary",
        "",
        "| Framework | Covered | Partial | Gap |",
        "|---|---:|---:|---:|",
    ]
    for framework, counts in by_framework.items():
        lines.append(f"| {framework} | {counts['covered']} | {counts['partial']} | {counts['gap']} |")
    lines.extend([
        "",
        "## Material findings",
        "",
        "- CycloneDX schema conformance is now enforced for canonical and deliberately modified raw SBOM fixtures.",
        "- The dataset strongly covers integrity and detection signals, including hashes, signatures, roots of trust, rollback, vendor trust, SBOM completeness, vulnerabilities and staleness.",
        "- SLSA build/source provenance is not represented. No signed provenance, builder identity, source revision, build instructions or build-platform isolation evidence exists.",
        "- NIST SP 800-193 detection and rollback concepts are represented; hardware-backed protection and recovery are outside the PoC boundary.",
        "- NIST SSDF component/vulnerability practices are partially represented, but organisational development-process controls are not established by this dataset.",
        "- VEX exists as reference CSV data, not yet as a standards-valid CycloneDX vulnerability analysis object.",
        "",
        "## Realism and generalisation limitation",
        "",
        dataset["realism_limitation"],
        "No external firmware corpus is used in this gate. Consequently, later ML evaluation must describe the model as validated on synthetic data only and must not claim production generalisation.",
        "",
        "## ML gate consequence",
        "",
        "The dataset may proceed to a controlled synthetic baseline-model experiment after the repository and ML specification gates pass. Framework gaps remain explicit model limitations and must not be converted into inferred negative evidence.",
        "",
        "## Reproduce",
        "",
        "```powershell",
        "python scripts/generate_evidence_bundles.py",
        "python -m src.supply_chain.decision_engine",
        "python scripts/framework_benchmark.py",
        "```",
        "",
    ])
    return "\n".join(lines)


def run(output_dir: Path = RESULTS) -> dict:
    cyclonedx = validate_cyclonedx()
    dataset = validate_dataset_coverage()
    rows = flatten_framework_coverage()
    assert cyclonedx["all_documents_valid"], "CycloneDX schema validation failed"
    assert cyclonedx["all_present_references_match"], "SBOM evidence reference hash mismatch"

    output_dir.mkdir(parents=True, exist_ok=True)
    write_json(output_dir / "cyclonedx_validation.json", cyclonedx)
    write_json(output_dir / "dataset_coverage.json", dataset)
    write_coverage_csv(rows, output_dir / "framework_coverage.csv")
    report = build_report(cyclonedx, dataset, rows)
    (output_dir / "FRAMEWORK_BENCHMARK_REPORT.md").write_text(report, encoding="utf-8", newline="\n")
    result = {
        "benchmark_date": BENCHMARK_DATE,
        "benchmark_status": "passed_with_documented_gaps",
        "cyclonedx_documents_valid": cyclonedx["documents_valid"],
        "cyclonedx_documents_checked": cyclonedx["documents_checked"],
        "dataset_records_checked": dataset["record_count"],
        "framework_requirement_count": len(rows),
        "coverage_counts": dict(Counter(row["status"] for row in rows)),
        "external_real_world_dataset_used": False,
        "ml_training_authorized_by_this_benchmark": False,
    }
    write_json(output_dir / "benchmark_summary.json", result)
    return result


def main() -> None:
    result = run()
    print("[PASS] Official CycloneDX 1.5 schema validation")
    print("[PASS] SBOM evidence reference and hash validation")
    print("[PASS] 5,000-record dataset coverage and grouped-lineage invariants")
    print("[PASS] SLSA and NIST coverage matrix generated with explicit gaps")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
