from pathlib import Path

from scripts.framework_benchmark import (
    flatten_framework_coverage,
    run,
    validate_cyclonedx,
    validate_dataset_coverage,
)


def test_official_cyclonedx_schema_conformance():
    result = validate_cyclonedx()
    assert result["documents_checked"] == 7
    assert result["documents_valid"] == 7
    assert result["all_documents_valid"] is True
    assert result["all_present_references_match"] is True


def test_framework_matrix_has_explicit_claim_boundary():
    rows = flatten_framework_coverage()
    assert {row["framework"] for row in rows} == {
        "CycloneDX", "SLSA", "NIST SP 800-193", "NIST SP 800-218 SSDF",
    }
    assert {row["status"] for row in rows} == {"covered", "partial", "gap"}
    assert any(row["requirement_id"] == "SLSA-PROV" and row["status"] == "gap" for row in rows)


def test_dataset_framework_coverage_invariants():
    result = validate_dataset_coverage()
    assert result["record_count"] == 5000
    assert result["lineage_count"] == 500
    assert result["external_real_world_dataset_used"] is False
    assert result["realism_status"] == "synthetic_only"


def test_benchmark_outputs_are_generated(tmp_path: Path):
    result = run(tmp_path)
    assert result["benchmark_status"] == "passed_with_documented_gaps"
    assert result["ml_training_authorized_by_this_benchmark"] is False
    assert {path.name for path in tmp_path.iterdir()} == {
        "FRAMEWORK_BENCHMARK_REPORT.md",
        "benchmark_summary.json",
        "cyclonedx_validation.json",
        "dataset_coverage.json",
        "framework_coverage.csv",
    }
