
from __future__ import annotations

import hashlib

import pytest

from src.supply_chain.anomaly.yara_scanner import scan_file
from src.supply_chain.anomaly.ransomware_assessment import (
    assess_ransomware_indicators,
)


SYNTHETIC_CASES = [
    (
        b"SYNTHETIC_RANSOMWARE_SIGNATURE_MARKER",
        "ransomware_signature",
    ),
    (
        b"SYNTHETIC_RANSOM_NOTE_MARKER",
        "ransom_note_artifact",
    ),
    (
        b"SYNTHETIC_ENCRYPTION_ROUTINE_MARKER",
        "encryption_routine_indicator",
    ),
    (
        b"SYNTHETIC_RECOVERY_INHIBITION_MARKER",
        "recovery_inhibition_indicator",
    ),
    (
        b"SYNTHETIC_PERSISTENCE_MARKER",
        "suspicious_persistence",
    ),
]


@pytest.mark.parametrize(
    ("sample", "expected_type"),
    SYNTHETIC_CASES,
)
def test_yara_detects_synthetic_indicator(
    tmp_path,
    sample,
    expected_type,
):
    artifact = tmp_path / "synthetic_firmware.bin"
    artifact.write_bytes(sample)

    evidence = scan_file(
        artifact,
        data_provenance="SYNTHETIC_TEST_FIXTURE",
    )

    assert evidence["scan_completed"] is True
    assert evidence["scan_mode"] == "static"
    assert evidence["schema_version"] == "1.0"

    assert len(evidence["findings"]) == 1
    assert evidence["findings"][0]["indicator_type"] == expected_type
    assert evidence["findings"][0]["validation_status"] == (
        "scanner_reported"
    )


def test_clean_synthetic_file_reports_no_indicators(tmp_path):
    artifact = tmp_path / "clean_firmware.bin"
    artifact.write_bytes(b"SYNTHETIC_CLEAN_FIRMWARE_FIXTURE")

    evidence = scan_file(
        artifact,
        data_provenance="SYNTHETIC_TEST_FIXTURE",
    )

    assert evidence["scan_completed"] is True
    assert evidence["findings"] == []


def test_evidence_is_compatible_with_existing_assessment(
    tmp_path,
):
    artifact = tmp_path / "synthetic_firmware.bin"
    artifact.write_bytes(
        b"SYNTHETIC_RANSOM_NOTE_MARKER"
    )

    evidence = scan_file(
        artifact,
        data_provenance="SYNTHETIC_TEST_FIXTURE",
    )

    result = assess_ransomware_indicators(
        evidence,
        evidence["artifact_sha256"],
    )

    assert result["assessment_status"] == "review_required"
    assert result["finding_count"] == 1
    assert result["infection_confirmed"] is False
    assert result["firmware_executed"] is False
    assert result["firmware_modified"] is False
    assert result["real_action_executed"] is False
    assert result["decision_authority"] == "HUMAN_REVIEW_REQUIRED"


def test_artifact_hash_matches_scanned_content(tmp_path):
    artifact = tmp_path / "synthetic.bin"
    content = b"SYNTHETIC_RANSOM_NOTE_MARKER"

    artifact.write_bytes(content)

    evidence = scan_file(artifact)

    expected_hash = hashlib.sha256(content).hexdigest()

    assert evidence["artifact_sha256"] == expected_hash


def test_scanner_does_not_modify_artifact(tmp_path):
    artifact = tmp_path / "synthetic.bin"
    original_content = b"SYNTHETIC_PERSISTENCE_MARKER"

    artifact.write_bytes(original_content)

    scan_file(artifact)

    assert artifact.read_bytes() == original_content


def test_missing_artifact_is_rejected(tmp_path):
    artifact = tmp_path / "missing.bin"

    with pytest.raises(FileNotFoundError):
        scan_file(artifact)


def test_oversized_artifact_is_rejected(tmp_path):
    artifact = tmp_path / "large.bin"
    artifact.write_bytes(b"A" * 100)

    with pytest.raises(ValueError, match="maximum file size"):
        scan_file(
            artifact,
            max_file_size_bytes=50,
        )


def test_invalid_maximum_file_size_is_rejected(tmp_path):
    artifact = tmp_path / "synthetic.bin"
    artifact.write_bytes(b"SYNTHETIC_CLEAN_FIXTURE")

    with pytest.raises(ValueError, match="positive integer"):
        scan_file(
            artifact,
            max_file_size_bytes=0,
        )


def test_empty_data_provenance_is_rejected(tmp_path):
    artifact = tmp_path / "synthetic.bin"
    artifact.write_bytes(b"SYNTHETIC_CLEAN_FIXTURE")

    with pytest.raises(ValueError, match="data_provenance"):
        scan_file(
            artifact,
            data_provenance="",
        )
