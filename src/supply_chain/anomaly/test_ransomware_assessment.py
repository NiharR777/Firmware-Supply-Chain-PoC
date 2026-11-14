import pytest

from src.supply_chain.anomaly.ransomware_assessment import (
    assess_ransomware_indicators,
)


ARTIFACT_HASH = "a" * 64


def make_evidence(findings=None, **overrides):
    evidence = {
        "schema_version": "1.0",
        "artifact_sha256": ARTIFACT_HASH,
        "scanner_name": "DemoStaticScanner",
        "scanner_version": "1.0",
        "scan_timestamp_utc": "2026-11-14T10:00:00Z",
        "scan_mode": "static",
        "scan_completed": True,
        "findings": findings if findings is not None else [],
        "data_provenance": "SYNTHETIC TEST EVIDENCE",
    }
    evidence.update(overrides)
    return evidence


def make_finding(**overrides):
    finding = {
        "indicator_type": "ransomware_signature",
        "indicator_id": "TEST-001",
        "description": "Synthetic ransomware signature match.",
        "severity": "high",
        "confidence": 0.95,
        "validation_status": "scanner_reported",
    }
    finding.update(overrides)
    return finding


def make_reviewed_finding(**overrides):
    finding = make_finding(
        validation_status="analyst_reviewed",
        reviewer_id="analyst-001",
        reviewed_at_utc="2026-11-14T11:00:00Z",
        review_reference="SEC-REVIEW-001",
    )
    finding.update(overrides)
    return finding


def test_empty_completed_scan_reports_no_indicators():
    result = assess_ransomware_indicators(
        make_evidence(),
        ARTIFACT_HASH,
    )

    assert result["assessment_status"] == "no_indicators_reported"
    assert result["finding_count"] == 0
    assert result["infection_confirmed"] is False
    assert result["firmware_executed"] is False


def test_ransomware_indicator_requires_human_review():
    result = assess_ransomware_indicators(
        make_evidence([make_finding()]),
        ARTIFACT_HASH,
    )

    assert result["assessment_status"] == "review_required"
    assert result["finding_count"] == 1
    assert result["highest_reported_severity"] == "high"
    assert result["recommendation"] == "isolate_for_human_security_review"
    assert result["infection_confirmed"] is False


def test_multiple_indicators_are_reported():
    findings = [
        make_finding(),
        make_finding(
            indicator_type="ransom_note_artifact",
            indicator_id="TEST-002",
            severity="critical",
        ),
    ]

    result = assess_ransomware_indicators(
        make_evidence(findings),
        ARTIFACT_HASH,
    )

    assert result["finding_count"] == 2
    assert result["highest_reported_severity"] == "critical"


def test_incomplete_scan_is_inconclusive():
    result = assess_ransomware_indicators(
        make_evidence(scan_completed=False),
        ARTIFACT_HASH,
    )

    assert result["assessment_status"] == "inconclusive"
    assert result["recommendation"] == "obtain_completed_static_analysis"


def test_artifact_hash_mismatch_is_rejected():
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        assess_ransomware_indicators(
            make_evidence(),
            "b" * 64,
        )


def test_invalid_artifact_hash_is_rejected():
    with pytest.raises(ValueError, match="64-character SHA-256"):
        assess_ransomware_indicators(
            make_evidence(),
            "invalid-hash",
        )


def test_unsupported_indicator_is_rejected():
    finding = make_finding(
        indicator_type="generic_vulnerability",
    )

    with pytest.raises(ValueError, match="Unsupported ransomware indicator"):
        assess_ransomware_indicators(
            make_evidence([finding]),
            ARTIFACT_HASH,
        )


def test_invalid_confidence_is_rejected():
    finding = make_finding(confidence=1.5)

    with pytest.raises(ValueError, match="confidence"):
        assess_ransomware_indicators(
            make_evidence([finding]),
            ARTIFACT_HASH,
        )


def test_duplicate_finding_ids_are_rejected():
    findings = [
        make_finding(),
        make_finding(indicator_type="ransom_note_artifact"),
    ]

    with pytest.raises(ValueError, match="Duplicate indicator_id"):
        assess_ransomware_indicators(
            make_evidence(findings),
            ARTIFACT_HASH,
        )


def test_non_static_scan_mode_is_rejected():
    with pytest.raises(ValueError, match="Only static analysis"):
        assess_ransomware_indicators(
            make_evidence(scan_mode="dynamic"),
            ARTIFACT_HASH,
        )


def test_analyst_reviewed_count_and_metadata_are_reported():
    finding = make_reviewed_finding()

    result = assess_ransomware_indicators(
        make_evidence([finding]),
        ARTIFACT_HASH,
    )

    assert result["analyst_reviewed_count"] == 1
    assert result["findings"][0]["reviewer_id"] == "analyst-001"
    assert result["findings"][0]["reviewed_at_utc"] == "2026-11-14T11:00:00Z"
    assert result["findings"][0]["review_reference"] == "SEC-REVIEW-001"


def test_analyst_reviewed_finding_requires_reviewer_id():
    finding = make_reviewed_finding(reviewer_id="")

    with pytest.raises(ValueError, match="reviewer_id"):
        assess_ransomware_indicators(
            make_evidence([finding]),
            ARTIFACT_HASH,
        )


def test_analyst_reviewed_finding_requires_review_timestamp():
    finding = make_reviewed_finding(reviewed_at_utc="")

    with pytest.raises(ValueError, match="reviewed_at_utc"):
        assess_ransomware_indicators(
            make_evidence([finding]),
            ARTIFACT_HASH,
        )


def test_analyst_reviewed_finding_requires_review_reference():
    finding = make_reviewed_finding(review_reference="")

    with pytest.raises(ValueError, match="review_reference"):
        assess_ransomware_indicators(
            make_evidence([finding]),
            ARTIFACT_HASH,
        )


def test_analyst_review_timestamp_must_be_valid_utc():
    finding = make_reviewed_finding(
        reviewed_at_utc="2026-11-14T11:00:00",
    )

    with pytest.raises(ValueError, match="UTC"):
        assess_ransomware_indicators(
            make_evidence([finding]),
            ARTIFACT_HASH,
        )


def test_scanner_timestamp_must_be_valid_utc():
    with pytest.raises(ValueError, match="scan_timestamp_utc"):
        assess_ransomware_indicators(
            make_evidence(scan_timestamp_utc="not-a-timestamp"),
            ARTIFACT_HASH,
        )


def test_scanner_timestamp_without_timezone_is_rejected():
    with pytest.raises(ValueError, match="UTC"):
        assess_ransomware_indicators(
            make_evidence(scan_timestamp_utc="2026-11-14T10:00:00"),
            ARTIFACT_HASH,
        )


def test_non_utc_scanner_timestamp_is_rejected():
    with pytest.raises(ValueError, match="UTC"):
        assess_ransomware_indicators(
            make_evidence(scan_timestamp_utc="2026-11-14T15:30:00+05:30"),
            ARTIFACT_HASH,
        )


def test_utc_offset_zero_is_accepted():
    result = assess_ransomware_indicators(
        make_evidence(scan_timestamp_utc="2026-11-14T10:00:00+00:00"),
        ARTIFACT_HASH,
    )

    assert result["scanner"]["scan_timestamp_utc"] == "2026-11-14T10:00:00+00:00"


def test_assessment_never_confirms_infection():
    result = assess_ransomware_indicators(
        make_evidence([make_finding()]),
        ARTIFACT_HASH,
    )

    assert result["infection_confirmed"] is False
    assert result["real_action_executed"] is False
    assert result["firmware_modified"] is False
