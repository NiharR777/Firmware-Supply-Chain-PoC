"""
Explainable, read-only ransomware static-indicator assessment.

This module evaluates structured evidence supplied by an external static
analysis scanner. It does not scan, execute, unpack, or modify firmware.

A scanner-reported indicator is not proof of ransomware infection.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any


SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")

SUPPORTED_INDICATORS = {
    "ransomware_signature",
    "ransom_note_artifact",
    "encryption_routine_indicator",
    "recovery_inhibition_indicator",
    "suspicious_persistence",
}

SUPPORTED_SEVERITIES = {"low", "medium", "high", "critical"}

SUPPORTED_VALIDATION_STATUSES = {
    "scanner_reported",
    "analyst_reviewed",
}

SEVERITY_ORDER = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _require_text(value: Any, field: str, max_length: int = 500) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string.")

    value = value.strip()

    if len(value) > max_length:
        raise ValueError(f"{field} exceeds the maximum length.")

    return value


def _validate_sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ValueError(f"{field} must be a valid 64-character SHA-256 hash.")

    return value.lower()


def _validate_utc_timestamp(value: Any, field: str) -> str:
    timestamp = _require_text(value, field, 80)

    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(
            f"{field} must be a valid ISO-8601 UTC timestamp."
        ) from exc

    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError(f"{field} must include a UTC timezone.")

    return timestamp


def _validate_finding(finding: Any, index: int) -> dict[str, Any]:
    if not isinstance(finding, dict):
        raise ValueError(f"Finding at index {index} must be an object.")

    indicator_type = _require_text(
        finding.get("indicator_type"),
        f"findings[{index}].indicator_type",
        80,
    )

    if indicator_type not in SUPPORTED_INDICATORS:
        raise ValueError(
            f"Unsupported ransomware indicator type: {indicator_type}"
        )

    indicator_id = _require_text(
        finding.get("indicator_id"),
        f"findings[{index}].indicator_id",
        120,
    )

    description = _require_text(
        finding.get("description"),
        f"findings[{index}].description",
        1000,
    )

    severity = _require_text(
        finding.get("severity"),
        f"findings[{index}].severity",
        20,
    ).lower()

    if severity not in SUPPORTED_SEVERITIES:
        raise ValueError(f"Unsupported severity: {severity}")

    confidence = finding.get("confidence")

    if (
        isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or not 0.0 <= confidence <= 1.0
    ):
        raise ValueError(
            f"findings[{index}].confidence must be between 0 and 1."
        )

    validation_status = _require_text(
        finding.get("validation_status"),
        f"findings[{index}].validation_status",
        40,
    )

    if validation_status not in SUPPORTED_VALIDATION_STATUSES:
        raise ValueError(
            f"Unsupported validation status: {validation_status}"
        )

    validated_finding = {
        "indicator_type": indicator_type,
        "indicator_id": indicator_id,
        "description": description,
        "severity": severity,
        "confidence": float(confidence),
        "validation_status": validation_status,
        "explanation": (
            "This static indicator warrants security investigation. "
            "It does not independently establish malicious execution "
            "or confirm ransomware infection."
        ),
    }

    if validation_status == "analyst_reviewed":
        reviewer_id = _require_text(
            finding.get("reviewer_id"),
            f"findings[{index}].reviewer_id",
            120,
        )

        reviewed_at_utc = _validate_utc_timestamp(
            finding.get("reviewed_at_utc"),
            f"findings[{index}].reviewed_at_utc",
        )

        review_reference = _require_text(
            finding.get("review_reference"),
            f"findings[{index}].review_reference",
            160,
        )

        validated_finding.update({
            "reviewer_id": reviewer_id,
            "reviewed_at_utc": reviewed_at_utc,
            "review_reference": review_reference,
        })

    return validated_finding


def assess_ransomware_indicators(
    evidence: dict[str, Any],
    expected_artifact_sha256: str,
) -> dict[str, Any]:
    """
    Assess supplied static ransomware-indicator evidence.

    Required evidence fields:
      schema_version
      artifact_sha256
      scanner_name
      scanner_version
      scan_timestamp_utc
      scan_mode
      scan_completed
      findings
      data_provenance

    The expected artifact hash must match the scanner evidence hash.
    No firmware binary is opened or executed.
    """

    if not isinstance(evidence, dict):
        raise ValueError("Evidence must be a JSON-style object.")

    expected_hash = _validate_sha256(
        expected_artifact_sha256,
        "expected_artifact_sha256",
    )

    observed_hash = _validate_sha256(
        evidence.get("artifact_sha256"),
        "artifact_sha256",
    )

    if observed_hash != expected_hash:
        raise ValueError(
            "Artifact SHA-256 mismatch: scanner evidence does not "
            "belong to the expected firmware artifact."
        )

    schema_version = _require_text(
        evidence.get("schema_version"),
        "schema_version",
        20,
    )

    if schema_version != "1.0":
        raise ValueError("Unsupported ransomware evidence schema version.")

    scanner_name = _require_text(
        evidence.get("scanner_name"),
        "scanner_name",
        120,
    )

    scanner_version = _require_text(
        evidence.get("scanner_version"),
        "scanner_version",
        80,
    )

    scan_timestamp = _validate_utc_timestamp(
        evidence.get("scan_timestamp_utc"),
        "scan_timestamp_utc",
    )

    scan_mode = _require_text(
        evidence.get("scan_mode"),
        "scan_mode",
        40,
    )

    if scan_mode != "static":
        raise ValueError(
            "Only static analysis evidence is supported by this module."
        )

    scan_completed = evidence.get("scan_completed")

    if not isinstance(scan_completed, bool):
        raise ValueError("scan_completed must be a boolean.")

    provenance = _require_text(
        evidence.get("data_provenance"),
        "data_provenance",
        120,
    )

    raw_findings = evidence.get("findings")

    if not isinstance(raw_findings, list):
        raise ValueError("findings must be a list.")

    if len(raw_findings) > 500:
        raise ValueError("Too many findings in one assessment.")

    findings = [
        _validate_finding(item, index)
        for index, item in enumerate(raw_findings)
    ]

    finding_ids = [item["indicator_id"] for item in findings]

    if len(finding_ids) != len(set(finding_ids)):
        raise ValueError("Duplicate indicator_id values are not allowed.")

    if not scan_completed:
        assessment_status = "inconclusive"
        recommendation = "obtain_completed_static_analysis"
        explanation = (
            "The scanner did not complete its analysis. "
            "No conclusion can be drawn from this evidence."
        )
    elif findings:
        assessment_status = "review_required"
        recommendation = "isolate_for_human_security_review"
        explanation = (
            "One or more ransomware-related static indicators were "
            "reported. A qualified analyst must review the findings."
        )
    else:
        assessment_status = "no_indicators_reported"
        recommendation = "continue_with_standard_security_review"
        explanation = (
            "The completed scanner report supplied no supported "
            "ransomware indicators. This does not prove the firmware "
            "is malware-free."
        )

    highest_severity = (
        max(
            (item["severity"] for item in findings),
            key=lambda value: SEVERITY_ORDER[value],
        )
        if findings
        else "none"
    )

    analyst_reviewed_count = sum(
        item["validation_status"] == "analyst_reviewed"
        for item in findings
    )

    return {
        "assessment_type": "RANSOMWARE_STATIC_INDICATOR_ASSESSMENT",
        "assessment_status": assessment_status,
        "artifact_sha256": observed_hash,
        "scanner": {
            "name": scanner_name,
            "version": scanner_version,
            "scan_timestamp_utc": scan_timestamp,
            "scan_mode": scan_mode,
            "scan_completed": scan_completed,
        },
        "finding_count": len(findings),
        "analyst_reviewed_count": analyst_reviewed_count,
        "highest_reported_severity": highest_severity,
        "findings": findings,
        "recommendation": recommendation,
        "explanation": explanation,
        "decision_authority": "HUMAN_REVIEW_REQUIRED",
        "firmware_executed": False,
        "firmware_modified": False,
        "real_action_executed": False,
        "infection_confirmed": False,
        "data_provenance": provenance,
        "limitations": [
            "This module evaluates supplied scanner evidence only.",
            "It does not scan or execute firmware binaries.",
            "Static indicators do not prove malicious runtime behaviour.",
            "No reported indicators do not guarantee malware absence.",
            "Human security review is required before operational decisions.",
            "Reviewer metadata provides traceability but does not authenticate identity.",
            "Scanner metadata is supplied evidence and is not independently authenticated here.",
        ],
    }
