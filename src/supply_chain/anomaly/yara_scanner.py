
"""
Read-only YARA static-indicator scanner.

Scans supplied artifact bytes using synthetic or approved YARA rules.
Does not execute, unpack, extract, or modify firmware.

YARA matches are indicators for human review, not proof of infection.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yara


SCANNER_NAME = "SpectraYaraStaticScanner"
SCANNER_VERSION = "1.0"
SCHEMA_VERSION = "1.0"

DEFAULT_RULES_PATH = (
    Path(__file__).parent
    / "yara_rules"
    / "synthetic_ransomware_indicators.yar"
)

DEFAULT_MAX_FILE_SIZE_BYTES = 64 * 1024 * 1024

SUPPORTED_INDICATORS = {
    "ransomware_signature",
    "ransom_note_artifact",
    "encryption_routine_indicator",
    "recovery_inhibition_indicator",
    "suspicious_persistence",
}

SUPPORTED_SEVERITIES = {
    "low",
    "medium",
    "high",
    "critical",
}


def _utc_timestamp() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _validate_metadata(meta: dict[str, Any]) -> dict[str, Any]:
    """Validate YARA rule metadata before creating evidence."""

    indicator_type = meta.get("indicator_type")

    if indicator_type not in SUPPORTED_INDICATORS:
        raise ValueError(
            f"Unsupported YARA indicator type: {indicator_type}"
        )

    severity = meta.get("severity")

    if severity not in SUPPORTED_SEVERITIES:
        raise ValueError(
            f"Unsupported YARA severity: {severity}"
        )

    confidence_percent = meta.get("confidence_percent")

    if (
        isinstance(confidence_percent, bool)
        or not isinstance(confidence_percent, int)
        or not 0 <= confidence_percent <= 100
    ):
        raise ValueError(
            "confidence_percent must be an integer between 0 and 100."
        )

    description = meta.get("description")

    if (
        not isinstance(description, str)
        or not description.strip()
        or len(description) > 1000
    ):
        raise ValueError("Invalid YARA rule description.")

    return {
        "indicator_type": indicator_type,
        "severity": severity,
        "confidence": confidence_percent / 100.0,
        "description": description.strip(),
    }


def _load_rules(rules_path: Path):
    if not rules_path.is_file():
        raise FileNotFoundError(
            f"YARA rules file not found: {rules_path}"
        )

    try:
        return yara.compile(filepath=str(rules_path))
    except yara.Error as exc:
        raise ValueError(
            f"Unable to compile YARA rules: {exc}"
        ) from exc


def scan_file(
    file_path: str | Path,
    rules_path: str | Path | None = None,
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
    data_provenance: str = "LOCAL_STATIC_FILE_SCAN",
) -> dict[str, Any]:
    """
    Scan a file using YARA and return ransomware evidence.

    The same in-memory bytes are used for hashing and scanning,
    preventing the hash from describing different content.

    No firmware execution or modification occurs.
    """

    if (
        isinstance(max_file_size_bytes, bool)
        or not isinstance(max_file_size_bytes, int)
        or max_file_size_bytes <= 0
    ):
        raise ValueError(
            "max_file_size_bytes must be a positive integer."
        )

    if (
        not isinstance(data_provenance, str)
        or not data_provenance.strip()
        or len(data_provenance.strip()) > 120
    ):
        raise ValueError(
            "data_provenance must be a non-empty string of at most 120 characters."
        )

    artifact_path = Path(file_path)

    if not artifact_path.is_file():
        raise FileNotFoundError(
            f"Artifact file not found: {artifact_path}"
        )

    selected_rules_path = (
        Path(rules_path)
        if rules_path is not None
        else DEFAULT_RULES_PATH
    )

    # Read only. The extra byte detects files exceeding the limit.
    try:
        with artifact_path.open("rb") as artifact:
            artifact_bytes = artifact.read(
                max_file_size_bytes + 1
            )
    except OSError as exc:
        raise ValueError(
            f"Unable to read artifact: {exc}"
        ) from exc

    if len(artifact_bytes) > max_file_size_bytes:
        raise ValueError(
            "Artifact exceeds the configured maximum file size."
        )

    # Hash and scan exactly the same byte sequence.
    artifact_hash = hashlib.sha256(
        artifact_bytes
    ).hexdigest()

    compiled_rules = _load_rules(selected_rules_path)

    try:
        matches = compiled_rules.match(
            data=artifact_bytes,
            timeout=10,
        )
    except yara.Error as exc:
        raise RuntimeError(
            f"YARA scanning failed: {exc}"
        ) from exc

    findings = []

    for match in matches:
        metadata = _validate_metadata(match.meta)

        rule_name = str(match.rule)

        findings.append({
            "indicator_type": metadata["indicator_type"],
            "indicator_id": f"YARA-{rule_name}",
            "description": metadata["description"],
            "severity": metadata["severity"],
            "confidence": metadata["confidence"],
            "validation_status": "scanner_reported",
        })

    findings.sort(
        key=lambda item: item["indicator_id"]
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_sha256": artifact_hash,
        "scanner_name": SCANNER_NAME,
        "scanner_version": SCANNER_VERSION,
        "scan_timestamp_utc": _utc_timestamp(),
        "scan_mode": "static",
        "scan_completed": True,
        "findings": findings,
        "data_provenance": data_provenance.strip(),
    }
