"""
Read-only API for ransomware static-indicator evidence assessment.

This API accepts structured evidence from an external static scanner.
It does not scan, execute, unpack, or modify firmware.
"""

from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from src.supply_chain.anomaly.ransomware_assessment import (
    assess_ransomware_indicators,
)


router = APIRouter(
    prefix="/api/ransomware-assessment",
    tags=["Ransomware Static Assessment"],
)

_AUDIT_LOCK = threading.Lock()
MAX_REQUEST_BYTES = 256 * 1024


class RansomwareAssessmentRequest(BaseModel):
    """Request containing expected artifact hash and scanner evidence."""

    model_config = ConfigDict(extra="forbid")

    expected_artifact_sha256: str = Field(min_length=64, max_length=64)
    evidence: dict[str, Any]


@router.post("/analyze")
def analyze_ransomware_evidence(
    request: RansomwareAssessmentRequest,
) -> dict[str, Any]:
    """Assess externally supplied static ransomware-indicator evidence."""

    request_data = request.model_dump()

    request_size = len(
        json.dumps(
            request_data,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    )

    if request_size > MAX_REQUEST_BYTES:
        raise HTTPException(
            status_code=413,
            detail="Ransomware evidence request exceeds the size limit.",
        )

    try:
        result = assess_ransomware_indicators(
            evidence=request.evidence,
            expected_artifact_sha256=request.expected_artifact_sha256,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc

    assessed_at = datetime.now(timezone.utc).isoformat()
    assessment_id = str(uuid.uuid4())

    response = {
        "assessment_id": assessment_id,
        "assessed_at_utc": assessed_at,
        **result,
    }

    # Record only compact metadata. Do not persist the full evidence,
    # artifact hash, reviewer details, or proprietary scanner report.
    project_root = Path(__file__).resolve().parents[3]
    audit_path = (
        project_root
        / "artifacts"
        / "dashboard"
        / "audit.jsonl"
    )

    audit_event = {
        "event": "ransomware_static_assessment_completed",
        "assessment_id": assessment_id,
        "assessment_status": result["assessment_status"],
        "finding_count": result["finding_count"],
        "highest_reported_severity": result[
            "highest_reported_severity"
        ],
        "scanner_name": result["scanner"]["name"],
        "timestamp": assessed_at,
        "firmware_executed": False,
        "firmware_modified": False,
        "real_action_executed": False,
        "infection_confirmed": False,
    }

    try:
        audit_path.parent.mkdir(parents=True, exist_ok=True)

        with _AUDIT_LOCK:
            with audit_path.open("a", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(audit_event, ensure_ascii=False) + "\n"
                )
    except OSError as exc:
        # Do not report a successful assessment if its audit event
        # could not be recorded.
        raise HTTPException(
            status_code=500,
            detail="Assessment could not be recorded in the audit log.",
        ) from exc

    return response