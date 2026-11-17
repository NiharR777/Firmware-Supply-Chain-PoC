
"""
Read-only API for ransomware static-indicator assessment.

Supports:
1. Structured evidence from an external static scanner.
2. Raw firmware upload scanned using the local YARA scanner.

Firmware is never executed, unpacked, installed, or modified.
YARA findings are indicators requiring human security review.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import uuid

from datetime import datetime, timezone
from functools import partial
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.concurrency import run_in_threadpool

from src.supply_chain.anomaly.ransomware_assessment import (
    assess_ransomware_indicators,
)
from src.supply_chain.anomaly.yara_scanner import scan_file


router = APIRouter(
    prefix="/api/ransomware-assessment",
    tags=["Ransomware Static Assessment"],
)

_AUDIT_LOCK = threading.Lock()

MAX_REQUEST_BYTES = 256 * 1024
MAX_UPLOAD_BYTES = 64 * 1024 * 1024
MAX_CONCURRENT_SCANS = 2

_SCAN_SLOTS = threading.BoundedSemaphore(
    MAX_CONCURRENT_SCANS
)

YARA_UPLOAD_PROVENANCE = "API_UPLOAD_STATIC_YARA_SCAN"


class RansomwareAssessmentRequest(BaseModel):
    """Request containing expected artifact hash and scanner evidence."""

    model_config = ConfigDict(extra="forbid")

    expected_artifact_sha256: str = Field(
        min_length=64,
        max_length=64,
    )
    evidence: dict[str, Any]


def _validate_content_length(
    request: Request,
    maximum_bytes: int,
) -> None:
    """Validate declared request size without trusting it as the only limit."""

    content_length = request.headers.get("content-length")

    if content_length is None:
        return

    if not re.fullmatch(r"[0-9]+", content_length.strip()):
        raise HTTPException(
            status_code=400,
            detail="Invalid Content-Length header.",
        )

    declared_length = int(content_length)

    if declared_length > maximum_bytes:
        raise HTTPException(
            status_code=413,
            detail="Request exceeds the configured size limit.",
        )


def _complete_assessment(
    evidence: dict[str, Any],
    expected_artifact_sha256: str,
) -> dict[str, Any]:
    """Validate evidence, assess it, and record compact audit metadata."""

    try:
        result = assess_ransomware_indicators(
            evidence=evidence,
            expected_artifact_sha256=expected_artifact_sha256,
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

    # Audit only compact metadata.
    # Never persist artifact hashes, full evidence, finding IDs,
    # proprietary scanner reports, or reviewer details.
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
        audit_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with _AUDIT_LOCK:
            with audit_path.open(
                "a",
                encoding="utf-8",
            ) as handle:
                handle.write(
                    json.dumps(
                        audit_event,
                        ensure_ascii=False,
                    ) + "\n"
                )

    except OSError as exc:
        raise HTTPException(
            status_code=500,
            detail="Assessment could not be recorded in the audit log.",
        ) from exc

    return response


@router.post("/analyze")
async def analyze_ransomware_evidence(
    request: Request,
) -> dict[str, Any]:
    """
    Assess externally supplied static ransomware-indicator evidence.

    Enforces the JSON size limit while receiving the request body,
    before parsing it into a Pydantic model.
    """

    content_type = request.headers.get(
        "content-type",
        "",
    ).split(";", 1)[0].strip().lower()

    if (
        content_type != "application/json"
        and not content_type.endswith("+json")
    ):
        raise HTTPException(
            status_code=415,
            detail="Content-Type must be application/json.",
        )

    _validate_content_length(
        request,
        MAX_REQUEST_BYTES,
    )

    body = bytearray()

    async for chunk in request.stream():
        body.extend(chunk)

        if len(body) > MAX_REQUEST_BYTES:
            raise HTTPException(
                status_code=413,
                detail="Ransomware evidence request exceeds the size limit.",
            )

    try:
        validated_request = (
            RansomwareAssessmentRequest.model_validate_json(
                bytes(body)
            )
        )

    except ValidationError as exc:
        raise RequestValidationError(
            exc.errors()
        ) from exc

    return _complete_assessment(
        evidence=validated_request.evidence,
        expected_artifact_sha256=(
            validated_request.expected_artifact_sha256
        ),
    )


@router.post("/scan")
async def scan_uploaded_firmware(
    request: Request,
    expected_artifact_sha256: str = Query(
        ...,
        min_length=64,
        max_length=64,
        description="Expected SHA-256 hash of the uploaded firmware.",
    ),
) -> dict[str, Any]:
    """
    Receive raw firmware bytes, scan them using YARA, and assess findings.

    Request body: raw binary firmware.
    Query parameter: expected_artifact_sha256.

    The temporary upload is deleted after assessment.
    """

    if not re.fullmatch(
        r"[0-9a-fA-F]{64}",
        expected_artifact_sha256,
    ):
        raise HTTPException(
            status_code=422,
            detail="Expected artifact SHA-256 must contain 64 hexadecimal characters.",
        )

    content_type = request.headers.get(
        "content-type",
        "",
    ).split(";", 1)[0].strip().lower()

    if content_type != "application/octet-stream":
        raise HTTPException(
            status_code=415,
            detail="Content-Type must be application/octet-stream.",
        )

    _validate_content_length(
        request,
        MAX_UPLOAD_BYTES,
    )

    # Limit the number of simultaneous uploads and scans
    # within this application process.
    if not _SCAN_SLOTS.acquire(blocking=False):
        raise HTTPException(
            status_code=503,
            detail="Scanner capacity is currently full. Please retry later.",
            headers={"Retry-After": "5"},
        )

    try:
        # Use a temporary directory so uploaded firmware is not retained.
        with tempfile.TemporaryDirectory(
            prefix="spectra-yara-upload-"
        ) as temporary_directory:

            artifact_path = os.path.join(
                temporary_directory,
                "firmware.bin",
            )

            total_bytes = 0

            try:
                with open(artifact_path, "wb") as artifact:
                    async for chunk in request.stream():

                        if not chunk:
                            continue

                        total_bytes += len(chunk)

                        if total_bytes > MAX_UPLOAD_BYTES:
                            raise HTTPException(
                                status_code=413,
                                detail=(
                                    "Firmware upload exceeds the "
                                    "64 MiB size limit."
                                ),
                            )

                        artifact.write(chunk)

            except HTTPException:
                raise

            except OSError as exc:
                raise HTTPException(
                    status_code=500,
                    detail="Could not store the temporary firmware upload.",
                ) from exc

            if total_bytes == 0:
                raise HTTPException(
                    status_code=422,
                    detail="Uploaded firmware file is empty.",
                )

            # Run synchronous YARA scanning in a worker thread.
            # This prevents the scan from blocking the async event loop.
            scanner_call = partial(
                scan_file,
                file_path=artifact_path,
                max_file_size_bytes=MAX_UPLOAD_BYTES,
                data_provenance=YARA_UPLOAD_PROVENANCE,
            )

            try:
                evidence = await run_in_threadpool(
                    scanner_call
                )

            except (ValueError, RuntimeError, OSError) as exc:
                # Avoid exposing internal scanner or filesystem details.
                raise HTTPException(
                    status_code=503,
                    detail=(
                        "Static firmware scanning could not be completed. "
                        "Check scanner configuration and retry."
                    ),
                ) from exc

            # The assessment engine independently verifies the
            # scanned artifact hash against the caller-supplied hash.
            return _complete_assessment(
                evidence=evidence,
                expected_artifact_sha256=expected_artifact_sha256,
            )

    finally:
        # Always release capacity, including when upload or scanning fails.
        _SCAN_SLOTS.release()
