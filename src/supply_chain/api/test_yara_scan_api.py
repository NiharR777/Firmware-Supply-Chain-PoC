
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.supply_chain.api import ransomware_assessment as ransomware_api


def make_client() -> TestClient:
    app = FastAPI()
    app.include_router(ransomware_api.router)
    return TestClient(app)


def redirect_audit_to_tmp_path(monkeypatch, tmp_path):
    project_root = tmp_path / "test_project"

    fake_module_path = (
        project_root
        / "src"
        / "supply_chain"
        / "api"
        / "ransomware_assessment.py"
    )

    class FakePath:
        def __init__(self, value):
            self.value = value

        def resolve(self):
            return fake_module_path

    monkeypatch.setattr(ransomware_api, "Path", FakePath)

    return project_root / "artifacts" / "dashboard" / "audit.jsonl"


def upload_firmware(client, content: bytes, expected_hash: str):
    return client.post(
        "/api/ransomware-assessment/scan",
        params={"expected_artifact_sha256": expected_hash},
        content=content,
        headers={"Content-Type": "application/octet-stream"},
    )


# ---------------------------------------------------------
# Existing tests
# ---------------------------------------------------------


def test_yara_upload_detects_synthetic_ransom_note(
    monkeypatch,
    tmp_path,
):
    redirect_audit_to_tmp_path(monkeypatch, tmp_path)

    client = make_client()

    firmware = b"SYNTHETIC_RANSOM_NOTE_MARKER"
    expected_hash = hashlib.sha256(firmware).hexdigest()

    response = upload_firmware(client, firmware, expected_hash)

    assert response.status_code == 200

    result = response.json()

    assert result["assessment_status"] == "review_required"
    assert result["finding_count"] == 1
    assert result["highest_reported_severity"] == "high"

    assert result["decision_authority"] == "HUMAN_REVIEW_REQUIRED"
    assert result["infection_confirmed"] is False
    assert result["firmware_executed"] is False
    assert result["firmware_modified"] is False
    assert result["real_action_executed"] is False


def test_clean_firmware_upload_reports_no_indicators(
    monkeypatch,
    tmp_path,
):
    redirect_audit_to_tmp_path(monkeypatch, tmp_path)

    client = make_client()

    firmware = b"BENIGN_SYNTHETIC_FIRMWARE_FIXTURE"
    expected_hash = hashlib.sha256(firmware).hexdigest()

    response = upload_firmware(client, firmware, expected_hash)

    assert response.status_code == 200

    result = response.json()

    assert result["assessment_status"] == "no_indicators_reported"
    assert result["finding_count"] == 0
    assert result["infection_confirmed"] is False


def test_upload_hash_mismatch_is_rejected(
    monkeypatch,
    tmp_path,
):
    redirect_audit_to_tmp_path(monkeypatch, tmp_path)

    client = make_client()

    firmware = b"SYNTHETIC_RANSOM_NOTE_MARKER"

    response = upload_firmware(client, firmware, "b" * 64)

    assert response.status_code == 422
    assert "SHA-256 mismatch" in response.json()["detail"]


def test_empty_firmware_upload_is_rejected():
    client = make_client()

    response = upload_firmware(client, b"", "a" * 64)

    assert response.status_code == 422
    assert "empty" in response.json()["detail"].lower()


def test_oversized_firmware_upload_is_rejected(monkeypatch):
    monkeypatch.setattr(ransomware_api, "MAX_UPLOAD_BYTES", 8)

    client = make_client()

    response = upload_firmware(client, b"A" * 9, "a" * 64)

    assert response.status_code == 413
    assert "size limit" in response.json()["detail"].lower()


def test_upload_audit_does_not_store_hash_or_finding_details(
    monkeypatch,
    tmp_path,
):
    audit_path = redirect_audit_to_tmp_path(monkeypatch, tmp_path)

    client = make_client()

    firmware = b"SYNTHETIC_RANSOM_NOTE_MARKER"
    expected_hash = hashlib.sha256(firmware).hexdigest()

    response = upload_firmware(client, firmware, expected_hash)

    assert response.status_code == 200
    assert audit_path.exists()

    audit_text = Path(audit_path).read_text(encoding="utf-8")
    audit_event = json.loads(audit_text.strip())

    assert audit_event["event"] == (
        "ransomware_static_assessment_completed"
    )

    assert audit_event["finding_count"] == 1
    assert expected_hash not in audit_text
    assert "SYNTHETIC_RANSOM_NOTE_MARKER" not in audit_text
    assert "YARA-Synthetic_Ransom_Note" not in audit_text


# ---------------------------------------------------------
# New API hardening tests
# ---------------------------------------------------------


def test_upload_rejects_incorrect_content_type():
    client = make_client()

    firmware = b"BENIGN_SYNTHETIC_FIRMWARE_FIXTURE"
    expected_hash = hashlib.sha256(firmware).hexdigest()

    response = client.post(
        "/api/ransomware-assessment/scan",
        params={"expected_artifact_sha256": expected_hash},
        content=firmware,
        headers={"Content-Type": "text/plain"},
    )

    assert response.status_code == 415
    assert "Content-Type" in response.json()["detail"]


def test_scan_is_rejected_when_concurrency_limit_is_reached():
    client = make_client()

    firmware = b"BENIGN_SYNTHETIC_FIRMWARE_FIXTURE"
    expected_hash = hashlib.sha256(firmware).hexdigest()

    first_slot = ransomware_api._SCAN_SLOTS.acquire(blocking=False)
    second_slot = ransomware_api._SCAN_SLOTS.acquire(blocking=False)

    assert first_slot is True
    assert second_slot is True

    try:
        response = upload_firmware(
            client,
            firmware,
            expected_hash,
        )

        assert response.status_code == 503
        assert response.headers["Retry-After"] == "5"
        assert "capacity" in response.json()["detail"].lower()

    finally:
        ransomware_api._SCAN_SLOTS.release()
        ransomware_api._SCAN_SLOTS.release()


def test_scanner_failure_returns_safe_service_error(
    monkeypatch,
    tmp_path,
):
    redirect_audit_to_tmp_path(monkeypatch, tmp_path)

    def failing_scanner(*args, **kwargs):
        raise RuntimeError("INTERNAL_SCANNER_SECRET")

    monkeypatch.setattr(
        ransomware_api,
        "scan_file",
        failing_scanner,
    )

    client = make_client()

    firmware = b"BENIGN_SYNTHETIC_FIRMWARE_FIXTURE"
    expected_hash = hashlib.sha256(firmware).hexdigest()

    response = upload_firmware(
        client,
        firmware,
        expected_hash,
    )

    assert response.status_code == 503
    assert "INTERNAL_SCANNER_SECRET" not in response.text

    # Confirm that the failed scan released its semaphore slot.
    slot_available = ransomware_api._SCAN_SLOTS.acquire(
        blocking=False
    )

    assert slot_available is True

    if slot_available:
        ransomware_api._SCAN_SLOTS.release()


def test_oversized_json_evidence_request_is_rejected(monkeypatch):
    monkeypatch.setattr(
        ransomware_api,
        "MAX_REQUEST_BYTES",
        8,
    )

    client = make_client()

    oversized_json = (
        b'{"padding":"' + b"A" * 64 + b'"}'
    )

    response = client.post(
        "/api/ransomware-assessment/analyze",
        content=oversized_json,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert "size limit" in response.json()["detail"].lower()
