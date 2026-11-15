from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.supply_chain.api import ransomware_assessment as ransomware_api


ARTIFACT_HASH = "a" * 64


def make_evidence() -> dict:
    return {
        "schema_version": "1.0",
        "artifact_sha256": ARTIFACT_HASH,
        "scanner_name": "DemoStaticScanner",
        "scanner_version": "1.0",
        "scan_timestamp_utc": "2026-11-15T08:00:00Z",
        "scan_mode": "static",
        "scan_completed": True,
        "data_provenance": "synthetic_test_evidence",
        "findings": [
            {
                "indicator_type": "ransom_note_artifact",
                "indicator_id": "FIND-001",
                "description": "Synthetic ransom-note indicator for testing.",
                "severity": "high",
                "confidence": 0.95,
                "validation_status": "scanner_reported",
            }
        ],
    }


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


def test_valid_ransomware_evidence_returns_review_required(
    monkeypatch,
    tmp_path,
):
    audit_path = redirect_audit_to_tmp_path(monkeypatch, tmp_path)
    client = make_client()

    response = client.post(
        "/api/ransomware-assessment/analyze",
        json={
            "expected_artifact_sha256": ARTIFACT_HASH,
            "evidence": make_evidence(),
        },
    )

    assert response.status_code == 200

    result = response.json()

    assert result["assessment_status"] == "review_required"
    assert result["finding_count"] == 1
    assert result["highest_reported_severity"] == "high"
    assert result["decision_authority"] == "HUMAN_REVIEW_REQUIRED"

    assert result["firmware_executed"] is False
    assert result["firmware_modified"] is False
    assert result["real_action_executed"] is False
    assert result["infection_confirmed"] is False

    assert result["assessment_id"]
    assert result["assessed_at_utc"]

    assert audit_path.exists()


def test_no_indicators_returns_standard_review(
    monkeypatch,
    tmp_path,
):
    redirect_audit_to_tmp_path(monkeypatch, tmp_path)
    client = make_client()

    evidence = make_evidence()
    evidence["findings"] = []

    response = client.post(
        "/api/ransomware-assessment/analyze",
        json={
            "expected_artifact_sha256": ARTIFACT_HASH,
            "evidence": evidence,
        },
    )

    assert response.status_code == 200
    assert response.json()["assessment_status"] == (
        "no_indicators_reported"
    )
    assert response.json()["finding_count"] == 0
    assert response.json()["infection_confirmed"] is False


def test_artifact_hash_mismatch_is_rejected(
    monkeypatch,
    tmp_path,
):
    redirect_audit_to_tmp_path(monkeypatch, tmp_path)
    client = make_client()

    response = client.post(
        "/api/ransomware-assessment/analyze",
        json={
            "expected_artifact_sha256": "b" * 64,
            "evidence": make_evidence(),
        },
    )

    assert response.status_code == 422
    assert "SHA-256 mismatch" in response.json()["detail"]


def test_invalid_static_evidence_is_rejected(
    monkeypatch,
    tmp_path,
):
    redirect_audit_to_tmp_path(monkeypatch, tmp_path)
    client = make_client()

    evidence = make_evidence()
    evidence["scan_mode"] = "dynamic"

    response = client.post(
        "/api/ransomware-assessment/analyze",
        json={
            "expected_artifact_sha256": ARTIFACT_HASH,
            "evidence": evidence,
        },
    )

    assert response.status_code == 422
    assert "Only static analysis" in response.json()["detail"]


def test_unexpected_top_level_field_is_rejected():
    client = make_client()

    response = client.post(
        "/api/ransomware-assessment/analyze",
        json={
            "expected_artifact_sha256": ARTIFACT_HASH,
            "evidence": make_evidence(),
            "infection_confirmed": True,
        },
    )

    assert response.status_code == 422


def test_audit_does_not_store_artifact_hash_or_full_evidence(
    monkeypatch,
    tmp_path,
):
    audit_path = redirect_audit_to_tmp_path(monkeypatch, tmp_path)
    client = make_client()

    response = client.post(
        "/api/ransomware-assessment/analyze",
        json={
            "expected_artifact_sha256": ARTIFACT_HASH,
            "evidence": make_evidence(),
        },
    )

    assert response.status_code == 200

    audit_text = audit_path.read_text(encoding="utf-8")
    audit_event = json.loads(audit_text.strip())

    assert audit_event["event"] == (
        "ransomware_static_assessment_completed"
    )
    assert audit_event["finding_count"] == 1
    assert ARTIFACT_HASH not in audit_text
    assert "FIND-001" not in audit_text
    assert "Synthetic ransom-note indicator" not in audit_text