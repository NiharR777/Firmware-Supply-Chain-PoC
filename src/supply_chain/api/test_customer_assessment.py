from __future__ import annotations

import json

from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.supply_chain.api import customer_assessment as customer_api


FIRMWARE_HASH = "a" * 64
BASELINE_HASH = "a" * 64


def make_cyclonedx() -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "firmware",
                "name": "Demo Industrial Controller",
                "version": "3.1.0",
            }
        },
        "components": [
            {
                "type": "library",
                "name": "openssl",
                "version": "1.0.2u",
                "purl": "pkg:generic/openssl@1.0.2u",
            },
            {
                "type": "library",
                "name": "zlib",
                "version": "1.2.13",
                "purl": "pkg:generic/zlib@1.2.13",
            },
        ],
    }


def make_spdx() -> dict:
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Demo Industrial Controller",
        "packages": [
            {
                "name": "openssl",
                "versionInfo": "1.0.2u",
                "SPDXID": "SPDXRef-Package-OpenSSL",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:generic/openssl@1.0.2u",
                    }
                ],
            }
        ],
    }


def make_payload(
    sbom: dict | None = None,
    **overrides,
) -> dict:
    payload = {
        "industry": "industrial",
        "customer_name": "Demo Customer",
        "product_name": "Demo Industrial Controller",
        "firmware_version": "3.1.0",
        "firmware_sha256": FIRMWARE_HASH,
        "approved_baseline_sha256": BASELINE_HASH,
        "approved_baseline_version": "3.1.0",
        "sbom": sbom if sbom is not None else make_cyclonedx(),
        "provenance_source": "synthetic_test_evidence",
        "supplier_name": "Demo Supplier",
    }
    payload.update(overrides)
    return payload


def make_client() -> TestClient:
    app = FastAPI()
    app.include_router(customer_api.router)
    return TestClient(app)


def mock_nvd_success(monkeypatch):
    monkeypatch.setattr(
        customer_api,
        "search_components",
        lambda components, max_components=3: {
            "provider": "NVD API 2.0",
            "is_live_source": True,
            "components_checked": min(
                len(components),
                max_components,
            ),
            "components_skipped": max(
                0,
                len(components) - max_components,
            ),
            "findings_count": 0,
            "findings": [],
            "component_results": [],
            "errors": [],
            "applicability_note": (
                "NVD keyword results are candidate CVEs only."
            ),
        },
    )


def redirect_audit_to_tmp_path(monkeypatch, tmp_path):
    project_root = tmp_path / "test_project"
    fake_module_path = (
        project_root
        / "src"
        / "supply_chain"
        / "api"
        / "customer_assessment.py"
    )

    class FakePath:
        def __init__(self, value):
            self.value = value

        def resolve(self):
            return fake_module_path

    monkeypatch.setattr(customer_api, "Path", FakePath)

    return (
        project_root
        / "artifacts"
        / "dashboard"
        / "audit.jsonl"
    )


def test_cyclonedx_assessment_returns_expected_result(
    monkeypatch,
    tmp_path,
):
    mock_nvd_success(monkeypatch)
    audit_path = redirect_audit_to_tmp_path(monkeypatch, tmp_path)

    response = make_client().post(
        "/api/customer-assessment/analyze",
        json=make_payload(),
    )

    assert response.status_code == 200

    result = response.json()

    assert result["sbom_format"] == "CycloneDX"
    assert result["component_count"] == 2
    assert result["components_with_name_and_version"] == 2
    assert result["completeness"] == "complete"
    assert result["product_mapping"]["mapped"] is True
    assert result["baseline_comparison"]["status"] == "match"

    assert result["vulnerability_matching"]["catalog_is_live"] is False
    assert result["vulnerability_matching"]["findings_count"] == 1

    finding = result["vulnerability_matching"]["findings"][0]
    assert finding["demo_id"] == "DEMO-VULN-001"
    assert finding["component"] == "openssl"
    assert finding["severity"] == "critical"

    assert result["human_review_required"] is True
    assert result["deployment_allowed"] is False
    assert result["real_action_executed"] is False

    assert result["assessment_id"].startswith("CUST-")
    assert result["sbom_sha256"]
    assert audit_path.exists()


def test_spdx_assessment_extracts_packages_and_purl(
    monkeypatch,
    tmp_path,
):
    mock_nvd_success(monkeypatch)
    redirect_audit_to_tmp_path(monkeypatch, tmp_path)

    response = make_client().post(
        "/api/customer-assessment/analyze",
        json=make_payload(sbom=make_spdx()),
    )

    assert response.status_code == 200

    result = response.json()

    assert result["sbom_format"] == "SPDX"
    assert result["component_count"] == 1
    assert result["completeness"] == "complete"
    assert result["product_mapping"]["mapped"] is True

    finding = result["vulnerability_matching"]["findings"][0]
    assert finding["component"] == "openssl"
    assert finding["purl"] == "pkg:generic/openssl@1.0.2u"


def test_baseline_mismatch_requires_release_hold_review(
    monkeypatch,
    tmp_path,
):
    mock_nvd_success(monkeypatch)
    redirect_audit_to_tmp_path(monkeypatch, tmp_path)

    payload = make_payload(
        approved_baseline_sha256="b" * 64,
    )

    response = make_client().post(
        "/api/customer-assessment/analyze",
        json=payload,
    )

    assert response.status_code == 200

    result = response.json()

    assert result["baseline_comparison"]["status"] == "mismatch"
    assert result["recommendation"] == "release_hold_review"
    assert result["risk"]["score"] == 70
    assert result["risk"]["level"] == "critical"
    assert result["deployment_allowed"] is False


def test_matching_baseline_uses_firmware_hash(
    monkeypatch,
    tmp_path,
):
    mock_nvd_success(monkeypatch)
    redirect_audit_to_tmp_path(monkeypatch, tmp_path)

    response = make_client().post(
        "/api/customer-assessment/analyze",
        json=make_payload(
            approved_baseline_sha256=FIRMWARE_HASH.upper(),
        ),
    )

    assert response.status_code == 200
    assert response.json()["baseline_comparison"]["status"] == "match"


def test_invalid_baseline_sha256_is_rejected(
    monkeypatch,
    tmp_path,
):
    mock_nvd_success(monkeypatch)
    redirect_audit_to_tmp_path(monkeypatch, tmp_path)

    response = make_client().post(
        "/api/customer-assessment/analyze",
        json=make_payload(approved_baseline_sha256="invalid"),
    )

    assert response.status_code == 422
    assert "64 hexadecimal characters" in response.json()["detail"]


def test_invalid_firmware_sha256_is_rejected():
    response = make_client().post(
        "/api/customer-assessment/analyze",
        json=make_payload(firmware_sha256="invalid"),
    )

    assert response.status_code == 422


def test_oversized_sbom_is_rejected(
    monkeypatch,
    tmp_path,
):
    mock_nvd_success(monkeypatch)
    redirect_audit_to_tmp_path(monkeypatch, tmp_path)

    oversized_sbom = {
        "bomFormat": "CycloneDX",
        "components": [],
        "large_test_field": "x" * (2 * 1024 * 1024),
    }

    response = make_client().post(
        "/api/customer-assessment/analyze",
        json=make_payload(sbom=oversized_sbom),
    )

    assert response.status_code == 413
    assert "2 MB" in response.json()["detail"]


def test_unsupported_sbom_format_is_rejected(
    monkeypatch,
    tmp_path,
):
    mock_nvd_success(monkeypatch)
    redirect_audit_to_tmp_path(monkeypatch, tmp_path)

    response = make_client().post(
        "/api/customer-assessment/analyze",
        json=make_payload(
            sbom={"format": "UNKNOWN", "components": []},
        ),
    )

    assert response.status_code == 422
    assert "Unsupported SBOM" in response.json()["detail"]


def test_missing_provenance_marks_assessment_incomplete(
    monkeypatch,
    tmp_path,
):
    mock_nvd_success(monkeypatch)
    redirect_audit_to_tmp_path(monkeypatch, tmp_path)

    response = make_client().post(
        "/api/customer-assessment/analyze",
        json=make_payload(
            provenance_source="",
            supplier_name="",
        ),
    )

    assert response.status_code == 200

    result = response.json()

    assert result["completeness"] == "incomplete"
    assert result["provenance"]["status"] == "incomplete"
    assert any(
        "Missing provenance fields" in warning
        for warning in result["warnings"]
    )


def test_nvd_failure_does_not_crash_assessment(
    monkeypatch,
    tmp_path,
):
    monkeypatch.setattr(
        customer_api,
        "search_components",
        lambda components, max_components=3: {
            "provider": "NVD API 2.0",
            "is_live_source": True,
            "components_checked": len(components[:max_components]),
            "components_skipped": 0,
            "findings_count": 0,
            "findings": [],
            "component_results": [],
            "errors": [
                {
                    "component": "openssl",
                    "status": "unavailable",
                    "reason": "Test connection failure.",
                }
            ],
        },
    )

    redirect_audit_to_tmp_path(monkeypatch, tmp_path)

    response = make_client().post(
        "/api/customer-assessment/analyze",
        json=make_payload(),
    )

    assert response.status_code == 200

    result = response.json()

    assert result["vulnerability_matching"]["live_nvd"]["errors"]
    assert result["human_review_required"] is True
    assert result["deployment_allowed"] is False


def test_audit_records_are_separate_json_lines_and_private(
    monkeypatch,
    tmp_path,
):
    mock_nvd_success(monkeypatch)
    audit_path = redirect_audit_to_tmp_path(monkeypatch, tmp_path)
    client = make_client()

    first = client.post(
        "/api/customer-assessment/analyze",
        json=make_payload(),
    )
    second = client.post(
        "/api/customer-assessment/analyze",
        json=make_payload(),
    )

    assert first.status_code == 200
    assert second.status_code == 200

    audit_text = audit_path.read_text(encoding="utf-8")
    audit_lines = audit_text.splitlines()

    assert len(audit_lines) == 2

    events = [json.loads(line) for line in audit_lines]

    assert all(
        event["event"] == "customer_sbom_assessment_completed"
        for event in events
    )

    assert events[0]["assessment_id"] != events[1]["assessment_id"]

    assert FIRMWARE_HASH not in audit_text
    assert "openssl" not in audit_text
    assert "DEMO-VULN-001" not in audit_text
    assert "synthetic_test_evidence" not in audit_text

    assert all(event["deployment_allowed"] is False for event in events)
    assert all(event["real_action_executed"] is False for event in events)