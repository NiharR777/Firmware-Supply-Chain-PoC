from fastapi.testclient import TestClient

from src.supply_chain.api.app import app


client = TestClient(app)


# =========================================================
# HEALTH TEST
# =========================================================

def test_health_endpoint():
    """
    Verify that the API is running correctly.
    """

    response = client.get("/health")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "healthy"
    assert data["data_provenance"] == "SYNTHETIC"


# =========================================================
# ROOT TEST
# =========================================================

def test_root_endpoint():
    """
    Verify the API information endpoint.
    """

    response = client.get("/")

    assert response.status_code == 200

    data = response.json()

    assert data["project"] == "Spectra AI"
    assert data["system"] == (
        "Refinery Firmware Supply Chain PoC"
    )
    assert data["environment"] == "SYNTHETIC"
    assert "/docs" == data["documentation"]


# =========================================================
# SCENARIOS TEST
# =========================================================

def test_scenarios_endpoint():
    """
    Verify that all ten refinery scenarios are exposed.
    """

    response = client.get("/scenarios")

    assert response.status_code == 200

    data = response.json()

    assert data["total_scenarios"] == 10
    assert data["data_provenance"] == "SYNTHETIC"

    scenarios = data["scenarios"]

    assert len(scenarios) == 10

    scenario_ids = {
        scenario["scenario_id"]
        for scenario in scenarios
    }

    expected_ids = {
        f"SC-{number:03d}"
        for number in range(1, 11)
    }

    assert scenario_ids == expected_ids


# =========================================================
# SINGLE SCENARIO TEST
# =========================================================

def test_single_scenario_endpoint():
    """
    Verify retrieval of one refinery scenario.
    """

    response = client.get(
        "/scenarios/SC-006"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["scenario_id"] == "SC-006"
    assert data["package_id"] == "PKG-002"
    assert data["risk_level"] == "investigate"
    assert data["risk_score"] == 15
    assert data["deployment_allowed"] is False
    assert data["human_approval_required"] is True
    assert data["real_action_executed"] is False


# =========================================================
# UNKNOWN SCENARIO TEST
# =========================================================

def test_unknown_scenario_returns_404():
    """
    Unknown scenarios must return HTTP 404.
    """

    response = client.get(
        "/scenarios/SC-999"
    )

    assert response.status_code == 404


# =========================================================
# FINAL ASSESSMENT TEST
# =========================================================

def test_assessment_endpoint():
    """
    Verify the final refinery assessment summary.
    """

    response = client.get(
        "/assessment"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["total_scenarios"] == 10
    assert data["high_risk"] == 6
    assert data["investigate"] == 4
    assert data["normal"] == 0
    assert data["deployment_blocked"] == 10

    assert len(data["assessments"]) == 10


# =========================================================
# SINGLE ASSESSMENT TEST
# =========================================================

def test_single_assessment_endpoint():
    """
    Verify final assessment for one scenario.
    """

    response = client.get(
        "/assessment/SC-003"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["scenario_id"] == "SC-003"
    assert data["risk_level"] == "high_risk"
    assert data["risk_score"] == 50
    assert data["deployment_allowed"] is False
    assert data["human_approval_required"] is True
    assert data["real_action_executed"] is False


# =========================================================
# ML PREDICTION TEST
# =========================================================

def test_ml_predictions_endpoint():
    """
    Verify that ML prediction results are available.
    """

    response = client.get(
        "/ml/predictions"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["data_provenance"] == "SYNTHETIC"
    assert "predictions" in data


# =========================================================
# EVIDENCE BUNDLE TEST
# =========================================================

def test_evidence_bundle_endpoint():
    """
    Verify that a scenario evidence bundle can be retrieved.
    """

    response = client.get(
        "/evidence/SC-006"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["scenario_id"] == "SC-006"
    assert data["data_provenance"] == "SYNTHETIC"

    evidence = data["evidence"]

    assert "package" in evidence
    assert "hash_evidence" in evidence
    assert "signature_evidence" in evidence
    assert "sbom" in evidence
    assert "asset_mapping" in evidence
    assert "decision" in evidence


# =========================================================
# DEPLOYMENT SAFETY TEST
# =========================================================

def test_deployment_status_is_read_only():
    """
    The PoC must never execute a real deployment action.
    """

    response = client.get(
        "/deployment/status"
    )

    assert response.status_code == 200

    data = response.json()

    assert data["deployment_mode"] == "READ_ONLY"
    assert data["real_action_executed"] is False
    assert data["deployment_allowed"] is False
    assert data["human_approval_required"] is True

    assert len(data["blocked_scenarios"]) == 10