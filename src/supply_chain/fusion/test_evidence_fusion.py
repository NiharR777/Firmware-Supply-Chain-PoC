import pytest

from src.supply_chain.fusion.evidence_fusion import fuse_evidence


@pytest.mark.parametrize("scenario_id", [f"SC-{number:03d}" for number in range(1, 11)])
def test_fused_evidence_contract(scenario_id):
    result = fuse_evidence(scenario_id)
    assert result["scenario_id"] == scenario_id
    assert result["package_id"]
    assert result["asset_id"]
    assert result["risk_level"] in {"normal", "investigate", "high_risk"}
    assert result["human_approval_required"] is True
    assert result["deployment_allowed"] is False
    assert result["real_action_executed"] is False
    assert "reference_evidence.json" in result["evidence_sources"]


def test_fused_hash_failure_is_observed():
    result = fuse_evidence("SC-001")
    assert result["hash_status"] == "failed"
    assert "hash_integrity_failure" in result["risk_factors"]


def test_fused_staleness_uses_freshness_evidence():
    assert fuse_evidence("SC-010")["evidence_freshness"] == "stale"
