import pytest

from src.supply_chain.risk_model import calculate_risk_score


@pytest.mark.parametrize(
    "factors,score,level",
    [
        ([], 0, "normal"),
        (["hash_integrity_failure"], 40, "high_risk"),
        (["signature_failure"], 30, "investigate"),
        (["missing_sbom"], 15, "investigate"),
        (["unauthorized_rollback"], 40, "high_risk"),
        (["hash_integrity_failure", "signature_failure"], 70, "high_risk"),
    ],
)
def test_risk_score_contract(factors, score, level):
    result = calculate_risk_score(factors)
    assert result["risk_score"] == score
    assert result["risk_level"] == level
    assert [row["factor"] for row in result["breakdown"]] == factors


def test_risk_score_is_capped_at_100():
    result = calculate_risk_score([
        "hash_integrity_failure",
        "signature_failure",
        "trusted_root_failure",
        "untrusted_vendor",
    ])
    assert result["risk_score"] == 100
    assert result["risk_level"] == "high_risk"
