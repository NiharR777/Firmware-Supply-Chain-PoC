"""
Explainable Risk Scoring Model
Firmware Supply-Chain PoC
"""

# Risk weights are based on security impact, not probability.
# A failed integrity/authenticity control is treated more severely
# than an evidence-quality issue.

RISK_WEIGHTS = {
    "hash_integrity_failure": 40,
    "signature_failure": 30,
    "trusted_root_failure": 20,
    "untrusted_vendor": 40,
    "unauthorized_rollback": 40,
    "vulnerable_component": 20,
    "unexpected_component": 20,
    "missing_sbom": 15,
    "stale_evidence": 10,
}


def calculate_risk_score(risk_factors):
    """
    Calculate an explainable risk score from detected risk factors.

    risk_factors should be a list of factor names.
    """

    score = 0
    breakdown = []

    for factor in risk_factors:
        weight = RISK_WEIGHTS.get(factor, 0)

        if weight > 0:
            score += weight

            breakdown.append({
                "factor": factor,
                "weight": weight
            })

    # Keep the score within 0-100.
    score = min(score, 100)

    if score >= 40:
        risk_level = "high_risk"
    elif score > 0:
        risk_level = "investigate"
    else:
        risk_level = "normal"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "breakdown": breakdown
    }