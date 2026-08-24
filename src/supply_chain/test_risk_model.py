from risk_model import calculate_risk_score


print("===== RISK MODEL TEST =====")

test_cases = [
    {
        "name": "Clean package",
        "factors": []
    },
    {
        "name": "Hash mismatch",
        "factors": ["hash_integrity_failure"]
    },
    {
        "name": "Invalid signature",
        "factors": ["signature_failure"]
    },
    {
        "name": "Missing SBOM",
        "factors": ["missing_sbom"]
    },
    {
        "name": "Hash + signature failure",
        "factors": [
            "hash_integrity_failure",
            "signature_failure"
        ]
    }
]


for test in test_cases:

    result = calculate_risk_score(
        test["factors"]
    )

    print()
    print(f"Scenario : {test['name']}")
    print(f"Factors  : {test['factors']}")
    print(f"Score    : {result['risk_score']}")
    print(f"Risk     : {result['risk_level']}")
    print(f"Breakdown: {result['breakdown']}")


print()
print("===== RISK MODEL TEST COMPLETE =====")