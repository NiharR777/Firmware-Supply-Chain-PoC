from decision_engine import evaluate_scenario


# ---------------------------------------------------------
# Expected refinery decisions
# ---------------------------------------------------------

EXPECTED_RESULTS = {

    "SC-001": "high_risk",
    "SC-002": "high_risk",
    "SC-003": "high_risk",
    "SC-004": "investigate",
    "SC-005": "high_risk",
    "SC-006": "investigate",
    "SC-007": "investigate",
    "SC-008": "high_risk",
    "SC-009": "high_risk",
    "SC-010": "investigate"
}


# ---------------------------------------------------------
# Test all scenarios
# ---------------------------------------------------------

def main():

    print()
    print("===== REFINERY SUPPLY-CHAIN SCENARIO TEST =====")

    passed = 0
    failed = 0

    for scenario_id, expected_risk in EXPECTED_RESULTS.items():

        result = evaluate_scenario(scenario_id)

        actual_risk = result["risk_level"]

        status = (
            "PASS"
            if actual_risk == expected_risk
            else "FAIL"
        )

        if status == "PASS":
            passed += 1
        else:
            failed += 1

        print()
        print(
            f"{scenario_id} | "
            f"Package: {result['package_id']} | "
            f"Expected: {expected_risk} | "
            f"Actual: {actual_risk} | "
            f"Status: {status}"
        )

        if result["reasons"]:

            for reason in result["reasons"]:

                print(
                    f"  - {reason}"
                )

    # -----------------------------------------------------
    # Final test result
    # -----------------------------------------------------

    print()
    print("===== TEST SUMMARY =====")

    print(
        f"Passed : {passed}"
    )

    print(
        f"Failed : {failed}"
    )

    if failed == 0:

        print()
        print(
            "ALL REFINERY SCENARIO TESTS PASSED."
        )

    else:

        print()
        print(
            "SOME REFINERY SCENARIO TESTS FAILED."
        )

    print()
    print("===== TEST COMPLETE =====")


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

if __name__ == "__main__":
    main()