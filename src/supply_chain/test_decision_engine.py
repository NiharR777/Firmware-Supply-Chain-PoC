import json
from pathlib import Path

import pytest

from src.supply_chain.decision_engine import (
    evaluate_scenario,
)


BASE_DIR = Path(
    "data/synthetic/supply_chain_poc"
)

EVIDENCE_DIR = (
    BASE_DIR
    / "generated"
    / "evidence_bundles"
)


EXPECTED_RISK = {
    "SC-001": "high_risk",
    "SC-002": "high_risk",
    "SC-003": "high_risk",
    "SC-004": "investigate",
    "SC-005": "high_risk",
    "SC-006": "investigate",
    "SC-007": "investigate",
    "SC-008": "high_risk",
    "SC-009": "high_risk",
    "SC-010": "investigate",
}


@pytest.mark.parametrize(
    "scenario_id,expected",
    EXPECTED_RISK.items(),
)
def test_expected_risk_level(
    scenario_id,
    expected,
):

    result = evaluate_scenario(
        scenario_id
    )

    assert result["risk_level"] == expected


@pytest.mark.parametrize(
    "scenario_id",
    [
        f"SC-{number:03d}"
        for number in range(1, 11)
    ],
)
def test_safety_invariants(
    scenario_id,
):

    result = evaluate_scenario(
        scenario_id
    )

    assert result[
        "human_approval_required"
    ] is True

    assert result[
        "deployment_allowed"
    ] is False

    assert result[
        "real_action_executed"
    ] is False


@pytest.mark.parametrize(
    "scenario_id",
    [
        f"SC-{number:03d}"
        for number in range(1, 11)
    ],
)
def test_result_contract(
    scenario_id,
):

    result = evaluate_scenario(
        scenario_id
    )

    required_fields = {
        "scenario_id",
        "package_id",
        "risk_score",
        "risk_level",
        "risk_factors",
        "risk_breakdown",
        "recommendation",
        "reasons",
        "affected_asset",
        "human_approval_required",
        "deployment_allowed",
        "real_action_executed",
    }

    assert required_fields.issubset(
        result.keys()
    )


def test_hash_mismatch_is_evidence_driven():

    result = evaluate_scenario(
        "SC-001"
    )

    assert (
        "hash_integrity_failure"
        in result["risk_factors"]
    )


def test_vulnerability_is_evidence_driven():

    result = evaluate_scenario(
        "SC-004"
    )

    assert (
        "vulnerable_component"
        in result["risk_factors"]
    )


def test_rollback_is_evidence_driven():

    result = evaluate_scenario(
        "SC-005"
    )

    assert (
        "unauthorized_rollback"
        in result["risk_factors"]
    )


def test_vendor_substitution_is_evidence_driven():

    result = evaluate_scenario(
        "SC-008"
    )

    assert (
        "untrusted_vendor"
        in result["risk_factors"]
    )


def test_stale_evidence_is_evidence_driven():

    result = evaluate_scenario(
        "SC-010"
    )

    assert (
        "stale_evidence"
        in result["risk_factors"]
    )


def test_no_answer_leakage_in_package_input():

    forbidden = {
        "scenario_type",
        "expected_decision",
        "risk_target",
        "target",
        "label",
        "ground_truth",
    }

    for number in range(1, 11):

        scenario_id = (
            f"SC-{number:03d}"
        )

        bundle = (
            EVIDENCE_DIR
            / scenario_id
        )

        for filename in [
            "package.json",
            "hash_evidence.json",
            "signature_evidence.json",
            "sbom.json",
            "rollback_evidence.json",
            "vendor_evidence.json",
            "freshness_evidence.json",
            "asset_mapping.json",
        ]:

            path = bundle / filename

            assert path.exists()

            data = json.loads(
                path.read_text(
                    encoding="utf-8"
                )
            )

            assert forbidden.isdisjoint(
                data.keys()
            )


def test_hash_files_reproduce():

    import hashlib

    for scenario_id in [
        "SC-001",
        "SC-002",
    ]:

        evidence_file = (
            EVIDENCE_DIR
            / scenario_id
            / "hash_evidence.json"
        )

        evidence = json.loads(
            evidence_file.read_text(
                encoding="utf-8"
            )
        )

        for key in [
            "expected_package_path",
            "observed_package_path",
        ]:

            path = Path(
                evidence[key]
            )

            assert path.exists()

            digest = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()

            if key == "expected_package_path":
                assert digest == evidence[
                    "expected_hash"
                ]
            else:
                assert digest == evidence[
                    "observed_hash"
                ]

    assert (
        json.loads(
            (
                EVIDENCE_DIR
                / "SC-001"
                / "hash_evidence.json"
            ).read_text(
                encoding="utf-8"
            )
        )["hash_match"]
        is False
    )


def test_sc004_uses_cyclonedx():

    path = (
        EVIDENCE_DIR
        / "SC-004"
        / "sbom.json"
    )

    sbom = json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )

    assert sbom["sbom_format"] == "CycloneDX"
    assert sbom["spec_version"] == "1.5"
    assert sbom["sbom_present"] is True