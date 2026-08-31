"""
Evidence-driven deterministic decision engine.

The engine consumes OBSERVED evidence only.

Forbidden decision inputs:
- scenario_type
- expected_decision
- risk_target
- labels
- scenario descriptions
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from src.supply_chain.risk_model import calculate_risk_score


BASE_DIR = Path("data/synthetic/supply_chain_poc")

EVIDENCE_DIR = (
    BASE_DIR
    / "generated"
    / "evidence_bundles"
)


FORBIDDEN_INPUT_FIELDS = {
    "scenario_type",
    "expected_decision",
    "risk_target",
    "target",
    "label",
    "ground_truth",
}


def load_json(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(
            f"Required evidence file not found: {path}"
        )

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def _check_forbidden_fields(data: dict) -> None:
    def keys(value):
        if isinstance(value, dict):
            for key, child in value.items():
                yield key
                yield from keys(child)
        elif isinstance(value, list):
            for child in value:
                yield from keys(child)

    leaked = FORBIDDEN_INPUT_FIELDS.intersection(keys(data))

    if leaked:
        raise ValueError(
            "Forbidden answer-bearing fields found in decision input: "
            + ", ".join(sorted(leaked))
        )


def evaluate_scenario(scenario_id: str) -> dict:

    bundle_dir = EVIDENCE_DIR / scenario_id

    if not bundle_dir.exists():
        raise ValueError(
            f"Evidence bundle not found: {scenario_id}"
        )

    package = load_json(
        bundle_dir / "package.json"
    )

    reference = load_json(
        bundle_dir / "reference_evidence.json"
    )

    hash_evidence = load_json(
        bundle_dir / "hash_evidence.json"
    )

    signature = load_json(
        bundle_dir / "signature_evidence.json"
    )

    sbom = load_json(
        bundle_dir / "sbom.json"
    )

    rollback = load_json(
        bundle_dir / "rollback_evidence.json"
    )

    vendor = load_json(
        bundle_dir / "vendor_evidence.json"
    )

    freshness = load_json(
        bundle_dir / "freshness_evidence.json"
    )

    asset = load_json(
        bundle_dir / "asset_mapping.json"
    )

    # --------------------------------------------------------
    # Leakage protection
    # --------------------------------------------------------

    for evidence in [
        package,
        reference,
        hash_evidence,
        signature,
        sbom,
        rollback,
        vendor,
        freshness,
        asset,
    ]:
        _check_forbidden_fields(evidence)

    # --------------------------------------------------------
    # Risk factors
    # --------------------------------------------------------

    risk_factors = []
    reasons = []

    # --------------------------------------------------------
    # 1. Hash integrity
    # --------------------------------------------------------

    expected_hash = reference.get(
        "trusted_sha256"
    )

    observed_hash = hash_evidence.get(
        "observed_hash"
    )

    if not expected_hash or not observed_hash:
        raise ValueError(
            "Hash evidence must contain expected_hash and observed_hash."
        )

    if expected_hash != observed_hash:
        risk_factors.append(
            "hash_integrity_failure"
        )

        reasons.append(
            "Firmware package hash does not match "
            "the trusted vendor hash."
        )

    # --------------------------------------------------------
    # 2. Signature
    # --------------------------------------------------------

    if signature.get("signature_status") in {
        "invalid",
        "untrusted",
    }:

        risk_factors.append(
            "signature_failure"
        )

        reasons.append(
            "Firmware package signature is invalid "
            "or not trusted."
        )

    # --------------------------------------------------------
    # 3. Trusted root
    # --------------------------------------------------------

    if signature.get("trusted_root_status") in {
        "invalid",
        "untrusted",
    }:

        risk_factors.append(
            "trusted_root_failure"
        )

        reasons.append(
            "Firmware package is not anchored "
            "to a trusted vendor root."
        )

    # --------------------------------------------------------
    # 4. Vendor trust
    # --------------------------------------------------------

    expected_vendor = reference.get(
        "approved_vendor_id"
    )

    observed_vendor = vendor.get(
        "observed_vendor_id"
    )

    if (
        expected_vendor != observed_vendor
        or vendor.get("vendor_trust_status") == "untrusted"
    ):

        risk_factors.append(
            "untrusted_vendor"
        )

        reasons.append(
            "Firmware package is associated "
            "with an untrusted vendor."
        )

    # --------------------------------------------------------
    # 5. Rollback
    # --------------------------------------------------------

    expected_version = reference.get(
        "approved_version"
    )

    observed_version = rollback.get(
        "observed_version"
    )

    rollback_authorized = rollback.get(
        "rollback_authorized"
    )

    def version_tuple(value: str) -> tuple[int, ...]:
        numbers = re.findall(r"\d+", value or "")
        if not numbers:
            raise ValueError(f"Invalid firmware version: {value!r}")
        return tuple(int(number) for number in numbers)

    if (
        version_tuple(observed_version) < version_tuple(expected_version)
        and rollback_authorized is False
    ):

        risk_factors.append(
            "unauthorized_rollback"
        )

        reasons.append(
            "Unauthorized rollback to an older "
            "firmware version was detected."
        )

    # --------------------------------------------------------
    # 6. SBOM
    # --------------------------------------------------------

    if sbom.get("sbom_present") is False:

        risk_factors.append(
            "missing_sbom"
        )

        reasons.append(
            "SBOM evidence is missing or incomplete."
        )

    elif sbom.get("sbom_status") != "complete":

        risk_factors.append(
            "missing_sbom"
        )

        reasons.append(
            "SBOM evidence is missing or incomplete."
        )

    # --------------------------------------------------------
    # 7. Vulnerability
    # --------------------------------------------------------

    if (
        sbom.get("vulnerability_status")
        == "affected"
    ):

        risk_factors.append(
            "vulnerable_component"
        )

        reasons.append(
            "A vulnerable component affects "
            "the firmware package."
        )

    # --------------------------------------------------------
    # 8. Unexpected component
    # --------------------------------------------------------

    if sbom.get(
        "unexpected_component_observed"
    ) is True:

        risk_factors.append(
            "unexpected_component"
        )

        reasons.append(
            "An unexpected component change was "
            "detected in the firmware package."
        )

    # --------------------------------------------------------
    # 9. Evidence freshness
    # --------------------------------------------------------

    evidence_age_days = freshness.get("evidence_age_days")
    freshness_threshold_days = freshness.get("freshness_threshold_days")

    if not isinstance(evidence_age_days, int) or not isinstance(
        freshness_threshold_days, int
    ):
        raise ValueError("Freshness evidence requires integer age/threshold")

    if evidence_age_days > freshness_threshold_days:

        risk_factors.append(
            "stale_evidence"
        )

        reasons.append(
            "Security evidence is stale and requires "
            "review before deployment."
        )

    # --------------------------------------------------------
    # Risk model
    # --------------------------------------------------------

    risk_result = calculate_risk_score(
        risk_factors
    )

    risk_score = risk_result["risk_score"]
    risk_level = risk_result["risk_level"]

    # --------------------------------------------------------
    # Safety gate
    # --------------------------------------------------------

    deployment_allowed = False
    human_approval_required = True
    real_action_executed = False

    if risk_level == "normal":
        recommendation = (
            "allow_after_human_review"
        )
    elif risk_level == "high_risk":
        recommendation = (
            "quarantine_review"
        )
    else:
        recommendation = "investigate"

    # --------------------------------------------------------
    # Result
    # --------------------------------------------------------

    return {
        "scenario_id": scenario_id,
        "package_id": package.get("package_id"),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_factors": risk_factors,
        "risk_breakdown": risk_result["breakdown"],
        "recommendation": recommendation,
        "reasons": reasons,
        "affected_asset": asset.get("asset_id"),
        "asset_name": asset.get("asset_name"),
        "device_type": asset.get("device_type"),
        "process_unit": asset.get("process_unit"),
        "human_approval_required": human_approval_required,
        "deployment_allowed": deployment_allowed,
        "real_action_executed": real_action_executed,
        "data_provenance": "SYNTHETIC OBSERVED EVIDENCE",
    }


def write_decision(scenario_id: str) -> dict:

    result = evaluate_scenario(
        scenario_id
    )

    output_file = (
        EVIDENCE_DIR
        / scenario_id
        / "decision.json"
    )

    with output_file.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            result,
            file,
            indent=2,
        )

    return result


def generate_all_decisions() -> None:

    for number in range(1, 11):

        scenario_id = (
            f"SC-{number:03d}"
        )

        result = write_decision(
            scenario_id
        )

        print(
            f"{scenario_id} | "
            f"Risk: {result['risk_level']} | "
            f"Score: {result['risk_score']} | "
            f"Recommendation: "
            f"{result['recommendation']}"
        )


if __name__ == "__main__":

    print(
        "\n===== REFINERY FIRMWARE "
        "SUPPLY-CHAIN DECISION =====\n"
    )

    generate_all_decisions()

    print(
        "\n===== DECISION GENERATION COMPLETE ====="
    )
