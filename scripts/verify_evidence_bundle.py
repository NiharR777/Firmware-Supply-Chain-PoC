"""Assertion-based standalone verification of all ten evidence bundles."""

import hashlib
import json
from pathlib import Path


BASE = Path("data/synthetic/supply_chain_poc/generated/evidence_bundles")
EXPECTED_RISK = {
    "SC-001": ("high_risk", "hash_integrity_failure"),
    "SC-002": ("high_risk", "hash_integrity_failure"),
    "SC-003": ("high_risk", "signature_failure"),
    "SC-004": ("investigate", "vulnerable_component"),
    "SC-005": ("high_risk", "unauthorized_rollback"),
    "SC-006": ("investigate", "missing_sbom"),
    "SC-007": ("investigate", "unexpected_component"),
    "SC-008": ("high_risk", "untrusted_vendor"),
    "SC-009": ("high_risk", "unauthorized_rollback"),
    "SC-010": ("investigate", "stale_evidence"),
}
FORBIDDEN = {
    "scenario_type", "expected_decision", "risk_target", "target", "label", "ground_truth",
}


def load(bundle: Path, name: str) -> dict:
    path = bundle / name
    assert path.exists(), f"Missing evidence file: {path}"
    return json.loads(path.read_text(encoding="utf-8"))


def collect_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        keys = set(value)
        for child in value.values():
            keys.update(collect_keys(child))
        return keys
    if isinstance(value, list):
        keys: set[str] = set()
        for child in value:
            keys.update(collect_keys(child))
        return keys
    return set()


def verify_bundle(scenario_id: str) -> None:
    bundle = BASE / scenario_id
    filenames = [
        "package.json", "reference_evidence.json", "hash_evidence.json",
        "signature_evidence.json", "sbom.json", "asset_mapping.json",
        "rollback_evidence.json", "vendor_evidence.json", "freshness_evidence.json",
    ]
    evidence = {name: load(bundle, name) for name in filenames}
    decision = load(bundle, "decision.json")
    for name, data in evidence.items():
        assert FORBIDDEN.isdisjoint(collect_keys(data)), f"Answer leakage in {scenario_id}/{name}"

    expected_level, expected_factor = EXPECTED_RISK[scenario_id]
    assert decision["risk_level"] == expected_level
    assert expected_factor in decision["risk_factors"]
    assert decision["deployment_allowed"] is False
    assert decision["human_approval_required"] is True
    assert decision["real_action_executed"] is False

    if scenario_id in {"SC-001", "SC-002"}:
        reference = evidence["reference_evidence.json"]
        observed = evidence["hash_evidence.json"]
        trusted_path = Path(reference["trusted_package_path"])
        observed_path = Path(observed["observed_package_path"])
        assert trusted_path.exists() and observed_path.exists() and trusted_path != observed_path
        trusted_hash = hashlib.sha256(trusted_path.read_bytes()).hexdigest()
        observed_hash = hashlib.sha256(observed_path.read_bytes()).hexdigest()
        assert trusted_hash == reference["trusted_sha256"]
        assert observed_hash == observed["observed_hash"]
        assert trusted_hash != observed_hash
        assert observed["hash_match"] is False


def main() -> None:
    for scenario_id in EXPECTED_RISK:
        verify_bundle(scenario_id)
        print(f"{scenario_id} evidence bundle verification PASSED")


if __name__ == "__main__":
    main()
