# Firmware & Supply-Chain Assurance PoC

## About the Project

This project is a proof of concept for checking the security and trustworthiness of firmware and software packages.

The main idea is to check whether a package is genuine, properly signed, contains the expected software components, and has any known security or supply-chain issues.

The project uses synthetic data, so no real firmware or production system is affected.

## What the Project Checks

The system will check:

- Package integrity
- SHA-256 hash
- Signature and attestation
- SBOM information
- Vulnerabilities and VEX information
- Vendor and provenance details
- Package version and rollback issues
- Unexpected component changes
- Dependency impact
- Unusual package or release behaviour

## Decision

After checking the available evidence, the system will give one of these recommendations:

- Accept
- Investigate
- High Risk

The recommendation is only for review. A human must approve any action.

## Safety

This project is completely read-only and uses synthetic evidence.

It will not:

- Flash firmware
- Install software
- Delete files
- Automatically quarantine packages
- Modify real devices
- Modify production systems
- Execute destructive actions

## Machine Learning

Machine learning is not implemented in this correction release. The validated
dataset and leakage-safe feature matrix are inputs to the next stage: a
documented, grouped model-training and evaluation experiment.

When introduced, ML will remain advisory. It must not override deterministic
hard evidence such as hash, signature, trusted-root, vendor, rollback, or SBOM
failures. Rule/ML disagreement will be recorded as an investigation signal.

## Validated Dataset Contract

The synthetic dataset contains 5,000 assessments across 500 firmware package
lineages (10 assessments per lineage). Data roles are isolated:

- `reference_data.csv`: approved vendor, hash, version, freshness, and component facts
- `reference_catalog.csv`: vendor trust and component catalog
- `observable_features.csv`: runtime-visible observations only
- `ground_truth_labels.csv`: labels and deterministic label provenance
- `scenario_manifests.csv`: generation recipes and safe mutation parameters
- `split_assignments.csv`: 70/15/15 lineage-grouped assignments
- `engineered_features.csv`: numeric, leakage-safe model features

Every record has a reproducible seed and run ID. All members of a lineage stay
within one split.

## Validation Commands

```text
python scripts/generate_evidence_bundles.py
python -m src.supply_chain.decision_engine
python scripts/verify_evidence_bundle.py
python scripts/generate_dataset.py
python scripts/feature_engineering.py
python scripts/validate_dataset.py
python scripts/validate_grouped_split.py
python -m pytest -q
```

## Current Status

Correction, dataset generation, dataset validation, grouped splitting, and
feature engineering are complete.

Status: Ready for an ML training/evaluation specification and baseline model
experiment. ML training, rule/ML fusion, API integration, and dashboard work
have not been implemented in this release.
