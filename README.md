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

Experiment v1 has been submitted and remains **REJECTED**. Its original models,
predictions and manifest are preserved. This release adds repository corrections,
an offline input guard and post-hoc evidence. No new training was performed.
Start with `docs/CORRECTION_HANDOVER.md` and `VALIDATION_RESULTS.md`.

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
python -m pip install -r requirements-correction.txt
python scripts/run_correction_checks.py --output ../correction-checks
```

Use Python 3.12 in an isolated environment. Logs are written outside the sealed
repository. The runner does not regenerate data or train models. Keep original
generator scripts for provenance, but do not run them over this frozen dataset.
The original training script is archived as text under `evidence/v1`.

## Standards Benchmark

`scripts/framework_benchmark.py` performs a reproducible pre-ML framework
gate. It validates the raw SBOM fixtures against the bundled official
CycloneDX 1.5 JSON schema, verifies evidence-to-SBOM hashes, checks the full
5,000-record dataset coverage, and generates explicit coverage/gap mappings
for SLSA 1.2, NIST SP 800-193, and NIST SP 800-218 SSDF.

Results are under `benchmarks/frameworks/results/`. This is a conformance and
coverage assessment, not certification. No external real-world firmware corpus
is used, so production generalisation must not be claimed.

## Current Status

Correction, dataset generation, dataset validation, grouped splitting, feature
engineering, and the pre-ML standards benchmark are complete.

Status: Experiment v1 is rejected. Correction checks verify package integrity and
supplementary evidence, not model acceptance. Complete Nihar's clean-checkout merge
verification next. Any Experiment v2 requires a new approved protocol and quarantined
holdout. Rule/ML fusion, API and dashboard integration remain unapproved.
