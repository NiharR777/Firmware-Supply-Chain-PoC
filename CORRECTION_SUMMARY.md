# Correction and dataset gate summary

## Scope completed

- Removed answer leakage from decision/runtime inputs. Scenario names and expected decisions remain only in scenario manifests or reporting metadata.
- Separated trusted reference data, observed evidence, ground-truth labels, scenario manifests, generation parameters, and grouped split assignments.
- Changed the deterministic engine to derive hash integrity, vendor trust, rollback, evidence freshness, SBOM status, and vulnerability status from evidence and trusted references.
- Corrected SC-004 vulnerability severity and affected component, SC-007 unexpected component evidence, SC-008 vendor/asset mapping, asset identifiers, and SBOM structures.
- Generated hash-mismatch fixtures from separate clean and manipulated synthetic package files and verified both SHA-256 values from the files.
- Replaced print-only checks with assertion-based tests.
- Rebuilt the synthetic dataset as 5,000 assessments across 500 package lineages, with ten records per lineage and reproducible per-record seeds.
- Produced a leakage-safe 22-column numeric feature matrix from observed and reference data only.
- Removed the premature ten-fixture ML model, ML predictions, agreement output, and API code. The fixtures remain tests, not training data.

## Dataset contract

The generated dataset is under `data/synthetic/supply_chain_poc/dataset/`:

- `reference_catalog.csv`: stable vendor and component reference catalog.
- `reference_data.csv`: trusted per-assessment reference values.
- `observable_features.csv`: assessment-time observations only.
- `ground_truth_labels.csv`: labels and scoring factors, never used to create features.
- `scenario_manifests.csv`: scenario provenance and attack parameters, never used to create features.
- `generation_parameters.json`: generator configuration and run metadata.
- `split_assignments.csv`: train/validation/test assignments grouped by package lineage.
- `engineered_features.csv`: numeric features created without labels or scenario manifests.
- `feature_metadata.json`: feature definitions and source restrictions.
- `dataset_file_hashes.json`: integrity hashes for generated files.

The split is 3,500 train, 750 validation, and 750 test records. A package lineage occurs in exactly one split.

## Verification commands

From the repository root:

```powershell
python scripts/generate_evidence_bundles.py
python -m src.supply_chain.decision_engine
python scripts/verify_evidence_bundle.py
python scripts/generate_dataset.py
python scripts/feature_engineering.py
python scripts/validate_dataset.py
python scripts/validate_grouped_split.py
python -m pytest -q
```

## Current gate and next step

Corrections, dataset generation, dataset validation, grouped splitting, and feature engineering are complete and testable. The single next gate is to agree the ML training/evaluation specification, then train and evaluate candidate models using only the grouped split. Do not implement rule/ML fusion, API, or dashboard integration until model discrimination, calibration, subgroup behavior, and reproducibility are accepted.

Later fusion must preserve deterministic hard-failure precedence. ML should remain advisory, and rule/ML disagreement should be recorded as an investigation/observability signal rather than silently overriding concrete evidence.
