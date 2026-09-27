# Validation results

Current correction: 2026-09-12. See `evidence/correction_checks/` for actual execution logs and `artifacts/correction/` for post-hoc reports. Experiment v1 remains REJECTED. Package checks do not grant training or integration approval.

## Correction checks executed

- 78 assertion-based tests passed (the restored 63-test baseline plus 15 correction tests).
- All 5,000 records passed dataset regeneration/content checks, label recalculation and stored byte hashes. No frozen file was regenerated in place.
- Grouped split, schema and ten evidence-bundle checks passed.
- All 19 historical input/model/result hashes matched the unchanged experiment manifest after byte restoration.
- Saved calibrated model reproduced all 750 labels and probabilities exactly (maximum absolute probability difference 0.0; tolerance 1e-10).
- Local explanations cover all 750 saved predictions. Selected-model validation permutation importance uses 20 repeats and seed 20260828. Other fitted candidates were not supplied, so all-candidate importance remains unavailable.
- Defined offline robustness mutations pass. The train-only envelope is a newly added conservative review control and does not activate the rejected model.
- Subgroup report includes per-class FPR/FNR, high-risk recall and 0.10 gap checks. No measurable gap fails; 13 groups have insufficient class support to estimate all required rates and remain explicitly partial.
- Dataset CSV schema/PII-pattern scan found no matches within its declared limited scope.
- The review runtime is Python 3.12 with exact installed versions recorded in `requirements-correction.txt` and `environment_record.json`. This does not establish the original training environment.
- Joblib emits NumPy 2.5 shape-assignment deprecation warnings during model loading. They are retained in the logs; reload outputs match exactly. A future dependency migration requires separate validation.

Final ZIP and clean Git-checkout verification are recorded in the companion `NIHAR_ML_CORRECTION_VALIDATION.json` outside the sealed ZIP, avoiding self-referential file hashes.

## Historical baseline validation (2026-09-01)

- Evidence bundle verification: 10/10 passed.
- Runtime evidence leakage audit: passed recursively for all ten fixtures.
- Clean/manipulated package hash recomputation: passed for SC-001 and SC-002.
- Dataset size and file alignment: 5,000/5,000 records passed.
- Class distribution: 1,000 normal, 2,000 investigate, 2,000 high-risk.
- Per-record seed regeneration: all 5,000 records passed.
- Independent deterministic label recalculation: all 5,000 labels passed.
- Trusted-vendor invariant for normal cases: passed.
- Grouped splitting: 500 independent lineages, ten assessments per lineage, no cross-split lineage leakage.
- Split sizes: 3,500 train, 750 validation, 750 test; all three classes occur in every split.
- Feature engineering: 5,000 rows and 22 numeric, leakage-safe feature columns.
- Exact reproducibility: all dataset files were byte-identical after a second complete generation and feature-engineering run.
- Official CycloneDX 1.5 schema validation: 7/7 raw SBOM documents passed.
- Evidence-to-SBOM path and SHA-256 verification: passed for every supplied SBOM.
- Framework coverage matrix: 20 requirements assessed across CycloneDX, SLSA 1.2, NIST SP 800-193 and NIST SP 800-218 SSDF.
- Coverage result: 7 covered, 6 partial, 7 explicit gaps.
- External firmware corpus: not used; the realism boundary remains synthetic-only.
- Automated test suite: 63 passed.

The original baseline contained no ML artifacts. This corrected release now preserves the submitted v1 models and results as rejected historical evidence. Fusion, API and dashboard remain unimplemented. Original training runtime/log/commit and all-candidate explanations remain unavailable; no retrospective pass is claimed for those controls.
