# Validation results

Validated on 2026-08-28 from the repository root.

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
- Automated test suite: 59 passed.

No ML model, ML prediction output, rule/ML fusion, inference API, or dashboard integration is included. Those remain gated on an agreed training and evaluation specification.
