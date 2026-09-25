# Firmware dataset framework benchmark

Benchmark date: 2026-09-01

> This is a reproducible conformance and coverage assessment. It is not a certification, production compliance claim, or proof that synthetic distributions match real firmware fleets.

## Acceptance result

- CycloneDX 1.5 raw documents valid: 7/7.
- SBOM evidence references and hashes consistent: true.
- Dataset records assessed: 5000 across 500 grouped lineages.
- Framework controls: 7 covered, 6 partial, 7 gaps.

## Framework coverage summary

| Framework | Covered | Partial | Gap |
|---|---:|---:|---:|
| CycloneDX | 3 | 1 | 1 |
| SLSA | 1 | 0 | 4 |
| NIST SP 800-193 | 2 | 1 | 1 |
| NIST SP 800-218 SSDF | 1 | 4 | 1 |

## Material findings

- CycloneDX schema conformance is now enforced for canonical and deliberately modified raw SBOM fixtures.
- The dataset strongly covers integrity and detection signals, including hashes, signatures, roots of trust, rollback, vendor trust, SBOM completeness, vulnerabilities and staleness.
- SLSA build/source provenance is not represented. No signed provenance, builder identity, source revision, build instructions or build-platform isolation evidence exists.
- NIST SP 800-193 detection and rollback concepts are represented; hardware-backed protection and recovery are outside the PoC boundary.
- NIST SSDF component/vulnerability practices are partially represented, but organisational development-process controls are not established by this dataset.
- VEX exists as reference CSV data, not yet as a standards-valid CycloneDX vulnerability analysis object.

## Realism and generalisation limitation

The benchmark verifies standards representation and internal invariants. It does not establish that synthetic feature distributions match deployed firmware ecosystems.
No external firmware corpus is used in this gate. Consequently, later ML evaluation must describe the model as validated on synthetic data only and must not claim production generalisation.

## ML gate consequence

The dataset may proceed to a controlled synthetic baseline-model experiment after the repository and ML specification gates pass. Framework gaps remain explicit model limitations and must not be converted into inferred negative evidence.

## Reproduce

```powershell
python scripts/generate_evidence_bundles.py
python -m src.supply_chain.decision_engine
python scripts/framework_benchmark.py
```
