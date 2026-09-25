# Data card: frozen synthetic firmware assessments

Dataset: 5,000 assessments, 500 independent package lineages with 10 records each. Classes: 1,000 normal, 2,000 investigate, 2,000 high_risk. Immutable grouped split: 3,500 train / 750 validation / 750 test. Each record retains its seed/run lineage. Records include benign evidence and simulated manipulations; no real firmware threat-detection benchmark dataset was added.

Files under `data/synthetic/supply_chain_poc/dataset` separate references, observable evidence, rule-derived ground truth, scenario/attack parameters, generation metadata, split assignments and engineered features. See `dataset_file_hashes.json` for frozen byte hashes. The correction restores the approved baseline bytes; it does not regenerate labels, records or splits. Historical flags such as `ml_training_started=false` in frozen generator metadata describe dataset-generation time, not current project status.

Provenance: generator code and recorded seeds allow regeneration checks. Synthetic vendor/product/asset identifiers are placeholders. Trusted versus observed identities are distinct. Manipulation hashes originate from synthetic package material, not executable malicious firmware. Labels derive from policy and are not independent human annotations or external security truth.

Framework comparison: restored `benchmarks/frameworks/results` records CycloneDX schema checks and a control coverage mapping, including explicit partial/gap findings. This is standards mapping and synthetic coverage, not a real-world performance benchmark or certification. TUF/Uptane signed update metadata, SLSA build provenance, hardware protection/recovery and organisational SSDF controls remain outside this dataset's demonstrated scope.

Privacy: schema review and PII-pattern scan cover all frozen dataset CSVs. The scan does not prove absence of all sensitive content. It does not inspect binary model internals or private external telemetry. Do not add proprietary firmware or personal telemetry to this research data without an approved access, retention and deletion policy.

Access/retention for this PoC: restrict artifacts to the project team and authorised reviewers; retain the frozen v1 package for the project audit period to be set by the project owner. No production collection has been authorised. Do not invent a retention duration or delete v1 evidence during merging.

Limitations: narrow generated distributions, correlated rule features, rule-derived labels, small/missing subgroup class support, and no independently labelled real-world holdout. Any v2 set needs independent lineages and a quarantined release/evaluation process; changing the random seed is insufficient proof of broader validity.
