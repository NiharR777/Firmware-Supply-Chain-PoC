# Nihar: correction handover, 12 September 2026

The repository package has been corrected. Experiment v1 remains **REJECTED**.
Passing the package checks does not approve the model or the next integration stage.

## What changed

- Restored the supplied framework-benchmarked baseline, including its official-schema benchmark materials, tests and corrected SC-004 SBOM.
- Excluded the three obsolete scripts from the active repository. Their original copies remain inside the historical submission ZIP only.
- Restored line endings to match all 19 EXISTING experiment-manifest hashes. No recorded hash was rewritten to make a changed result pass. The frozen dataset bytes are those in the approved baseline.
- Preserved the original submission ZIP, models, predictions and manifest. `evidence/v1/restoration_audit.json` records each byte restoration.
- Added an offline input guard and assertion tests. Invalid inputs abstain and request investigation. All use of the rejected model is ineligible. The guard does not change deterministic policy decisions.
- Reproduced all 750 saved probabilities from the saved calibrated model, with no fitting. Added 750 record-linked local explanations, recalculated calibration metrics, subgroup error rates and explicit treatment of groups with missing class support.
- Added model/data cards, a scoped privacy scan, assurance matrix, incident/monitoring/rollback plans and the actual correction runtime record.
- Archived the original training script as text and replaced its runnable entry point with a stop message to prevent accidental reuse of the opened test set.

## What cannot be repaired retrospectively

Experiment v1 fitted one Isolation Forest configuration instead of the approved eight. Supervised configuration selection also used validation across the full grid rather than first selecting hyperparameters within training CV. Anomaly validation gates failed, yet final test evaluation was still performed. These are historical protocol deviations and remain recorded.

The original training execution log, actual runtime record and Git commit were not supplied. The new runtime record describes this correction review only. The other fitted candidate objects were not supplied, so all-candidate validation importance and logistic coefficient evidence cannot be recovered without refitting. Refitting was not performed.

The new safety envelope is a conservative review control derived only from training features. It is not an approved production OOD detector. New audit reports are dated post-hoc and do not replace v1 results or change its rejection.

## What Nihar should do

1. Extract this ZIP into a new folder. Preserve the existing repository/branch first.
2. Install the tested review dependencies with `python -m pip install -r requirements-correction.txt` in a separate Python 3.12 environment.
3. Run `python scripts/run_correction_checks.py --output ../nihar-correction-checks`. This runs tests, dataset/split/schema/evidence checks and package verification; it does not train.
4. Merge the corrected tree into GitHub, taking care that overlaying files does not delete obsolete tracked files automatically. Explicitly remove `scripts/generate_scenarios.py`, `scripts/test_environment.py` and `src/supply_chain/hash_evidence.py` from the active repository. Retain the correction `.gitattributes` so frozen bytes are not converted by Git.
5. Validate a fresh Git checkout again and send the commit ID and generated check log. If files change during merging, do not silently replace the package manifest; provide the changed-file list for review.

Do not run the historical training script. No new dataset or holdout was created in this correction. Experiment v2 needs an approved protocol and a newly quarantined, independent evaluation set. New seeds alone do not demonstrate real-world generalisation. Fusion/API/dashboard work remains unapproved until the experiment acceptance decision is resolved.

## Interpretation of the original metrics

The supervised model reproduces deterministic labels on a synthetic dataset containing direct rule-derived aggregate features. Its perfect result is rule fidelity on this dataset, not demonstrated unknown-threat detection. Isolation Forest's recall is **non-normal recall** (investigate plus high-risk), not specifically high-risk recall. Its failure remains a valid negative result.

Some earlier descriptions called the line-ending mismatch a dataset change. The frozen numerical records were not changed; restoring matching bytes resolved the integrity error. The baseline's LF checkout rule was incompatible with its frozen CRLF metadata, so the correction now preserves frozen bytes explicitly.
