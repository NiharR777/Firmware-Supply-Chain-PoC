# Responsible AI assurance matrix

Evidence below is scoped to this correction. PASS does not accept Experiment v1. Proposed roles require confirmation; no independent signoff is fabricated.

| ID | Control / proposed owner | Evidence and verification | Result and remaining limitation |
|---|---|---|---|
| RAI-01 | Governance / Nihar, project reviewer, Nirupam Sir | model_card.md; closed manifest; training entry-point stop | DOCUMENTED; role confirmation and independent approval pending |
| RAI-02 | Data separation / dataset owner | frozen dataset hashes; validate_dataset.py; grouped tests; feature schema test | VERIFIED by correction checks; synthetic distribution limits remain |
| RAI-03 | Human oversight / product owner | operational_boundary.md; guard emits no policy action or score | VERIFIED offline boundary; integrated human workflow pending |
| RAI-04 | Hard-failure precedence / security lead | unchanged decision engine; original assertion tests; guard nonmutation test | VERIFIED existing rule tests; actual rule/ML integration tests are deferred until integration is authorised |
| RAI-05 | Transparency / Nihar | explanation_report.json; selected_validation_importance.json; reload_verification.json | PARTIAL: 750 local explanations complete; all-candidate validation importance and logistic coefficients unavailable |
| RAI-06 | Reliability / Nihar | original metrics; recalculated calibration_report.json | Supervised calibration reproduced; anomaly gates FAIL; overall experiment REJECTED |
| RAI-07 | Robustness / security QA | robustness_report.json; input_profile.json; test_ml_correction.py | PASS defined offline mutations; post-hoc envelope is not a validated production OOD detector |
| RAI-08 | Technical performance consistency / independent reviewer | subgroup_evaluation.json; false-gap and denominator tests | Measurable gaps assessed; unsupported denominators explicitly NOT_ESTIMABLE; real-world coverage pending |
| RAI-09 | Privacy / dataset owner | data_card.md; privacy_scan.json | LIMITED schema/pattern scan; no claim of exhaustive PII detection |
| RAI-10 | Integrity / security lead | historical restoration audit; package_manifest.json; reload verification; correction execution log | Corrected bytes and reload VERIFIED; original runtime/log/commit absent and remain a reproducibility gap |
| RAI-11 | Disagreement/override accountability / product owner | future audit fields in operational_boundary.md | DEFERRED to approved fusion/API stage; no implemented operational audit workflow claimed |
| RAI-12 | Monitoring/rollback / operations owner | monitoring_and_rollback.md | SPECIFIED only; thresholds, owner appointment, pilot and tabletop approval pending |

No certification, regulatory compliance or real-world fairness claim is made. This mapping uses the already approved specification and restored framework references. The final correction logs provide the actual execution results; documents alone are not proof that controls ran.
