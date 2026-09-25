# Operational boundary

The package is an offline, rejected experiment plus correction evidence. It does not implement rule/ML fusion, a production inference API, dashboard, firmware deployment or quarantine.

`ml_input_guard.py` examines only engineered inputs and emits eligibility/abstention plus an investigation routing hint. It returns no policy decision and no ML score. Therefore its investigation hint cannot lower an existing deterministic high-risk decision. Deterministic hard failures continue to be evaluated by the unchanged decision engine and its assertion tests.

Future integration requires explicit approval. It must keep deterministic hard-failure precedence and make disagreement an attributable investigation signal. Human approval remains necessary for consequential action. Proposed future audit fields are event ID/time, input/model/data/code hashes, policy result/reasons, ML result/abstention, disagreement, human identity/decision/reason and final disposition. This is a documented future contract, not an implemented audit workflow.

For the current correction, missing, malformed, infinite, NaN and unsupported feature combinations trigger abstention. The profile uses only training-row inclusive min/max bounds and observed binary combinations. It may reject legitimate novelty and miss other shifts; it is deliberately a conservative review check. It is not calibrated using the opened test set and is not represented as production-ready.
