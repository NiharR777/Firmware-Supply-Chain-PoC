# Monitoring, incident handling and rollback plan

Status: specified for future integration; no deployment, telemetry monitor or rollback system is implemented. Nihar is the proposed technical responder; the project review owner and Nirupam Sir approve changes. Operations ownership and alert recipients must be appointed before deployment.

Proposed predeployment controls requiring approval:

- Every input: validate artifact integrity/schema and record abstention reasons. Any hash mismatch, nonfinite input or unsupported schema withholds the ML output immediately and opens an investigation. Deterministic findings remain unchanged.
- Daily during an initial supervised pilot: review counts of invalid/OOD inputs, class/score distributions and availability. Proposed review alert: OOD rate over 5% in a batch of at least 100 assessments, or twice the approved baseline rate for two consecutive batches. These proposed thresholds have not been tuned or validated on operational data.
- Weekly: review labelled error metrics, calibration and technical subgroups once sufficient independently verified outcomes exist. A failed approved acceptance metric or a supported subgroup gap above 0.10 triggers an ML-use review. Small denominators are reported explicitly rather than treated as passing.
- Monthly and at any firmware/vendor/schema/model change: review drift and the reference-data contract. The project owner approves reference-window and drift-measure choices before deployment; no online learning or automatic threshold adaptation is authorised.

Incident procedure: stop serving the ML advisory output, retain deterministic assessments, preserve input/model/code hashes and logs, assign the technical responder, assess scope, document cause and remediation, and obtain reviewer/approver clearance before reactivation. Never overwrite prior outputs or silently change thresholds.

Rollback: withdraw the affected model registration/configuration and return to a previously approved model only if one exists. This PoC has none, so the fallback is deterministic-only assessment with human review. Record who disabled/re-enabled the model, when, why and the associated artifact identifiers. This is a plan, not a claim that a deployment registry exists.

Before deployment: perform an approved tabletop exercise covering integrity failure, OOD surge, missed high-risk outcome and subgroup degradation. Preserve the exercise log and approval. These controls remain pending until that later stage.
