
from __future__ import annotations

import json
import statistics
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from src.supply_chain.decision_engine import EVIDENCE_DIR, evaluate_scenario


PROJECT_ROOT = Path(__file__).resolve().parents[3]
STATIC_DIR = Path(__file__).resolve().parent / "static"
STATE_DIR = PROJECT_ROOT / "artifacts" / "dashboard"
STATE_FILE = STATE_DIR / "workflow_state.json"
AUDIT_FILE = STATE_DIR / "audit.jsonl"

SCENARIO_IDS = tuple(f"SC-{n:03d}" for n in range(1, 11))
LOCK = threading.Lock()


app = FastAPI(
    title="Firmware Supply-Chain Assurance API",
    version="0.3.0",
    description=(
        "Synthetic-evidence assessment and simulated human-review "
        "workflow. No operational actions."
    ),
)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class AssessmentRequest(BaseModel):
    scenario_id: str = Field(pattern=r"^SC-(00[1-9]|010)$")
    package_id: str = Field(min_length=1, max_length=64)


class ApprovalRequest(BaseModel):
    reviewer: str = Field(min_length=1, max_length=80)
    disposition: str = Field(
        pattern=r"^(approved_for_simulated_test|hold_for_review|rejected)$"
    )
    note: str = Field(default="", max_length=500)


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(
            f"Required evidence file missing: {path.name}"
        )

    value = json.loads(path.read_text(encoding="utf-8"))

    if not isinstance(value, dict):
        raise ValueError(
            f"Evidence must be a JSON object: {path.name}"
        )

    return value


def bundle(scenario_id: str) -> Path:
    if scenario_id not in SCENARIO_IDS:
        raise HTTPException(404, "Unknown scenario ID.")

    base = EVIDENCE_DIR.resolve()
    path = (base / scenario_id).resolve()

    if path.parent != base or not path.is_dir():
        raise HTTPException(
            404, "Scenario evidence bundle not found."
        )

    return path


def load_state():
    if not STATE_FILE.exists():
        return {
            "workflow": {},
            "assessment_metrics_ms": [],
        }

    try:
        state = json.loads(
            STATE_FILE.read_text(encoding="utf-8")
        )

        if not isinstance(state, dict):
            raise ValueError()

        state.setdefault("workflow", {})
        state.setdefault("assessment_metrics_ms", [])

        return state

    except (json.JSONDecodeError, OSError, ValueError):
        raise HTTPException(
            500,
            "Dashboard state is unreadable; inspect it before continuing."
        )


def save_state(state):
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    temp = STATE_FILE.with_suffix(".tmp")

    temp.write_text(
        json.dumps(state, indent=2),
        encoding="utf-8",
    )

    temp.replace(STATE_FILE)


def audit(event):
    """Append an audit event without rewriting existing history."""

    STATE_DIR.mkdir(parents=True, exist_ok=True)

    with LOCK:
        with AUDIT_FILE.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(event, ensure_ascii=False) + "\n"
            )


def package_for(scenario_id):
    return str(
        read_json(
            bundle(scenario_id) / "package.json"
        ).get("package_id", "")
    )


def evidence_checks(scenario_id):
    directory = bundle(scenario_id)

    ref = read_json(directory / "reference_evidence.json")
    hash_evidence = read_json(directory / "hash_evidence.json")
    signature = read_json(directory / "signature_evidence.json")
    vendor = read_json(directory / "vendor_evidence.json")
    rollback = read_json(directory / "rollback_evidence.json")
    sbom = read_json(directory / "sbom.json")
    freshness = read_json(directory / "freshness_evidence.json")

    hash_ok = (
        bool(ref.get("trusted_sha256"))
        and bool(hash_evidence.get("observed_hash"))
        and ref.get("trusted_sha256")
        == hash_evidence.get("observed_hash")
    )

    signature_ok = (
        signature.get("signature_status") == "valid"
    )

    root_ok = (
        signature.get("trusted_root_status") == "trusted"
    )

    vendor_ok = (
        ref.get("approved_vendor_id")
        == vendor.get("observed_vendor_id")
        and vendor.get("vendor_trust_status") == "trusted"
    )

    rollback_ok = (
        ref.get("approved_version")
        == rollback.get("observed_version")
        or rollback.get("rollback_authorized") is True
    )

    sbom_ok = (
        sbom.get("sbom_present") is True
        and sbom.get("sbom_status") == "complete"
    )

    vulnerability_status = sbom.get(
        "vulnerability_status", "unknown"
    )

    unexpected = sbom.get("unexpected_component_observed")

    age = freshness.get("evidence_age_days")
    threshold = freshness.get("freshness_threshold_days")

    freshness_ok = (
        isinstance(age, int)
        and isinstance(threshold, int)
        and age <= threshold
    )

    rows = [
        (
            "SHA-256 integrity",
            hash_ok,
            f"Trusted reference compared with observed hash: "
            f"{'match' if hash_ok else 'mismatch'}.",
        ),
        (
            "Digital signature",
            signature_ok,
            f"Signature status: "
            f"{signature.get('signature_status', 'missing')}.",
        ),
        (
            "Trusted root",
            root_ok,
            f"Root status: "
            f"{signature.get('trusted_root_status', 'missing')}.",
        ),
        (
            "Vendor trust",
            vendor_ok,
            f"Observed vendor: "
            f"{vendor.get('observed_vendor_id', 'missing')}.",
        ),
        (
            "Rollback policy",
            rollback_ok,
            f"Approved version: {ref.get('approved_version')}; "
            f"observed: {rollback.get('observed_version')}.",
        ),
        (
            "SBOM completeness",
            sbom_ok,
            f"Status: {sbom.get('sbom_status', 'missing')}; "
            f"components: {sbom.get('component_count', 'unknown')}.",
        ),
        (
            "Vulnerability applicability",
            vulnerability_status == "not_affected",
            f"Package vulnerability status: {vulnerability_status}.",
        ),
        (
            "Unexpected components",
            unexpected is False,
            f"Unexpected component observed: {unexpected}.",
        ),
        (
            "Evidence freshness",
            freshness_ok,
            f"Evidence age: {age}; threshold: {threshold} days.",
        ),
    ]

    result = []

    for name, ok, detail in rows:
        status = (
            "pass"
            if ok
            else (
                "warning"
                if name == "Vulnerability applicability"
                and vulnerability_status not in (
                    "affected",
                    "not_affected",
                )
                else "review"
            )
        )

        result.append({
            "name": name,
            "status": status,
            "detail": detail,
        })

    return result


def make_assessment(scenario_id, package_id):
    actual_package_id = package_for(scenario_id)

    if actual_package_id != package_id:
        raise HTTPException(
            422,
            f"Package ID does not match {scenario_id}. "
            f"Expected {actual_package_id}.",
        )

    start = time.perf_counter()

    try:
        result = evaluate_scenario(scenario_id)

    except (
        FileNotFoundError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        raise HTTPException(
            422,
            f"Assessment could not be completed: {exc}",
        ) from exc

    elapsed = (time.perf_counter() - start) * 1000
    assessed_at = now()

    payload = {
        "use_case": "firmware_supply_chain",
        "scenario_id": scenario_id,
        "package_id": result.get("package_id"),
        "decision": result.get("risk_level"),
        "risk_score": result.get("risk_score"),
        "severity": result.get("risk_level"),
        "risk_factors": result.get("risk_factors", []),
        "risk_breakdown": result.get("risk_breakdown", []),
        "evidence_layers": evidence_checks(scenario_id),
        "explanations": result.get("reasons", []),
        "recommended_actions": [
            result.get("recommendation", "investigate")
        ],
        "affected_assets": [{
            "asset_id": result.get("affected_asset"),
            "asset_name": result.get("asset_name"),
            "device_type": result.get("device_type"),
            "process_unit": result.get("process_unit"),
        }],
        "human_approval_required": True,
        "deployment_allowed": False,
        "real_action_executed": False,
        "data_provenance": "SYNTHETIC OBSERVED EVIDENCE",
        "assessment_duration_ms": round(elapsed, 3),
        "assessed_at": assessed_at,
        "warnings": [
            "Synthetic evidence only; not a production firmware scanner.",
            "Read-only assessment. No uploaded binary is executed or installed.",
        ],
    }

    with LOCK:
        state = load_state()

        samples = state.setdefault(
            "assessment_metrics_ms", []
        )

        samples.append(round(elapsed, 3))
        state["assessment_metrics_ms"] = samples[-500:]

        save_state(state)

    audit({
        "event": "assessment_completed",
        "scenario_id": scenario_id,
        "package_id": package_id,
        "decision": payload["decision"],
        "risk_score": payload["risk_score"],
        "duration_ms": payload["assessment_duration_ms"],
        "timestamp": assessed_at,
        "real_action_executed": False,
    })

    return payload


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "service": "firmware-supply-chain-assurance",
        "assessment_mode": "synthetic_read_only",
        "real_action_executed": False,
    }


@app.get("/api/scenarios")
def scenarios():
    rows = []

    for scenario_id in SCENARIO_IDS:
        try:
            package = read_json(
                bundle(scenario_id) / "package.json"
            )

            asset = read_json(
                bundle(scenario_id) / "asset_mapping.json"
            )

            rows.append({
                "scenario_id": scenario_id,
                "package_id": package.get("package_id"),
                "firmware_version": package.get("firmware_version"),
                "asset_name": asset.get("asset_name"),
                "device_type": asset.get("device_type"),
            })

        except (
            HTTPException,
            FileNotFoundError,
            ValueError,
            json.JSONDecodeError,
        ):
            rows.append({
                "scenario_id": scenario_id,
                "available": False,
            })

    return {
        "count": len(rows),
        "scenarios": rows,
    }


@app.post("/api/supply-chain/assess")
def assess(request: AssessmentRequest):
    return make_assessment(
        request.scenario_id,
        request.package_id,
    )


@app.get("/api/metrics")
def metrics():
    with LOCK:
        samples = load_state().get(
            "assessment_metrics_ms", []
        )

    return {
        "dashboard_assessments_recorded": len(samples),
        "latency_samples_ms": samples,
        "mean_latency_ms": (
            round(statistics.mean(samples), 3)
            if samples else None
        ),
        "median_latency_ms": (
            round(statistics.median(samples), 3)
            if samples else None
        ),
        "min_latency_ms": (
            round(min(samples), 3)
            if samples else None
        ),
        "max_latency_ms": (
            round(max(samples), 3)
            if samples else None
        ),
        "note": (
            "API-process assessment measurements; "
            "not production benchmarks."
        ),
    }


def _performance_bundle_record(scenario_id: str) -> dict[str, Any]:
    """Return observed fields from one predefined synthetic evidence bundle."""
    directory = bundle(scenario_id)
    package = read_json(directory / "package.json")
    sbom = read_json(directory / "sbom.json")
    signature = read_json(directory / "signature_evidence.json")
    vendor = read_json(directory / "vendor_evidence.json")
    asset = read_json(directory / "asset_mapping.json")

    sbom_present = sbom.get("sbom_present") is True
    sbom_complete = sbom_present and sbom.get("sbom_status") == "complete"
    signature_valid = signature.get("signature_status") == "valid"
    trusted_root = signature.get("trusted_root_status") == "trusted"
    vendor_trusted = vendor.get("vendor_trust_status") == "trusted"
    vex_status = str(sbom.get("vulnerability_status", "unknown")).lower()

    return {
        "scenario_id": scenario_id,
        "package_id": package.get("package_id"),
        "asset_name": asset.get("asset_name"),
        "device_type": asset.get("device_type"),
        "sbom_present": sbom_present,
        "sbom_complete": sbom_complete,
        "signature_valid": signature_valid,
        "trusted_root": trusted_root,
        "signature_compliant": signature_valid and trusted_root,
        "vendor_trusted": vendor_trusted,
        "vex_status": vex_status,
        "vex_explicit": vex_status in ("affected", "not_affected"),
        "component_count": sbom.get("component_count"),
    }


@app.get("/api/performance-dashboard")
def performance_dashboard():
    """
    Aggregate only fields actually present in the ten synthetic bundles.
    These are bundle-level demonstration indicators, not plant-wide OT KPIs.
    """
    records = []
    unavailable = []
    for scenario_id in SCENARIO_IDS:
        try:
            records.append(_performance_bundle_record(scenario_id))
        except (HTTPException, FileNotFoundError, ValueError, json.JSONDecodeError):
            unavailable.append(scenario_id)

    total = len(records)

    def percentage(numerator: int, denominator: int):
        return round((numerator / denominator) * 100, 1) if denominator else None

    sbom_complete = sum(1 for row in records if row["sbom_complete"])
    signature_compliant = sum(1 for row in records if row["signature_compliant"])
    vendor_trusted = sum(1 for row in records if row["vendor_trusted"])
    vex_explicit = sum(1 for row in records if row["vex_explicit"])
    vex_affected = sum(1 for row in records if row["vex_status"] == "affected")
    vex_not_affected = sum(1 for row in records if row["vex_status"] == "not_affected")
    vex_unknown = sum(1 for row in records if row["vex_status"] not in ("affected", "not_affected"))

    # CVSS/EPSS severity records, asset inventory denominators, incident timestamps,
    # CI/CD attestations and binary-analysis outputs are not present in this PoC API.
    # Do not infer or fabricate those measurements.
    return {
        "data_basis": "Predefined synthetic evidence bundles; bundle-level indicators only",
        "scope_note": (
            "These percentages describe available scenario bundles, not deployed OT assets, "
            "plant inventory, vendor populations, or production performance."
        ),
        "scenario_bundles_available": total,
        "scenario_bundles_unavailable": unavailable,
        "kpis": {
            "sbom_coverage": {
                "label": "Complete SBOM evidence",
                "numerator": sbom_complete,
                "denominator": total,
                "value_percent": percentage(sbom_complete, total),
                "target": "98% Tier-1 assets; 90% non-critical assets",
                "basis": "Complete SBOM evidence bundles / available synthetic scenario bundles",
                "status": "measured_on_synthetic_bundles",
            },
            "signature_compliance": {
                "label": "Signature and trusted-root evidence",
                "numerator": signature_compliant,
                "denominator": total,
                "value_percent": percentage(signature_compliant, total),
                "target": "100%",
                "basis": "Valid signature AND trusted root / available synthetic scenario bundles",
                "status": "measured_on_synthetic_bundles",
            },
            "vendor_trust": {
                "label": "Trusted vendor evidence",
                "numerator": vendor_trusted,
                "denominator": total,
                "value_percent": percentage(vendor_trusted, total),
                "target": "No numeric target specified in supplied metrics document",
                "basis": "Bundles whose supplied vendor trust status is trusted / available bundles",
                "status": "measured_on_synthetic_bundles",
            },
            "vex_coverage": {
                "label": "Explicit VEX status coverage",
                "numerator": vex_explicit,
                "denominator": total,
                "value_percent": percentage(vex_explicit, total),
                "target": "85% of relevant alerts resolved through VEX",
                "basis": "Bundles with affected or not_affected status / available bundles",
                "status": "measured_on_synthetic_bundles",
            },
        },
        "vex_status_counts": {
            "affected": vex_affected,
            "not_affected": vex_not_affected,
            "unknown_or_missing": vex_unknown,
        },
        "scenario_evidence": records,
        "not_measured": [
            {
                "metric": "Firmware Vulnerability Exposure Index (FVEI)",
                "reason": "Structured CVE severity, CVSS and EPSS records are not exposed by the current dashboard evidence schema.",
                "document_target": "Zero unmitigated Critical/High CVEs on safety-critical networks; zero-day remediation window to be defined.",
            },
            {
                "metric": "Firmware MTTD / MTTR",
                "reason": "Detection, incident, isolation and remediation timestamps are not collected.",
                "document_target": "Operational target requires agreed incident timing definitions.",
            },
            {
                "metric": "CI/CD artifact attestation",
                "reason": "No SLSA/build provenance attestation evidence is present in the current bundles.",
                "document_target": "100% for safety-instrumented and station-automation software.",
            },
            {
                "metric": "Firmware binary parsing accuracy and coverage",
                "reason": "The current PoC does not parse arbitrary firmware binaries or produce parser ground-truth comparisons.",
                "document_target": "Parsing accuracy >=98%; coverage of target OEM firmware formats.",
            },
            {
                "metric": "Reachability accuracy / MTTC",
                "reason": "No binary call-graph, network/bus reachability, or CVE-to-function validation dataset is implemented.",
                "document_target": "Reachability precision >=95%; MTTC target requires measurement.",
            },
            {
                "metric": "Bootloader identification and tamper-detection accuracy",
                "reason": "No raw image bootloader extraction or controlled tamper test dataset is implemented.",
                "document_target": "Bootloader identification rate 99%; cryptographic provenance accuracy 100%.",
            },
            {
                "metric": "SBOM-to-binary consistency and license precision",
                "reason": "No binary-derived SBOM comparison or license scanner is implemented.",
                "document_target": "SBOM consistency >=99%; license compliance precision 100%.",
            },
            {
                "metric": "Safety-system exposure and patch-deferral risk",
                "reason": "No deployed SIS inventory, maintenance-window, or patch-deferral records are connected.",
                "document_target": "Operational safety and patch-deferral thresholds require plant-specific inventory.",
            },
            {
                "metric": "Field provenance drift",
                "reason": "No live device firmware-state telemetry or central deployed-asset inventory is connected.",
                "document_target": "100% accuracy target in supplied metrics document.",
            },
        ],
        "targets_note": (
            "Targets are copied from the supplied requirements document. They are not claims "
            "that the current PoC meets those targets."
        ),
    }


@app.get("/api/workflow")
def get_workflow():
    with LOCK:
        state = load_state()
        workflow = state.get("workflow", {})

        return {"workflow": workflow}


@app.post("/api/workflow/{scenario_id}/approval")
def approval(
    scenario_id: str,
    request: ApprovalRequest,
):
    bundle(scenario_id)

    reviewer = request.reviewer.strip()
    note = request.note.strip()

    with LOCK:
        state = load_state()
        existing = state.setdefault(
            "workflow", {}
        ).get(scenario_id)

        if (
            existing
            and existing.get("reviewer") == reviewer
            and existing.get("disposition") == request.disposition
            and existing.get("note", "") == note
        ):
            return {
                **existing,
                "duplicate_submission": True,
            }

        record = {
            "scenario_id": scenario_id,
            "package_id": package_for(scenario_id),
            "reviewer": reviewer,
            "disposition": request.disposition,
            "note": note,
            "recorded_at": now(),
            "workflow_status": "human_review_recorded",
            "deployment_allowed": False,
            "real_action_executed": False,
        }

        state["workflow"][scenario_id] = record
        save_state(state)

    audit({
        "event": "human_review_recorded",
        **record,
    })

    return {
        **record,
        "duplicate_submission": False,
    }


def record_gate_attempt(
    scenario_id,
    package_id,
    outcome,
    reason,
    disposition,
    risk_level=None,
    risk_score=None,
):
    """Persist the latest simulated gate result and audit event."""

    if outcome == "passed_for_simulated_test_only":
        workflow_status = "simulated_test_gate_passed"

    elif risk_level is not None and risk_level != "normal":
        workflow_status = "simulated_test_blocked_high_risk"

    elif disposition is None:
        workflow_status = "simulated_test_blocked_review_required"

    elif disposition != "approved_for_simulated_test":
        workflow_status = "simulated_test_blocked_review_disposition"

    else:
        workflow_status = "simulated_test_blocked_assessment_error"

    event = {
        "event": "simulated_release_gate_evaluated",
        "scenario_id": scenario_id,
        "package_id": package_id,
        "outcome": outcome,
        "reason": reason,
        "review_disposition": disposition,
        "decision": risk_level,
        "risk_score": risk_score,
        "workflow_status": workflow_status,
        "timestamp": now(),
        "deployment_allowed": False,
        "real_action_executed": False,
        "mode": "simulation_only",
    }

    with LOCK:
        state = load_state()

        workflow = state.setdefault(
            "workflow", {}
        )

        record = workflow.setdefault(
            scenario_id,
            {
                "scenario_id": scenario_id,
                "package_id": package_id,
                "deployment_allowed": False,
                "real_action_executed": False,
            },
        )

        record["workflow_status"] = workflow_status
        record["latest_gate_evaluation"] = event

        record["deployment_allowed"] = False
        record["real_action_executed"] = False

        if outcome == "passed_for_simulated_test_only":
            record["simulation"] = {
                "scenario_id": scenario_id,
                "package_id": package_id,
                "workflow_status": workflow_status,
                "message": (
                    "Simulation only. No device connection, "
                    "installation, flashing, or execution occurred."
                ),
                "deployment_allowed": False,
                "real_action_executed": False,
                "recorded_at": now(),
            }

        save_state(state)

    audit(event)

    return event


@app.post("/api/workflow/{scenario_id}/simulate-release")
def simulate_release(scenario_id: str):
    bundle(scenario_id)

    with LOCK:
        record = load_state().get(
            "workflow", {}
        ).get(scenario_id)

    package_id = package_for(scenario_id)

    disposition = (
        record.get("disposition")
        if record else None
    )

    if not record:
        record_gate_attempt(
            scenario_id,
            package_id,
            "blocked",
            "No human review record exists.",
            None,
        )

        raise HTTPException(
            409,
            "Record a human review before simulated release.",
        )

    if disposition != "approved_for_simulated_test":
        reason = (
            f"Human disposition is {disposition}; "
            "simulated test requires approved_for_simulated_test."
        )

        record_gate_attempt(
            scenario_id,
            package_id,
            "blocked",
            reason,
            disposition,
        )

        raise HTTPException(
            409,
            "Simulated test requires approved_for_simulated_test disposition.",
        )

    try:
        result = evaluate_scenario(scenario_id)

    except (
        FileNotFoundError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        record_gate_attempt(
            scenario_id,
            package_id,
            "blocked",
            f"Assessment could not be completed: {exc}",
            disposition,
        )

        raise HTTPException(
            422,
            f"Assessment could not be completed: {exc}",
        ) from exc

    risk_level = result.get("risk_level")
    risk_score = result.get("risk_score")

    if risk_level != "normal":
        record_gate_attempt(
            scenario_id,
            package_id,
            "blocked",
            "Current deterministic assessment is not normal.",
            disposition,
            risk_level,
            risk_score,
        )

        raise HTTPException(
            409,
            "Simulated test held: current deterministic assessment is not normal.",
        )

    event = record_gate_attempt(
        scenario_id,
        result.get("package_id"),
        "passed_for_simulated_test_only",
        (
            "Human approval and deterministic "
            "normal-risk condition were satisfied."
        ),
        disposition,
        risk_level,
        risk_score,
    )

    return event["simulation"]


@app.get("/api/audit")
def get_audit():
    if not AUDIT_FILE.exists():
        return {"events": []}

    events = []

    for line in AUDIT_FILE.read_text(
        encoding="utf-8"
    ).splitlines()[-200:]:

        try:
            events.append(json.loads(line))

        except json.JSONDecodeError:
            continue

    return {
        "events": list(reversed(events))
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "src.supply_chain.api.app:app",
        host="127.0.0.1",
        port=8000,
    )
