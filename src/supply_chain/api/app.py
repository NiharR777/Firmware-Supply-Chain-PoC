from pathlib import Path
import json

from fastapi import FastAPI, HTTPException


# =========================================================
# PROJECT PATHS
# =========================================================

PROJECT_ROOT = Path(__file__).resolve().parents[3]

BASE_DIR = (
    PROJECT_ROOT
    / "data"
    / "synthetic"
    / "supply_chain_poc"
)

REPORT_DIR = BASE_DIR / "generated" / "reports"
EVIDENCE_DIR = BASE_DIR / "generated" / "evidence_bundles"
ML_DIR = BASE_DIR / "generated" / "ml_predictions"


# =========================================================
# FASTAPI APPLICATION
# =========================================================

app = FastAPI(
    title="Spectra AI - Refinery Firmware Supply Chain PoC",
    description=(
        "Evidence-driven firmware and software supply-chain "
        "risk assessment API for a synthetic refinery environment."
    ),
    version="1.0.0",
)


# =========================================================
# HELPER FUNCTIONS
# =========================================================

def load_json(file_path: Path) -> dict:
    """Load a JSON file."""

    if not file_path.exists():
        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    with file_path.open(
        "r",
        encoding="utf-8"
    ) as file:
        return json.load(file)


def load_final_assessment() -> list:
    """Load the generated final refinery assessment."""

    file_path = (
        REPORT_DIR
        / "final_refinery_assessment.json"
    )

    data = load_json(file_path)

    # Support either a direct list or a dictionary wrapper.
    if isinstance(data, list):
        return data

    if isinstance(data, dict):

        for key in (
            "assessments",
            "results",
            "scenarios",
            "data",
        ):
            if key in data and isinstance(data[key], list):
                return data[key]

    raise ValueError(
        "Unexpected final assessment JSON format."
    )


def find_scenario(scenario_id: str) -> dict:
    """Find one scenario from the final assessment."""

    assessments = load_final_assessment()

    for assessment in assessments:
        if assessment.get("scenario_id") == scenario_id:
            return assessment

    raise HTTPException(
        status_code=404,
        detail=f"Scenario {scenario_id} not found."
    )


# =========================================================
# HEALTH CHECK
# =========================================================

@app.get("/health")
def health_check():
    """
    API health/status endpoint.
    """

    return {
        "status": "healthy",
        "service": "Spectra AI Refinery Firmware Supply Chain PoC",
        "data_provenance": "SYNTHETIC",
    }


# =========================================================
# ROOT
# =========================================================

@app.get("/")
def root():
    """
    API information.
    """

    return {
        "project": "Spectra AI",
        "system": "Refinery Firmware Supply Chain PoC",
        "api_version": "1.0.0",
        "environment": "SYNTHETIC",
        "documentation": "/docs",
        "endpoints": [
            "/health",
            "/scenarios",
            "/scenarios/{scenario_id}",
            "/assessment",
            "/assessment/{scenario_id}",
            "/ml/predictions",
        ],
    }


# =========================================================
# SCENARIOS
# =========================================================

@app.get("/scenarios")
def get_scenarios():
    """
    Return all generated refinery scenario assessments.
    """

    try:
        assessments = load_final_assessment()

        return {
            "total_scenarios": len(assessments),
            "data_provenance": "SYNTHETIC",
            "scenarios": assessments,
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


@app.get("/scenarios/{scenario_id}")
def get_scenario(scenario_id: str):
    """
    Return assessment information for one scenario.
    """

    try:
        return find_scenario(scenario_id)

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


# =========================================================
# FINAL ASSESSMENT
# =========================================================

@app.get("/assessment")
def get_assessment():
    """
    Return the complete final refinery assessment.
    """

    try:
        assessments = load_final_assessment()

        high_risk = sum(
            1
            for item in assessments
            if item.get("risk_level") == "high_risk"
        )

        investigate = sum(
            1
            for item in assessments
            if item.get("risk_level") == "investigate"
        )

        normal = sum(
            1
            for item in assessments
            if item.get("risk_level") == "normal"
        )

        deployment_blocked = sum(
            1
            for item in assessments
            if item.get("deployment_allowed") is False
        )

        return {
            "total_scenarios": len(assessments),
            "high_risk": high_risk,
            "investigate": investigate,
            "normal": normal,
            "deployment_blocked": deployment_blocked,
            "data_provenance": "SYNTHETIC",
            "assessments": assessments,
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


@app.get("/assessment/{scenario_id}")
def get_assessment_for_scenario(
    scenario_id: str,
):
    """
    Return the final assessment for one refinery scenario.
    """

    return find_scenario(scenario_id)


# =========================================================
# ML PREDICTIONS
# =========================================================

@app.get("/ml/predictions")
def get_ml_predictions():
    """
    Return ML risk predictions and ML/rule agreement results.
    """

    file_path = (
        ML_DIR
        / "ml_risk_predictions.json"
    )

    try:
        predictions = load_json(file_path)

        return {
            "data_provenance": "SYNTHETIC",
            "predictions": predictions,
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


# =========================================================
# EVIDENCE BUNDLE
# =========================================================

@app.get("/evidence/{scenario_id}")
def get_evidence_bundle(
    scenario_id: str,
):
    """
    Return all generated evidence for one scenario.

    This endpoint is read-only.
    """

    scenario_dir = (
        EVIDENCE_DIR
        / scenario_id
    )

    if not scenario_dir.exists():
        raise HTTPException(
            status_code=404,
            detail=f"Evidence bundle for {scenario_id} not found.",
        )

    evidence = {}

    for file_path in sorted(
        scenario_dir.glob("*.json")
    ):

        try:
            evidence[file_path.stem] = load_json(file_path)

        except Exception:
            evidence[file_path.stem] = {
                "error": "Unable to parse evidence file."
            }

    return {
        "scenario_id": scenario_id,
        "data_provenance": "SYNTHETIC",
        "evidence": evidence,
    }


# =========================================================
# SAFETY / DEPLOYMENT STATUS
# =========================================================

@app.get("/deployment/status")
def deployment_status():
    """
    Show deployment safety status.

    The PoC never performs a real deployment action.
    """

    try:
        assessments = load_final_assessment()

        return {
            "deployment_mode": "READ_ONLY",
            "real_action_executed": False,
            "deployment_allowed": False,
            "human_approval_required": True,
            "blocked_scenarios": [
                item.get("scenario_id")
                for item in assessments
                if item.get("deployment_allowed") is False
            ],
            "message": (
                "This proof-of-concept does not execute real "
                "firmware deployment actions."
            ),
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=str(exc),
        )


# =========================================================
# DIRECT EXECUTION
# =========================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "src.supply_chain.api.app:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
    )