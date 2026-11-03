# Firmware Assurance Dashboard Starter

A separate FastAPI + HTML/CSS/JavaScript layer for the existing synthetic Firmware Supply-Chain PoC.

## Install / run (Windows PowerShell)

Run from the repository root with `.venv` activated.

1. Check dependencies:
   `python -c "import fastapi, uvicorn; print('FastAPI and Uvicorn available')"`
2. If missing, install the already-pinned dependencies:
   `python -m pip install -r requirements.txt`
3. Start:
   `python -m uvicorn src.supply_chain.api.app:app --host 127.0.0.1 --port 8000`
4. Open `http://127.0.0.1:8000`; API docs: `http://127.0.0.1:8000/docs`.
5. Stop with Ctrl+C.

## API
- GET `/api/health`
- GET `/api/scenarios`
- POST `/api/supply-chain/assess` with `{"scenario_id":"SC-001","package_id":"PKG-001"}`
- GET `/api/metrics`
- GET `/api/workflow`
- POST `/api/workflow/{scenario_id}/approval`
- POST `/api/workflow/{scenario_id}/simulate-release`
- GET `/api/audit`

## Safety and limitations
- Only the ten predefined synthetic scenarios are assessed. No arbitrary file upload or binary execution.
- Calls existing `evaluate_scenario()` directly. Does not call `write_decision()` and does not overwrite historical `decision.json`.
- Separate workflow state and audit records are stored under `artifacts/dashboard/`.
- Simulated test gate requires human disposition `approved_for_simulated_test` and a fresh deterministic `normal` result.
- `deployment_allowed` is always false and `real_action_executed` is always false.
- Metrics are local API-process timings, not production benchmarks.
- This is a local PoC starter, not production-ready or an exhaustive binary scanner.
- The old API contract's confidence field is intentionally omitted: deterministic risk score is not a probability or calibrated model confidence.
