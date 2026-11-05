# Firmware Assurance Dashboard — Performance Metrics Upgrade

## Included files
- `src/supply_chain/api/app.py`
- `src/supply_chain/api/static/index.html`
- `src/supply_chain/api/static/styles.css`
- `src/supply_chain/api/static/app.js`

## Apply
Back up the current four files, then copy these files into the matching locations in the repository. Do not replace the decision engine or evidence bundles.

## Run
From the repository root with the existing virtual environment active:
`python -m uvicorn src.supply_chain.api.app:app --host 127.0.0.1 --port 8000`

Open `http://127.0.0.1:8000`.

## Added API
`GET /api/performance-dashboard`

The new KPI cards are computed from the predefined synthetic evidence bundles. Denominators are scenario bundles, not real OT asset inventory. Targets are shown as requirements, not claimed achievements.

The following are explicitly reported as not measured: FVEI/CVSS/EPSS, MTTD/MTTR, CI/CD attestations, binary parsing accuracy/coverage, reachability, bootloader analysis, SBOM-to-binary consistency/license precision, safety-system exposure/patch-deferral risk, and live provenance drift.

Existing endpoints and safety boundaries are retained. No firmware is uploaded, executed, installed, or sent to a physical device.
