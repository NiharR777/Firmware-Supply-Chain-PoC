
# FirmwareGuard – Firmware & Supply-Chain Assurance PoC

## 1. Project Overview

FirmwareGuard is a proof of concept for assessing the security, integrity, and trustworthiness of firmware packages and their software supply chains.

The system evaluates package evidence, software component inventories, vulnerability information, vendor trust, digital signatures, and dependency relationships.

It combines deterministic security checks, evidence analysis, controlled assessment workflows, and advisory intelligence.

The project uses synthetic evidence and controlled test scenarios. It is not connected to or authorized to modify real production devices.

## 2. Core Security Checks

FirmwareGuard supports the following assessment areas:

- SHA-256 package integrity verification
- Digital signature and trusted-root assessment
- Vendor trust evaluation
- SBOM component identification
- Vulnerability identification and risk assessment
- VEX information and justification
- Dependency and component mapping
- Package version and rollback checks
- Evidence freshness and provenance
- Unexpected component detection
- Static ransomware indicator scanning

## 3. Assessment Decisions

The system uses three principal security decisions:

- **Allow:** Evidence satisfies the applicable assessment requirements.
- **Investigate:** Evidence is incomplete, uncertain, or requires additional review.
- **Quarantine:** Evidence indicates a serious security or trust concern requiring isolation from the normal release workflow.

These are assessment decisions, not automated physical or deployment actions.

Human review remains mandatory.

## 4. Main Application Modules

### Security Dashboard
Displays supply-chain assessment information, security indicators, and scenario summaries.

### Supply-Chain Assessment
Evaluates package integrity, signatures, vendors, components, dependencies, and evidence.

### Customer SBOM Assessment
Accepts CycloneDX JSON and SPDX JSON SBOM documents and performs structural checks, component extraction, provenance assessment, baseline comparison, and vulnerability assessment.

### VEX Management
Supports vulnerability exploitability information and VEX export and validation workflows.

### Ransomware Assessment
Provides static ransomware-related assessment capabilities.

### YARA Scanner
Scans supplied files for configured synthetic static indicators. It does not execute uploaded files.

### Workflow and Audit
Provides human-review workflows, approval records, simulation endpoints, and audit information.

## 5. Technology Stack

### Backend
- Python
- FastAPI
- Pydantic
- Pytest

### Frontend
- React
- TypeScript
- Vite
- Tailwind CSS
- Recharts

### Security and Intelligence
- SHA-256
- Digital signature and trust assessment
- CycloneDX and SPDX SBOM formats
- VEX
- YARA
- NIST NVD vulnerability intelligence

## 6. Application Architecture

```text
React + TypeScript Frontend
           |
           v
       FastAPI API
           |
           v
 Deterministic Assessment
           |
     +-----+------+
     |            |
     v            v
 Evidence      Vulnerability
 Validation    Intelligence
     |            |
     +-----+------+
           |
           v
 Risk and Decision Engine
           |
           v
 Human Review Workflow
           |
           v
 Audit and Reporting
```

Deterministic assessment results remain authoritative. External vulnerability intelligence and advisory information do not independently authorize deployment.

## 7. Running the Application

### Backend

From the repository root:

```powershell
.venv\Scripts\Activate.ps1

python -m uvicorn src.supply_chain.api.app:app --host 127.0.0.1 --port 8010
```

Backend health:

http://127.0.0.1:8010/api/health

API documentation:

http://127.0.0.1:8010/docs

### Frontend

Open another terminal:

```powershell
cd frontend/firmwareguard

npm install
npm run dev
```

Frontend:

http://localhost:3001

## 8. API Endpoints

The current application exposes these principal endpoints:

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Health check |
| GET | `/api/scenarios` | Scenario information |
| GET | `/api/metrics` | Security metrics |
| GET | `/api/performance-dashboard` | Performance dashboard |
| GET | `/api/workflow` | Workflow information |
| GET | `/api/audit` | Audit records |
| POST | `/api/supply-chain/assess` | Supply-chain assessment |
| POST | `/api/workflow/{scenario_id}/approval` | Human approval workflow |
| POST | `/api/workflow/{scenario_id}/simulate-release` | Release simulation |
| POST | `/api/customer-assessment/analyze` | Customer SBOM assessment |
| POST | `/api/ransomware-assessment/analyze` | Ransomware assessment |
| POST | `/api/ransomware-assessment/scan` | Static indicator scan |

## 9. Validation and Testing

### Backend tests

```powershell
python -m pytest src -q
```

Previously verified result: 138 tests passed.

### Frontend lint

```powershell
cd frontend/firmwareguard
npm run lint
```

### Frontend production build

```powershell
npm run build
```

Previously verified: lint and production build passed.

These results describe the recorded verification run. Run the commands again after making further code changes.

## 10. Synthetic Scenario Catalogue

The project includes ten controlled supply-chain scenarios:

- SC-001: Package hash mismatch
- SC-002: Package integrity mismatch
- SC-003: Invalid signature or untrusted root
- SC-004: Vulnerable component
- SC-005: Unauthorized rollback
- SC-006: Missing SBOM
- SC-007: Unexpected component
- SC-008: Untrusted vendor
- SC-009: Unauthorized rollback scenario
- SC-010: Stale evidence

The scenarios are synthetic and intended for controlled testing and demonstration.

## 11. Safety and Responsible Use

FirmwareGuard is designed as a read-only assessment proof of concept.

It does not:

- Flash firmware
- Install software
- Execute firmware
- Automatically deploy packages
- Automatically quarantine real devices
- Modify production systems
- Perform destructive actions

Human approval is required. Deployment remains disabled, and real actions are not executed.

## 12. Machine Learning Experiment Status

Experiment v1 has been submitted and remains **REJECTED**.

Its original models, predictions, and manifest are preserved.

The correction work includes repository validation, an offline input guard, and post-hoc evidence. No new training was performed.

Machine learning must remain advisory and must not override deterministic evidence such as hash, signature, trusted-root, vendor, rollback, or SBOM failures.

Start with:

- `docs/CORRECTION_HANDOVER.md`
- `VALIDATION_RESULTS.md`

Any future Experiment v2 requires a new approved protocol and quarantined holdout.

Rule/ML fusion, API integration, and dashboard integration remain unapproved.

## 13. Validated Dataset Contract

The synthetic dataset contains 5,000 assessments across 500 firmware package lineages, with 10 assessments per lineage.

Data roles are isolated:

- `reference_data.csv`: approved vendor, hash, version, freshness, and component facts
- `reference_catalog.csv`: vendor trust and component catalog
- `observable_features.csv`: runtime-visible observations only
- `ground_truth_labels.csv`: labels and deterministic label provenance
- `scenario_manifests.csv`: generation recipes and safe mutation parameters
- `split_assignments.csv`: 70/15/15 lineage-grouped assignments
- `engineered_features.csv`: numeric, leakage-safe model features

Every record has a reproducible seed and run ID. All members of a lineage stay within one split.

## 14. Standards Benchmark

`scripts/framework_benchmark.py` performs a reproducible pre-ML framework gate.

It validates raw SBOM fixtures against the bundled CycloneDX 1.5 JSON schema, verifies evidence-to-SBOM hashes, checks dataset coverage, and generates coverage and gap mappings for:

- SLSA 1.2
- NIST SP 800-193
- NIST SP 800-218 SSDF

Results are under:

`benchmarks/frameworks/results/`

This is a conformance and coverage assessment, not certification.

## 15. Project Limitations

- Synthetic test scenarios do not establish production effectiveness.
- Vulnerability applicability requires independent verification.
- Customer SBOM assessment does not establish that a supplied firmware binary is safe.
- Customer-entered hash metadata is not equivalent to independently hashing a firmware binary.
- Product mapping and baseline comparison have defined PoC limitations.
- External intelligence availability may vary.
- The system is not a certified production security platform.

## 16. Current Project Status

The following work has been implemented and previously verified:

- Backend assessment APIs
- Supply-chain scenario assessment
- Customer SBOM assessment
- VEX validation and export
- YARA-based static scanning
- Ransomware assessment
- Human-review workflow
- Audit functionality
- Frontend integration
- Backend and frontend test/build verification

The current internship branch is:

`feature/responsible-ai-ransomware`

The project remains a proof of concept and requires further independent security review before production use.
