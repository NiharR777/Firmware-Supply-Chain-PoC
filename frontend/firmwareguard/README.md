
# FirmwareGuard – Firmware & Supply-Chain Security

FirmwareGuard is a React and TypeScript frontend for a firmware and software supply-chain security proof of concept.

It connects to a FastAPI backend to assess firmware package evidence, customer SBOMs, vulnerabilities, vendor trust, and ransomware indicators.

## Features

- Firmware supply-chain security dashboard
- SHA-256 integrity verification
- Digital signature and trusted-root assessment
- Vendor trust and provenance checks
- SBOM component and vulnerability assessment
- Dependency and component analysis
- VEX export and validation
- Customer SBOM assessment
- Static ransomware indicator scanning using YARA
- Human-review and approval workflow
- Audit and performance dashboards

## Technology Stack

- React
- TypeScript
- Vite
- Tailwind CSS
- Recharts
- FastAPI backend
- Python

## Prerequisites

- Node.js and npm
- Python and the backend virtual environment
- Access to the FirmwareGuard backend

## Run the Frontend

From this directory:

```bash
npm install
npm run dev
```

The development server is configured to run at:

http://localhost:3001

## Run the Backend

From the repository root, activate the Python virtual environment and start the API:

```bash
python -m uvicorn src.supply_chain.api.app:app --host 127.0.0.1 --port 8010
```

Backend health endpoint:

http://127.0.0.1:8010/api/health

API documentation:

http://127.0.0.1:8010/docs

## Validation

Run frontend linting:

```bash
npm run lint
```

Run the production build:

```bash
npm run build
```

Run backend tests from the repository root:

```bash
python -m pytest src -q
```

## Security and Safety Boundaries

FirmwareGuard is a proof of concept using synthetic supply-chain scenarios and controlled assessment workflows.

- Assessment results are recommendations for human review.
- AI or external vulnerability intelligence does not independently authorize deployment.
- Customer-supplied firmware hashes are treated as metadata unless a separate binary verification process is explicitly performed.
- Firmware is not flashed, installed, or executed.
- No real production device is modified.
- Deployment is disabled by design.
- Real-world applicability must be independently verified before operational use.

## Important

The application is an internship proof of concept, not a certified production firmware-security platform.
