"""Customer SBOM intake and read-only assessment API.

The vulnerability catalog is synthetic for this PoC. Live NVD results are
candidate findings only and require human applicability review.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .nvd_client import search_components


router = APIRouter(
    prefix="/api/customer-assessment",
    tags=["Customer SBOM Assessment"],
)

_AUDIT_LOCK = threading.Lock()

SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
MAX_SBOM_BYTES = 2 * 1024 * 1024


DEMO_VULNERABILITY_CATALOG = [
    {
        "demo_id": "DEMO-VULN-001",
        "package_name": "openssl",
        "affected_versions": ["1.0.2", "1.0.2u", "1.1.0"],
        "severity": "critical",
        "cvss": 9.8,
        "description": (
            "Synthetic demonstration finding: legacy cryptographic library version."
        ),
        "recommendation": (
            "Validate vendor-supported remediation and upgrade compatibility."
        ),
    },
    {
        "demo_id": "DEMO-VULN-002",
        "package_name": "log4j",
        "affected_versions": ["2.14.0", "2.14.1", "2.15.0"],
        "severity": "critical",
        "cvss": 10.0,
        "description": (
            "Synthetic demonstration finding: example logging dependency version."
        ),
        "recommendation": (
            "Confirm reachability and apply a vendor-approved fixed release."
        ),
    },
    {
        "demo_id": "DEMO-VULN-003",
        "package_name": "busybox",
        "affected_versions": ["1.30.0", "1.31.0"],
        "severity": "high",
        "cvss": 8.1,
        "description": (
            "Synthetic demonstration finding: example embedded utility version."
        ),
        "recommendation": (
            "Check the device vendor's patched firmware and compatibility notes."
        ),
    },
    {
        "demo_id": "DEMO-VULN-004",
        "package_name": "curl",
        "affected_versions": ["7.60.0", "7.61.0"],
        "severity": "medium",
        "cvss": 6.5,
        "description": (
            "Synthetic demonstration finding: example network library version."
        ),
        "recommendation": (
            "Review exposure and update to a vendor-supported version."
        ),
    },
]


class CustomerAssessmentRequest(BaseModel):
    industry: Literal["industrial", "telecom", "healthcare"]
    customer_name: str = Field(min_length=1, max_length=120)
    product_name: str = Field(min_length=1, max_length=160)
    firmware_version: str = Field(min_length=1, max_length=80)
    firmware_sha256: str = Field(pattern=r"^[A-Fa-f0-9]{64}$")
    approved_baseline_sha256: str | None = Field(
        default=None,
        max_length=64,
    )
    approved_baseline_version: str | None = Field(
        default=None,
        max_length=80,
    )
    sbom: dict[str, Any]
    provenance_source: str = Field(default="", max_length=300)
    supplier_name: str = Field(default="", max_length=160)


def _components(
    sbom: dict[str, Any],
) -> tuple[str, list[dict[str, str]]]:
    fmt = str(sbom.get("bomFormat", "")).lower()

    if fmt == "cyclonedx":
        raw = sbom.get("components", [])
        normalized: list[dict[str, str]] = []

        if isinstance(raw, list):
            for item in raw:
                if not isinstance(item, dict):
                    continue

                normalized.append(
                    {
                        "name": str(item.get("name", "")).strip(),
                        "version": str(item.get("version", "")).strip(),
                        "purl": str(item.get("purl", "")).strip(),
                        "type": str(item.get("type", "library")).strip(),
                    }
                )

        return "CycloneDX", normalized

    if (
        "spdxVersion" in sbom
        or sbom.get("SPDXID") == "SPDXRef-DOCUMENT"
    ):
        raw = sbom.get("packages", [])
        normalized = []

        if isinstance(raw, list):
            for item in raw:
                if not isinstance(item, dict):
                    continue

                purl = ""
                refs = item.get("externalRefs", [])

                if isinstance(refs, list):
                    for ref in refs:
                        if (
                            isinstance(ref, dict)
                            and "purl"
                            in str(ref.get("referenceType", "")).lower()
                        ):
                            purl = str(ref.get("referenceLocator", ""))
                            break

                normalized.append(
                    {
                        "name": str(item.get("name", "")).strip(),
                        "version": str(item.get("versionInfo", "")).strip(),
                        "purl": purl,
                        "type": "library",
                    }
                )

        return "SPDX", normalized

    raise HTTPException(
        status_code=422,
        detail="Unsupported SBOM. Provide CycloneDX JSON or SPDX JSON.",
    )


def _risk(
    findings: list[dict[str, Any]],
    baseline_status: str,
    completeness: str,
) -> tuple[int, str]:
    score = 0
    weights = {
        "critical": 35,
        "high": 22,
        "medium": 12,
        "low": 5,
    }

    for finding in findings:
        score += weights.get(finding["severity"], 0)

    if baseline_status == "mismatch":
        score += 35
    elif baseline_status == "missing":
        score += 10

    if completeness != "complete":
        score += 10

    score = min(score, 100)

    if score >= 70:
        level = "critical"
    elif score >= 40:
        level = "high"
    elif score >= 20:
        level = "medium"
    else:
        level = "low"

    return score, level


@router.post("/analyze")
def analyze_customer_sbom(request: CustomerAssessmentRequest):
    sbom_bytes = json.dumps(
        request.sbom,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    if len(sbom_bytes) > MAX_SBOM_BYTES:
        raise HTTPException(
            status_code=413,
            detail="SBOM exceeds the 2 MB PoC limit.",
        )

    if (
        request.approved_baseline_sha256
        and not SHA256_RE.fullmatch(request.approved_baseline_sha256)
    ):
        raise HTTPException(
            status_code=422,
            detail=(
                "Approved baseline SHA-256 must contain "
                "64 hexadecimal characters."
            ),
        )

    sbom_format, components = _components(request.sbom)
    warnings: list[str] = []

    if not components:
        warnings.append("No component records were found in the SBOM.")

    missing_fields = [
        label
        for label, value in [
            ("provenance source", request.provenance_source),
            ("supplier name", request.supplier_name),
        ]
        if not value.strip()
    ]

    if missing_fields:
        warnings.append(
            "Missing provenance fields: "
            + ", ".join(missing_fields)
            + "."
        )

    complete_components = [
        component
        for component in components
        if component["name"] and component["version"]
    ]

    completeness = (
        "complete"
        if (
            components
            and len(complete_components) == len(components)
            and not missing_fields
        )
        else "incomplete"
    )

    product_component = {}
    metadata = request.sbom.get("metadata", {})

    if (
        sbom_format == "CycloneDX"
        and isinstance(metadata, dict)
    ):
        product_component = metadata.get("component", {})

    sbom_product_name = (
        str(product_component.get("name", "")).strip()
        if isinstance(product_component, dict)
        else ""
    )

    if sbom_format == "SPDX":
        sbom_product_name = str(
            request.sbom.get("name", "")
        ).strip()

    product_mapping = {
        "customer_product": request.product_name,
        "sbom_root_component": sbom_product_name or None,
        "mapped": (
            bool(sbom_product_name)
            and sbom_product_name.casefold()
            == request.product_name.casefold()
        ),
        "note": (
            "Exact name match only; confirm mapping "
            "with the customer product inventory."
        ),
    }

    findings = []

    for component in complete_components:
        for entry in DEMO_VULNERABILITY_CATALOG:
            if (
                component["name"].casefold()
                == entry["package_name"]
                and component["version"] in entry["affected_versions"]
            ):
                findings.append(
                    {
                        "demo_id": entry["demo_id"],
                        "component": component["name"],
                        "version": component["version"],
                        "purl": component["purl"] or None,
                        "severity": entry["severity"],
                        "cvss_demo_score": entry["cvss"],
                        "description": entry["description"],
                        "recommendation": entry["recommendation"],
                        "evidence_source": (
                            "Built-in synthetic demonstration catalog"
                        ),
                    }
                )

    # Live NVD candidates are kept separate from synthetic findings.
    # They do not automatically affect the deterministic risk score.
    nvd_result = search_components(
        complete_components,
        max_components=3,
    )

    if request.approved_baseline_sha256:
        baseline_status = (
            "match"
            if (
                request.firmware_sha256.lower()
                == request.approved_baseline_sha256.lower()
            )
            else "mismatch"
        )
    elif request.approved_baseline_version:
        baseline_status = (
            "match"
            if (
                request.firmware_version
                == request.approved_baseline_version
            )
            else "mismatch"
        )
    else:
        baseline_status = "missing"

    risk_score, risk_level = _risk(
        findings,
        baseline_status,
        completeness,
    )

    if baseline_status == "mismatch":
        recommendation = "release_hold_review"
    elif risk_level in ("critical", "high"):
        recommendation = "analyst_review"
    elif completeness != "complete" or not product_mapping["mapped"]:
        recommendation = "investigate"
    else:
        recommendation = "review_and_document"

    assessed_at = datetime.now(timezone.utc).isoformat()
    assessment_id = (
        "CUST-"
        + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        + "-"
        + uuid.uuid4().hex[:8].upper()
    )

    result = {
        "assessment_id": assessment_id,
        "assessed_at": assessed_at,
        "industry": request.industry,
        "customer_name": request.customer_name,
        "product_name": request.product_name,
        "firmware_version": request.firmware_version,
        "firmware_sha256": request.firmware_sha256.lower(),
        "sbom_format": sbom_format,
        "sbom_sha256": hashlib.sha256(sbom_bytes).hexdigest(),
        "component_count": len(components),
        "components_with_name_and_version": len(complete_components),
        "completeness": completeness,
        "provenance": {
            "source": request.provenance_source or None,
            "supplier": request.supplier_name or None,
            "status": (
                "provided" if not missing_fields else "incomplete"
            ),
        },
        "product_mapping": product_mapping,
        "baseline_comparison": {
            "status": baseline_status,
            "submitted_version": request.firmware_version,
            "approved_version": request.approved_baseline_version,
            "approved_sha256": request.approved_baseline_sha256,
            "submitted_sha256": request.firmware_sha256.lower(),
        },
        "vulnerability_matching": {
            "catalog": "synthetic_demo_catalog",
            "catalog_is_live": False,
            "findings_count": len(findings),
            "findings": findings,
            "live_nvd": nvd_result,
        },
        "risk": {
            "score": risk_score,
            "level": risk_level,
        },
        "recommendation": recommendation,
        "warnings": warnings + [
            (
                "Synthetic demonstration findings are separate "
                "from live NVD candidate CVEs."
            ),
            (
                "NVD keyword results require affected-product and "
                "version applicability review; they are not "
                "confirmed vulnerabilities."
            ),
            (
                "Firmware hash is customer-supplied metadata; "
                "the API does not receive or hash a firmware binary."
            ),
            (
                "No binary is executed, installed, modified, or deployed."
            ),
            (
                "Analyst review is required; this result is not "
                "a release authorization."
            ),
        ],
        "human_review_required": True,
        "deployment_allowed": False,
        "real_action_executed": False,
    }

    # Store only compact assessment metadata.
    # Do not persist the uploaded SBOM or customer firmware hash.
    project_root = Path(__file__).resolve().parents[3]
    audit_path = (
        project_root
        / "artifacts"
        / "dashboard"
        / "audit.jsonl"
    )
    audit_path.parent.mkdir(parents=True, exist_ok=True)

    audit_event = {
        "event": "customer_sbom_assessment_completed",
        "assessment_id": result["assessment_id"],
        "industry": request.industry,
        "product_name": request.product_name,
        "risk_level": risk_level,
        "risk_score": risk_score,
        "recommendation": recommendation,
        "deployment_allowed": False,
        "real_action_executed": False,
        "timestamp": assessed_at,
    }

    with _AUDIT_LOCK:
        with audit_path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(audit_event, ensure_ascii=False) + "\n"
            )

    return result