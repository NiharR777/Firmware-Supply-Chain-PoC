
"""Read-only NIST NVD CVE API 2.0 connector for FirmwareGuard.

Returns candidate CVEs for SBOM components.
Keyword matches are not proof of affected-version applicability.
Human review is always required.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

REQUEST_TIMEOUT_SECONDS = 15
MAX_RESULTS_PER_COMPONENT = 10
MAX_COMPONENTS_PER_ASSESSMENT = 5
MIN_REQUEST_INTERVAL = 6.5
CACHE_TTL_SECONDS = 1800

_last_request_time = 0.0

_CACHE: dict[str, tuple[float, list[dict[str, Any]]]] = {}


def _severity_from_score(
    score: float | None,
    supplied: str | None,
) -> str:
    if supplied:
        severity = supplied.strip().lower()
        if severity in {"critical", "high", "medium", "low"}:
            return severity

    if score is None:
        return "unknown"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"

    return "unknown"


def _extract_metrics(
    cve: dict[str, Any],
) -> tuple[float | None, str | None, str | None]:

    metrics = cve.get("metrics", {})

    if not isinstance(metrics, dict):
        return None, None, None

    metric_types = (
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    )

    for metric_type in metric_types:
        entries = metrics.get(metric_type, [])

        if not isinstance(entries, list) or not entries:
            continue

        for entry in entries:
            if not isinstance(entry, dict):
                continue

            data = entry.get("cvssData", {})

            if not isinstance(data, dict):
                continue

            score = data.get("baseScore")
            severity = (
                data.get("baseSeverity")
                or entry.get("baseSeverity")
            )

            try:
                numeric_score = (
                    float(score) if score is not None else None
                )
            except (ValueError, TypeError):
                numeric_score = None

            return (
                numeric_score,
                severity,
                data.get("version"),
            )

    return None, None, None


def _extract_description(cve: dict[str, Any]) -> str:

    descriptions = cve.get("descriptions", [])

    if isinstance(descriptions, list):
        for item in descriptions:
            if (
                isinstance(item, dict)
                and item.get("lang") == "en"
                and item.get("value")
            ):
                return str(item["value"])[:2000]

    return "No English description supplied by NVD."


def _extract_references(cve: dict[str, Any]) -> list[str]:

    output = []

    references = cve.get("references", [])

    if isinstance(references, list):
        for reference in references[:8]:
            if isinstance(reference, dict):
                url = reference.get("url")
                if url:
                    output.append(str(url))

    return output


def _extract_cpe_criteria(cve: dict[str, Any]) -> list[str]:
    """Extract NVD CPE criteria for subsequent applicability review."""

    criteria: list[str] = []

    def walk(node: Any) -> None:

        if isinstance(node, dict):

            matches = node.get("cpeMatch", [])

            if isinstance(matches, list):
                for match in matches:
                    if (
                        isinstance(match, dict)
                        and match.get("criteria")
                    ):
                        criteria.append(
                            str(match["criteria"])
                        )

            for value in node.values():
                if isinstance(value, (dict, list)):
                    walk(value)

        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(cve.get("configurations", []))

    return list(dict.fromkeys(criteria))[:20]


def _parse_cve_item(
    item: dict[str, Any],
    component: dict[str, str],
) -> dict[str, Any] | None:

    cve = item.get("cve", {})

    if not isinstance(cve, dict):
        return None

    cve_id = cve.get("id")

    if not cve_id:
        return None

    score, supplied_severity, cvss_version = (
        _extract_metrics(cve)
    )

    severity = _severity_from_score(
        score,
        supplied_severity,
    )

    return {
        "cve_id": str(cve_id),
        "component": component.get("name", ""),
        "version": component.get("version", ""),
        "severity": severity,
        "cvss_score": score,
        "cvss_version": cvss_version,
        "description": _extract_description(cve),
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "references": _extract_references(cve),
        "cpe_criteria": _extract_cpe_criteria(cve),

        "match_status": (
            "candidate_requires_applicability_review"
        ),
        "applicability_verified": False,

        "evidence_source": (
            "NIST National Vulnerability Database (NVD) API 2.0"
        ),

        "recommendation": (
            "Review NVD affected-product information and vendor "
            "advisory. Confirm exact product, version, configuration "
            "and patch compatibility before remediation."
        ),
    }


def search_component(
    component: dict[str, str],
) -> dict[str, Any]:
    """Retrieve candidate CVEs for a named and versioned component."""

    name = str(component.get("name", "")).strip()
    version = str(component.get("version", "")).strip()

    if not name or not version:
        return {
            "status": "skipped",
            "reason": "Component name and version are required.",
            "findings": [],
        }

    cache_key = (
        f"{name.casefold()}::{version.casefold()}"
    )

    cached = _CACHE.get(cache_key)

    if (
        cached
        and time.time() - cached[0] < CACHE_TTL_SECONDS
    ):
        return {
            "status": "ok",
            "cached": True,
            "findings": cached[1],
        }

    global _last_request_time

    elapsed = time.monotonic() - _last_request_time

    if elapsed < MIN_REQUEST_INTERVAL:
        time.sleep(MIN_REQUEST_INTERVAL - elapsed)

    params = urlencode({
        "keywordSearch": f"{name} {version}",
        "resultsPerPage": MAX_RESULTS_PER_COMPONENT,
    })

    headers = {
        "User-Agent": "FirmwareGuard-PoC/1.0",
        "Accept": "application/json",
    }

    api_key = os.getenv("NVD_API_KEY", "").strip()

    if api_key:
        headers["apiKey"] = api_key

    request = Request(
        f"{NVD_CVE_API}?{params}",
        headers=headers,
        method="GET",
    )

    try:
        _last_request_time = time.monotonic()

        with urlopen(
            request,
            timeout=REQUEST_TIMEOUT_SECONDS,
        ) as response:

            payload = json.loads(
                response.read().decode("utf-8")
            )

        vulnerabilities = payload.get(
            "vulnerabilities", []
        )

        findings = []

        if isinstance(vulnerabilities, list):
            for item in vulnerabilities:

                if not isinstance(item, dict):
                    continue

                parsed = _parse_cve_item(
                    item,
                    component,
                )

                if parsed:
                    findings.append(parsed)

        _CACHE[cache_key] = (
            time.time(),
            findings,
        )

        return {
            "status": "ok",
            "cached": False,
            "total_results": payload.get(
                "totalResults",
                len(findings),
            ),
            "findings": findings,
        }

    except HTTPError as exc:

        if exc.code == 429:
            return {
                "status": "rate_limited",
                "reason": (
                    "NVD rate limit reached. Retry later."
                ),
                "findings": [],
            }

        return {
            "status": "unavailable",
            "reason": f"NVD returned HTTP {exc.code}.",
            "findings": [],
        }

    except (
        URLError,
        TimeoutError,
        OSError,
        json.JSONDecodeError,
    ) as exc:

        return {
            "status": "unavailable",
            "reason": (
                f"NVD connection or response error: "
                f"{type(exc).__name__}."
            ),
            "findings": [],
        }


def search_components(
    components: list[dict[str, str]],
    max_components: int = MAX_COMPONENTS_PER_ASSESSMENT,
) -> dict[str, Any]:
    """Search a bounded number of components against live NVD."""

    findings: list[dict[str, Any]] = []
    component_results = []
    errors = []

    selected = components[:max_components]

    for component in selected:

        result = search_component(component)

        component_results.append({
            "component": component.get("name", ""),
            "version": component.get("version", ""),
            "status": result["status"],
            "candidate_count": len(
                result.get("findings", [])
            ),
        })

        findings.extend(
            result.get("findings", [])
        )

        if result["status"] != "ok":
            errors.append({
                "component": component.get("name", ""),
                "status": result["status"],
                "reason": result.get(
                    "reason",
                    "NVD lookup failed.",
                ),
            })

    return {
        "provider": "NVD API 2.0",
        "is_live_source": True,
        "components_checked": len(selected),
        "components_skipped": max(
            0,
            len(components) - len(selected),
        ),
        "findings_count": len(findings),
        "findings": findings,
        "component_results": component_results,
        "errors": errors,
        "applicability_note": (
            "NVD keyword results are candidate CVEs only. "
            "Exact affected-version applicability has not "
            "been verified."
        ),
    }
