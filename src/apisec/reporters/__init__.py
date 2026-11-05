"""Report writers: JSON, Markdown, SARIF 2.1.0."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from .. import __version__
from ..models import Finding

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
# SARIF only knows error / warning / note.
SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.endpoint))


def to_json(findings: list[Finding], target: str) -> str:
    doc = {
        "tool": {"name": "api-security-toolkit", "version": __version__},
        "target": target,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": {"total": len(findings)},
        "findings": [f.to_dict() for f in _sorted(findings)],
    }
    return json.dumps(doc, indent=2)


def to_markdown(findings: list[Finding], target: str) -> str:
    lines = [
        "# API Security Scan Report",
        "",
        f"- **Target:** `{target}`",
        f"- **Tool:** api-security-toolkit {__version__}",
        f"- **Findings:** {len(findings)}",
        "",
        "> Only test systems you own or are authorized to test.",
        "",
    ]
    if not findings:
        lines.append("No findings.")
    for i, f in enumerate(_sorted(findings), 1):
        lines += [
            f"## {i}. [{f.severity.upper()}] {f.title}",
            "",
            f"- **Endpoint:** `{f.endpoint}`",
            f"- **OWASP:** {f.owasp}",
            f"- **Confidence:** {f.confidence}",
            f"- **Description:** {f.description}",
            f"- **Evidence:** `{f.evidence}`",
            f"- **Remediation:** {f.remediation}",
            "",
        ]
    return "\n".join(lines)


def to_sarif(findings: list[Finding], target: str, spec_path: str = "openapi.json") -> str:
    """SARIF 2.1.0. API findings have no source line, so results point at the spec file
    (the contract under test) and carry the HTTP endpoint as a logical location."""
    rules: dict[str, dict] = {}
    for f in findings:
        rules.setdefault(
            f.check_id,
            {
                "id": f.check_id,
                "name": f.title.replace(" ", ""),
                "shortDescription": {"text": f.title},
                "helpUri": "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
                "properties": {"tags": ["security", f.owasp]},
            },
        )
    results = [
        {
            "ruleId": f.check_id,
            "level": SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"{f.description} Remediation: {f.remediation}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": spec_path},
                        "region": {"startLine": 1},
                    },
                    "logicalLocations": [{"name": f.endpoint, "kind": "function"}],
                }
            ],
            "properties": {"confidence": f.confidence, "evidence": f.evidence, "owasp": f.owasp},
        }
        for f in _sorted(findings)
    ]
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "api-security-toolkit",
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {"target": target},
            }
        ],
    }
    return json.dumps(doc, indent=2)


WRITERS = {"json": (to_json, "json"), "md": (to_markdown, "md"), "sarif": (to_sarif, "sarif")}
