"""API3:2023 Broken Object Property Level Authorization (excessive data exposure).

Calls read-only endpoints and flags sensitive-looking field names in JSON responses.
"""

from __future__ import annotations

import re

from ..models import Finding
from .base import Check, ScanContext, fill_path

SENSITIVE = re.compile(
    r"^(password|passwd|pwd|password_?hash|hash|secret|api_?key|token|auth_?token|"
    r"access_?token|refresh_?token|ssn|credit_?card|card_?number|private_?key)$",
    re.IGNORECASE,
)


def find_sensitive_keys(data: object, prefix: str = "") -> list[str]:
    hits: list[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            full = f"{prefix}.{key}" if prefix else str(key)
            if SENSITIVE.match(str(key)):
                hits.append(full)
            hits.extend(find_sensitive_keys(value, full))
    elif isinstance(data, list):
        for item in data[:5]:  # sample the first few items
            hits.extend(find_sensitive_keys(item, prefix + "[]"))
    return hits


class ExposureCheck(Check):
    id = "data-exposure"
    owasp = "API3:2023"
    title = "Excessive data exposure"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for ep in ctx.endpoints:
            if ep.method != "GET":
                continue
            path = fill_path(ep.path, {})
            resp = ctx.client.request("GET", path, ctx.user_a)
            if resp is None or resp.status_code != 200:
                continue
            try:
                hits = sorted(set(find_sensitive_keys(resp.json())))
            except ValueError:
                continue
            if hits:
                findings.append(
                    Finding(
                        check_id=self.id,
                        owasp=self.owasp,
                        title=self.title,
                        severity="medium",
                        endpoint=ep.key,
                        description="Response contains fields that look sensitive: "
                        + ", ".join(hits),
                        evidence=f"GET {path} -> 200, fields: {hits}",
                        remediation=(
                            "Return only the fields the client needs (explicit response "
                            "schemas / DTOs) and never expose secrets or password hashes."
                        ),
                        confidence="medium",
                    )
                )
        return findings
