"""API8:2023-style injection probing (error-based SQL injection signals).

Sends classic metacharacter payloads in query, path and JSON-body string parameters and looks
for database error signatures, or a new 5xx that the baseline request did not produce.
This is a detector for obvious injection points, not an exploitation tool.
"""

from __future__ import annotations

import re

from ..client import Identity
from ..models import Endpoint, Finding
from .base import Check, ScanContext, fill_path

PAYLOADS = ["'", '"', "' OR '1'='1' --", "1; SELECT 1--"]

SQL_ERRORS = re.compile(
    r"(sql syntax|sqlite[_ ]?error|sqlite3\.|unrecognized token|psycopg2|pg_query|"
    r"ora-\d{5}|odbc|mysql_fetch|unclosed quotation mark|syntax error at or near|"
    r"sqlalchemy\.exc|operationalerror|mongoerror)",
    re.IGNORECASE,
)


class InjectionCheck(Check):
    id = "injection"
    owasp = "API8:2023"  # Security Misconfiguration / injection class in the 2023 list
    title = "Possible SQL/NoSQL injection"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for ep in ctx.endpoints:
            if ep.method not in {"GET", "POST"}:
                continue
            finding = self._test_endpoint(ctx, ep, ctx.user_a)
            if finding:
                findings.append(finding)
        return findings

    def _send(
        self,
        ctx: ScanContext,
        ep: Endpoint,
        identity: Identity | None,
        target: tuple[str, str] | None,
        payload: str,
    ):
        """Send one request, putting `payload` into target=(location, name)."""
        path_vals: dict[str, str] = {}
        query: dict[str, str] = {}
        body: dict[str, str] = {}
        for p in ep.params:
            if p.location == "path":
                path_vals[p.name] = "1"
            elif p.location == "query":
                query[p.name] = "1"
            elif p.location == "body" and p.type == "string":
                body[p.name] = "test"
        if target:
            loc, name = target
            {"path": path_vals, "query": query, "body": body}[loc][name] = payload
        return ctx.client.request(
            ep.method,
            fill_path(ep.path, path_vals),
            identity,
            params=query or None,
            json_body=body or None,
        )

    def _test_endpoint(
        self, ctx: ScanContext, ep: Endpoint, identity: Identity | None
    ) -> Finding | None:
        targets = [
            (p.location, p.name)
            for p in ep.params
            if p.location in {"path", "query", "body"} and p.type == "string"
        ]
        if not targets:
            return None
        baseline = self._send(ctx, ep, identity, None, "1")
        base_status = baseline.status_code if baseline is not None else None
        for target in targets:
            for payload in PAYLOADS:
                resp = self._send(ctx, ep, identity, target, payload)
                if resp is None:
                    continue
                error_hit = SQL_ERRORS.search(resp.text or "")
                new_5xx = resp.status_code >= 500 and (base_status or 0) < 500
                if error_hit or new_5xx:
                    why = (
                        f"database error signature '{error_hit.group(0)}'"
                        if error_hit
                        else f"server error {resp.status_code} (baseline {base_status})"
                    )
                    return Finding(
                        check_id=self.id,
                        owasp=self.owasp,
                        title=self.title,
                        severity="high" if error_hit else "medium",
                        endpoint=ep.key,
                        description=(
                            f"Parameter '{target[1]}' ({target[0]}) triggered {why} when sent "
                            f"the payload {payload!r}."
                        ),
                        evidence=f"payload={payload!r} -> HTTP {resp.status_code}",
                        remediation=(
                            "Use parameterized queries / an ORM, validate input types, and "
                            "never return raw database errors to clients."
                        ),
                        confidence="high" if error_hit else "low",
                    )
        return None
