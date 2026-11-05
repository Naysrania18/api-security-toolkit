"""API1:2023 Broken Object Level Authorization (BOLA / IDOR).

Method: learn real object ids as user A (via the collection endpoint), then request the same
objects as user B. If B receives the object, object-level authorization is missing.

Confidence:
  high - A's and B's collection listings differ, so the id is provably *not* B's own object.
  low  - listings are identical (global listing), so ownership is unknown; verify manually.
"""

from __future__ import annotations

from ..models import Endpoint, Finding
from ..sequences import discover_ids
from .base import PATH_PARAM_RE, Check, ScanContext, fill_path


class BolaCheck(Check):
    id = "bola"
    owasp = "API1:2023"
    title = "Broken Object Level Authorization"

    def run(self, ctx: ScanContext) -> list[Finding]:
        if ctx.user_a is None or ctx.user_b is None:
            return []  # needs two identities
        findings: list[Finding] = []
        for ep in ctx.endpoints:
            if ep.method != "GET" or not PATH_PARAM_RE.search(ep.path):
                continue
            ids_a = discover_ids(ctx, ep, ctx.user_a)
            if not ids_a:
                continue
            ids_b = discover_ids(ctx, ep, ctx.user_b)
            foreign = [i for i in ids_a if i not in ids_b]
            confidence = "high"
            if not foreign:
                foreign, confidence = ids_a, "low"
            finding = self._probe(ctx, ep, foreign[:3], confidence)
            if finding:
                findings.append(finding)
        return findings

    def _probe(
        self, ctx: ScanContext, ep: Endpoint, ids: list[str], confidence: str
    ) -> Finding | None:
        param = PATH_PARAM_RE.findall(ep.path)[-1]
        for obj_id in ids:
            path = fill_path(ep.path, {param: obj_id})
            as_a = ctx.client.request("GET", path, ctx.user_a)
            as_b = ctx.client.request("GET", path, ctx.user_b)
            if as_a is None or as_b is None:
                continue
            if as_a.status_code == 200 and as_b.status_code == 200:
                return Finding(
                    check_id=self.id,
                    owasp=self.owasp,
                    title=self.title,
                    severity="high",
                    endpoint=ep.key,
                    description=(
                        f"User '{ctx.user_b.name}' could read object '{obj_id}' that was "
                        f"discovered through user '{ctx.user_a.name}'."
                    ),
                    evidence=f"GET {path} -> 200 for both users (body {len(as_b.content)} bytes)",
                    remediation=(
                        "Enforce object-level authorization on every request: compare the "
                        "authenticated user to the object's owner before returning data."
                    ),
                    confidence=confidence,
                )
        return None
