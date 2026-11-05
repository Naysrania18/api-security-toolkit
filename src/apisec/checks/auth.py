"""API2:2023 Broken Authentication.

For endpoints the spec marks as secured, send: no credentials, a garbage token, and a valid
token with its last character altered. Any 2xx means authentication is not enforced.
"""

from __future__ import annotations

from ..client import Identity
from ..models import Finding
from .base import Check, ScanContext, fill_path


class BrokenAuthCheck(Check):
    id = "broken-auth"
    owasp = "API2:2023"
    title = "Broken Authentication"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for ep in ctx.endpoints:
            if not ep.secured or ep.method != "GET":
                continue  # only safe (read-only) methods are probed without credentials
            path = fill_path(ep.path, {})
            for label, identity in self._variants(ctx):
                resp = ctx.client.request(ep.method, path, identity)
                if resp is not None and 200 <= resp.status_code < 300:
                    findings.append(
                        Finding(
                            check_id=self.id,
                            owasp=self.owasp,
                            title=self.title,
                            severity="high",
                            endpoint=ep.key,
                            description=(
                                "Endpoint is marked as secured in the spec but accepted a "
                                f"request with {label}."
                            ),
                            evidence=f"{ep.method} {path} with {label} -> {resp.status_code}",
                            remediation=(
                                "Validate the token signature, expiry and audience on every "
                                "protected route; reject missing or malformed credentials "
                                "with 401."
                            ),
                            confidence="high",
                        )
                    )
                    break  # one finding per endpoint is enough
        return findings

    @staticmethod
    def _variants(ctx: ScanContext) -> list[tuple[str, Identity | None]]:
        variants: list[tuple[str, Identity | None]] = [
            ("no credentials", None),
            ("an invalid token", Identity("bogus", "not-a-real-token")),
        ]
        if ctx.user_a and ctx.user_a.token:
            last = ctx.user_a.token[-1]
            tampered = ctx.user_a.token[:-1] + ("A" if last != "A" else "B")
            variants.append(("a tampered token", Identity("tampered", tampered, ctx.user_a.scheme)))
        return variants
