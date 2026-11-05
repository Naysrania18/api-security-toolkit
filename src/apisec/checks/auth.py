"""API2:2023 Broken Authentication.

For endpoints the spec marks as secured, send: no credentials, a garbage token, and a valid
token with its last character altered. Any 2xx means authentication is not enforced.
"""

from __future__ import annotations

from ..client import Identity
from ..models import Finding
from .base import Check, ScanContext, fill_path


def tamper_token(token: str) -> str:
    """Corrupt a token so a correct verifier must reject it.

    For a JWT we change the FIRST character of the signature: it carries 6 full bits.
    (Changing the last base64 character can be a no-op, because it only carries a few
    meaningful bits and some decoders ignore the rest, which would cause false positives.)
    """
    parts = token.split(".")
    target = parts[2] if len(parts) == 3 and parts[2] else token
    flipped = ("B" if target[0] != "B" else "C") + target[1:]
    return ".".join([*parts[:2], flipped]) if target is not token else flipped


class BrokenAuthCheck(Check):
    id = "broken-auth"
    owasp = "API2:2023"
    title = "Broken Authentication"

    def run(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for ep in ctx.endpoints:
            if not ep.secured or ep.method != "GET" or not ep.safe_to_probe:
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
            variants.append(
                (
                    "a tampered token",
                    Identity("tampered", tamper_token(ctx.user_a.token), ctx.user_a.scheme),
                )
            )
        return variants
