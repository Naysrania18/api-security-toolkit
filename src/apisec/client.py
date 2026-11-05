"""HTTP client with built-in safety rails: host allowlist, rate limiting, timeouts."""

from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urlparse

import requests

WARNING_BANNER = (
    "WARNING: only test systems you own or are explicitly authorized to test.\n"
    "Unauthorized testing may be illegal."
)

DEFAULT_ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"}


class SafetyError(RuntimeError):
    pass


@dataclass
class Identity:
    """A named API user. `token` is sent as `<scheme> <token>` in the Authorization header."""

    name: str
    token: str | None = None
    scheme: str = "Bearer"

    def headers(self) -> dict[str, str]:
        if not self.token:
            return {}
        return {"Authorization": f"{self.scheme} {self.token}".strip()}


def check_target_allowed(base_url: str, extra_hosts: set[str] | None = None) -> None:
    host = urlparse(base_url).hostname or ""
    allowed = DEFAULT_ALLOWED_HOSTS | (extra_hosts or set())
    if host not in allowed:
        raise SafetyError(
            f"host '{host}' is not in the allowlist {sorted(allowed)}. "
            "Add it explicitly with --allow-host only if you are authorized to test it."
        )


class ApiClient:
    def __init__(self, base_url: str, rate_limit_rps: float = 10.0, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.min_interval = 1.0 / rate_limit_rps if rate_limit_rps > 0 else 0.0
        self.timeout = timeout
        self._last = 0.0
        self._session = requests.Session()
        self.request_count = 0

    def request(
        self,
        method: str,
        path: str,
        identity: Identity | None = None,
        params: dict | None = None,
        json_body: dict | None = None,
        extra_headers: dict | None = None,
    ) -> requests.Response | None:
        wait = self.min_interval - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        headers = dict(identity.headers()) if identity else {}
        headers.update(extra_headers or {})
        try:
            resp = self._session.request(
                method,
                self.base_url + path,
                params=params,
                json=json_body,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.RequestException:
            resp = None
        self._last = time.monotonic()
        self.request_count += 1
        return resp
