"""Check plugin interface and shared scan context."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..client import ApiClient, Identity
from ..models import Endpoint, Finding
from ..paths import PATH_PARAM_RE, fill_path  # noqa: F401  (re-exported)


@dataclass
class ScanContext:
    endpoints: list[Endpoint]
    client: ApiClient
    identities: list[Identity]  # identities[0] = "user A", [1] = "user B" (optional)

    @property
    def user_a(self) -> Identity | None:
        return self.identities[0] if self.identities else None

    @property
    def user_b(self) -> Identity | None:
        return self.identities[1] if len(self.identities) > 1 else None


class Check(ABC):
    id: str = ""
    owasp: str = ""
    title: str = ""

    @abstractmethod
    def run(self, ctx: ScanContext) -> list[Finding]: ...
