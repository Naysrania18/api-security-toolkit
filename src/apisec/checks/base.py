"""Check plugin interface and shared scan context."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass

from ..client import ApiClient, Identity
from ..models import Endpoint, Finding


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


PATH_PARAM_RE = re.compile(r"\{([^}]+)\}")


def fill_path(template: str, values: dict[str, str]) -> str:
    """Substitute {param} placeholders; unknown params get a harmless placeholder value."""
    return PATH_PARAM_RE.sub(lambda m: str(values.get(m.group(1), "1")), template)
