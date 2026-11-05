"""Core data models shared by the spec loader, checks and reporters."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Param:
    name: str
    location: str  # "path" | "query" | "header" | "body"
    required: bool = False
    type: str = "string"


@dataclass
class Endpoint:
    method: str
    path: str  # template, e.g. /books/v1/{book_title}
    params: list[Param] = field(default_factory=list)
    secured: bool = False  # spec says auth is required
    operation_id: str = ""

    @property
    def key(self) -> str:
        return f"{self.method} {self.path}"

    def params_in(self, location: str) -> list[Param]:
        return [p for p in self.params if p.location == location]


@dataclass
class Finding:
    check_id: str
    owasp: str  # e.g. "API1:2023"
    title: str
    severity: str  # "info" | "low" | "medium" | "high" | "critical"
    endpoint: str  # "GET /users/v1/{username}"
    description: str
    evidence: str = ""
    remediation: str = ""
    confidence: str = "medium"  # "low" | "medium" | "high"

    def to_dict(self) -> dict:
        return self.__dict__.copy()
