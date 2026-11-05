"""Check registry."""

from .auth import BrokenAuthCheck
from .base import Check, ScanContext
from .bola import BolaCheck
from .exposure import ExposureCheck
from .injection import InjectionCheck

ALL_CHECKS: dict[str, type[Check]] = {
    c.id: c for c in (BolaCheck, BrokenAuthCheck, InjectionCheck, ExposureCheck)
}

__all__ = ["ALL_CHECKS", "Check", "ScanContext"]
