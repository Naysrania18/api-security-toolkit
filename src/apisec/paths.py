"""Path-template helpers."""

from __future__ import annotations

import re

PATH_PARAM_RE = re.compile(r"\{([^}]+)\}")


def fill_path(template: str, values: dict[str, str]) -> str:
    """Substitute {param} placeholders; unknown params get a harmless placeholder value."""
    return PATH_PARAM_RE.sub(lambda m: str(values.get(m.group(1), "1")), template)
