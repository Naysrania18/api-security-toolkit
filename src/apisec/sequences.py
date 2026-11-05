"""Light-weight 'producer -> consumer' inference (idea borrowed from RESTler).

For an endpoint like GET /books/v1/{book_title}, the 'producer' is the collection endpoint
GET /books/v1. We call the producer to learn *real* identifiers instead of guessing them.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .paths import PATH_PARAM_RE

if TYPE_CHECKING:
    from .checks.base import ScanContext
    from .client import Identity
    from .models import Endpoint


def collection_path(endpoint: Endpoint) -> str | None:
    """Path of the collection that produces ids for the last {param}, or None."""
    matches = list(PATH_PARAM_RE.finditer(endpoint.path))
    if not matches:
        return None
    last = matches[-1]
    if last.end() != len(endpoint.path):  # id must be the final path segment
        return None
    return endpoint.path[: last.start()].rstrip("/") or "/"


def _extract_ids(data: object, param: str) -> list[str]:
    items: list = []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        for value in data.values():  # e.g. {"Books": [...]} or {"users": [...]}
            if isinstance(value, list):
                items = value
                break
    ids: list[str] = []
    for item in items:
        if isinstance(item, dict):
            for key in (param, "id", "_id", "uuid"):
                if key in item and isinstance(item[key], (str, int)):
                    ids.append(str(item[key]))
                    break
            else:
                first = next((v for v in item.values() if isinstance(v, (str, int))), None)
                if first is not None:
                    ids.append(str(first))
        elif isinstance(item, (str, int)):
            ids.append(str(item))
    return ids


def discover_ids(
    ctx: ScanContext, endpoint: Endpoint, identity: Identity | None, limit: int = 20
) -> list[str]:
    """Call the producer GET collection (if the spec has one) and return up to `limit` ids."""
    coll = collection_path(endpoint)
    if coll is None:
        return []
    if not any(e.method == "GET" and e.path == coll for e in ctx.endpoints):
        return []
    param = PATH_PARAM_RE.findall(endpoint.path)[-1]
    resp = ctx.client.request("GET", coll, identity)
    if resp is None or resp.status_code != 200:
        return []
    try:
        return _extract_ids(resp.json(), param)[:limit]
    except ValueError:
        return []
