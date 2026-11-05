"""Load OpenAPI 3.x / Swagger 2.0 documents into a flat list of Endpoint objects."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .models import Endpoint, Param

HTTP_METHODS = {"get", "post", "put", "patch", "delete"}


class SpecError(ValueError):
    pass


def load_spec(path: str | Path) -> dict:
    text = Path(path).read_text(encoding="utf-8")
    try:
        # YAML is a superset of JSON, so one parser handles both.
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise SpecError(f"cannot parse spec: {exc}") from exc
    if not isinstance(doc, dict) or not ("openapi" in doc or "swagger" in doc):
        raise SpecError("not an OpenAPI/Swagger document (missing 'openapi' or 'swagger' key)")
    if "paths" not in doc:
        raise SpecError("spec has no 'paths'")
    return doc


def _resolve(doc: dict, node: Any, depth: int = 0) -> Any:
    """Follow local $ref pointers (#/components/...) with a depth guard against cycles."""
    while isinstance(node, dict) and "$ref" in node and depth < 10:
        ref = node["$ref"]
        if not isinstance(ref, str) or not ref.startswith("#/"):
            return {}
        target: Any = doc
        for part in ref[2:].split("/"):
            target = target.get(part, {}) if isinstance(target, dict) else {}
        node = target
        depth += 1
    return node


def _body_params(doc: dict, schema: Any) -> list[Param]:
    schema = _resolve(doc, schema)
    if not isinstance(schema, dict):
        return []
    required = set(schema.get("required", []))
    out = []
    for name, prop in (schema.get("properties") or {}).items():
        prop = _resolve(doc, prop)
        ptype = prop.get("type", "string") if isinstance(prop, dict) else "string"
        out.append(Param(name, "body", name in required, str(ptype)))
    return out


def _is_secured(doc: dict, op: dict) -> bool:
    security = op.get("security", doc.get("security"))
    return bool(security)


def parse_endpoints(doc: dict) -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    for path, item in doc["paths"].items():
        item = _resolve(doc, item)
        if not isinstance(item, dict):
            continue
        shared = item.get("parameters", [])
        for method, op in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(op, dict):
                continue
            params: list[Param] = []
            for raw in [*shared, *op.get("parameters", [])]:
                p = _resolve(doc, raw)
                if not isinstance(p, dict) or "name" not in p:
                    continue
                loc = p.get("in", "query")
                if loc == "body":  # Swagger 2.0 body parameter
                    params.extend(_body_params(doc, p.get("schema")))
                    continue
                schema = p.get("schema", p)
                params.append(
                    Param(
                        p["name"],
                        loc,
                        bool(p.get("required", loc == "path")),
                        str(schema.get("type", "string")) if isinstance(schema, dict) else "string",
                    )
                )
            # OpenAPI 3 request body (JSON only for now)
            body = _resolve(doc, op.get("requestBody", {}))
            content = body.get("content", {}) if isinstance(body, dict) else {}
            for media, mt in content.items():
                if "json" in media:
                    params.extend(_body_params(doc, mt.get("schema")))
                    break
            endpoints.append(
                Endpoint(
                    method=method.upper(),
                    path=path,
                    params=params,
                    secured=_is_secured(doc, op),
                    operation_id=op.get("operationId", ""),
                )
            )
    return endpoints


def load_endpoints(path: str | Path) -> list[Endpoint]:
    return parse_endpoints(load_spec(path))
