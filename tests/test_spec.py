import json

import pytest

from apisec.spec import SpecError, load_endpoints, load_spec, parse_endpoints
from conftest import SPEC


def test_openapi3_endpoints_parsed():
    eps = {e.key: e for e in load_endpoints(SPEC)}
    assert "GET /api/notes/{note_id}" in eps
    note = eps["GET /api/notes/{note_id}"]
    assert note.secured is True
    assert [(p.name, p.location) for p in note.params] == [("note_id", "path")]
    assert eps["GET /api/search"].secured is False


def test_ref_request_body_resolved():
    post = {e.key: e for e in load_endpoints(SPEC)}["POST /api/notes"]
    assert [(p.name, p.location, p.required) for p in post.params] == [("text", "body", True)]


def test_swagger2_body_parameter(tmp_path):
    doc = {
        "swagger": "2.0",
        "paths": {
            "/login": {
                "post": {
                    "parameters": [
                        {
                            "in": "body",
                            "name": "body",
                            "schema": {
                                "type": "object",
                                "required": ["username"],
                                "properties": {"username": {"type": "string"}},
                            },
                        }
                    ]
                }
            }
        },
    }
    f = tmp_path / "s.json"
    f.write_text(json.dumps(doc))
    (ep,) = parse_endpoints(load_spec(f))
    assert ep.method == "POST" and ep.params[0].name == "username"


def test_rejects_non_openapi(tmp_path):
    f = tmp_path / "x.yml"
    f.write_text("hello: world\n")
    with pytest.raises(SpecError):
        load_spec(f)


def test_cyclic_ref_does_not_hang():
    doc = {
        "openapi": "3.0.0",
        "components": {"schemas": {"A": {"$ref": "#/components/schemas/A"}}},
        "paths": {
            "/x": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {"schema": {"$ref": "#/components/schemas/A"}}
                        }
                    }
                }
            }
        },
    }
    assert parse_endpoints(doc)[0].path == "/x"


def test_destructive_looking_routes_are_not_probed():
    from apisec.models import Endpoint

    assert not Endpoint("GET", "/createdb").safe_to_probe
    assert not Endpoint("GET", "/session/logout").safe_to_probe
    assert Endpoint("GET", "/books/v1").safe_to_probe
