"""Fixtures: run the vulnerable Flask app on a random local port in a background thread."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest
from werkzeug.serving import make_server

from apisec.checks import ScanContext
from apisec.client import ApiClient, Identity
from apisec.spec import load_endpoints
from vuln_app import create_app

SPEC = Path(__file__).parent / "openapi_test.yml"


@pytest.fixture(scope="session")
def base_url():
    server = make_server("127.0.0.1", 0, create_app())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture()
def ctx(base_url):
    return ScanContext(
        endpoints=load_endpoints(SPEC),
        client=ApiClient(base_url, rate_limit_rps=0),
        identities=[Identity("alice", "token-alice"), Identity("bob", "token-bob")],
    )
