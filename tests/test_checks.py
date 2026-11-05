"""Each check is run against the local vulnerable app: it must flag the planted bug and must
NOT flag the safe counterpart (false-positive guard)."""

from apisec.checks.auth import BrokenAuthCheck
from apisec.checks.bola import BolaCheck
from apisec.checks.exposure import ExposureCheck, find_sensitive_keys
from apisec.checks.injection import InjectionCheck
from apisec.client import Identity
from apisec.sequences import collection_path, discover_ids


def endpoints_of(findings):
    return {f.endpoint for f in findings}


def test_bola_found_on_vulnerable_route_only(ctx):
    findings = BolaCheck().run(ctx)
    assert endpoints_of(findings) == {"GET /api/notes/{note_id}"}
    assert findings[0].confidence == "high"  # alice's and bob's listings differ


def test_bola_needs_two_identities(ctx):
    ctx.identities = ctx.identities[:1]
    assert BolaCheck().run(ctx) == []


def test_broken_auth_flags_unprotected_admin_route(ctx):
    findings = BrokenAuthCheck().run(ctx)
    assert endpoints_of(findings) == {"GET /api/admin/stats"}


def test_injection_detects_sql_error_leak(ctx):
    findings = InjectionCheck().run(ctx)
    assert endpoints_of(findings) == {"GET /api/search"}
    assert findings[0].confidence == "high"


def test_exposure_flags_password_hash(ctx):
    findings = ExposureCheck().run(ctx)
    assert endpoints_of(findings) == {"GET /api/profile"}
    assert "password_hash" in findings[0].description


def test_find_sensitive_keys_nested():
    data = {"user": {"name": "a", "token": "x"}, "items": [{"secret": 1}]}
    assert find_sensitive_keys(data) == ["user.token", "items[].secret"]


def test_collection_path_and_discovery(ctx):
    ep = next(e for e in ctx.endpoints if e.key == "GET /api/notes/{note_id}")
    assert collection_path(ep) == "/api/notes"
    assert sorted(discover_ids(ctx, ep, Identity("alice", "token-alice"))) == ["1", "2"]
    assert discover_ids(ctx, ep, Identity("bob", "token-bob")) == ["3"]


def test_tamper_token_changes_jwt_signature_start_not_end():
    from apisec.checks.auth import tamper_token

    jwt = "aaa.bbb.Sig123"
    out = tamper_token(jwt)
    assert out.split(".")[:2] == ["aaa", "bbb"]
    assert out.split(".")[2] != "Sig123" and out.split(".")[2][1:] == "ig123"
    assert tamper_token("opaque") != "opaque"
