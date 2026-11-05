import json

import pytest

from apisec import cli
from apisec.client import SafetyError, check_target_allowed
from apisec.models import Finding
from apisec.reporters import to_json, to_markdown, to_sarif
from conftest import SPEC

F = Finding(
    check_id="bola",
    owasp="API1:2023",
    title="Broken Object Level Authorization",
    severity="high",
    endpoint="GET /api/notes/{note_id}",
    description="d",
    evidence="e",
    remediation="r",
)


def test_json_report_shape():
    doc = json.loads(to_json([F], "http://127.0.0.1"))
    assert doc["summary"]["total"] == 1
    assert doc["findings"][0]["check_id"] == "bola"


def test_markdown_report_mentions_endpoint_and_warning():
    md = to_markdown([F], "http://127.0.0.1")
    assert "GET /api/notes/{note_id}" in md and "authorized" in md


def test_sarif_structure():
    doc = json.loads(to_sarif([F], "http://127.0.0.1", "openapi.yml"))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["rules"][0]["id"] == "bola"
    result = run["results"][0]
    assert result["ruleId"] == "bola" and result["level"] == "error"
    loc = result["locations"][0]
    assert loc["physicalLocation"]["artifactLocation"]["uri"] == "openapi.yml"
    assert loc["logicalLocations"][0]["name"] == "GET /api/notes/{note_id}"


def test_empty_sarif_is_valid():
    doc = json.loads(to_sarif([], "t"))
    assert doc["runs"][0]["results"] == []


def test_host_allowlist():
    check_target_allowed("http://localhost:5000")
    with pytest.raises(SafetyError):
        check_target_allowed("https://example.com")
    check_target_allowed("https://example.com", {"example.com"})


def test_cli_refuses_without_authorization_flag(base_url, tmp_path, capsys):
    code = cli.main(
        ["scan", "--spec", str(SPEC), "--base-url", base_url, "--out-dir", str(tmp_path)]
    )
    assert code == 2
    assert "--i-am-authorized" in capsys.readouterr().err


def test_cli_refuses_non_allowlisted_host(tmp_path, capsys):
    code = cli.main(
        ["scan", "--spec", str(SPEC), "--base-url", "https://example.com", "--i-am-authorized"]
    )
    assert code == 2


def test_cli_end_to_end_writes_all_reports(base_url, tmp_path):
    code = cli.main(
        [
            "scan", "--spec", str(SPEC), "--base-url", base_url,
            "--token-a", "token-alice", "--token-b", "token-bob",
            "--rate", "0", "--out-dir", str(tmp_path), "--i-am-authorized",
        ]
    )  # fmt: skip
    assert code == 1  # findings present -> non-zero for CI
    sarif = json.loads((tmp_path / "report.sarif").read_text())
    assert {r["ruleId"] for r in sarif["runs"][0]["results"]} == {
        "bola", "broken-auth", "injection", "data-exposure"
    }  # fmt: skip
    assert (tmp_path / "report.json").exists() and (tmp_path / "report.md").exists()
