"""Command line interface: `apisec scan --spec openapi.yml --base-url http://127.0.0.1:5000 ...`"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .checks import ALL_CHECKS, ScanContext
from .client import WARNING_BANNER, ApiClient, Identity, SafetyError, check_target_allowed
from .models import Finding
from .reporters import WRITERS, to_sarif
from .spec import SpecError, load_endpoints


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="apisec",
        description="OWASP API Top 10 checks driven by an OpenAPI/Swagger spec.",
        epilog=WARNING_BANNER,
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="run checks against a live API")
    scan.add_argument("--spec", required=True, help="path to OpenAPI 3.x / Swagger 2.0 (json/yaml)")
    scan.add_argument("--base-url", required=True, help="e.g. http://127.0.0.1:5000")
    scan.add_argument(
        "--token-a", default=os.environ.get("APISEC_TOKEN_A"), help="bearer token for user A"
    )
    scan.add_argument(
        "--token-b", default=os.environ.get("APISEC_TOKEN_B"), help="bearer token for user B"
    )
    scan.add_argument("--checks", default="all", help=f"comma list of: {', '.join(ALL_CHECKS)}")
    scan.add_argument("--format", default="json,md,sarif", help="comma list of: json, md, sarif")
    scan.add_argument("--out-dir", default="reports", help="where to write reports")
    scan.add_argument("--rate", type=float, default=10.0, help="max requests per second")
    scan.add_argument(
        "--allow-host", action="append", default=[], help="extra host allowed besides localhost"
    )
    scan.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="confirm you own the target or have written permission to test it",
    )

    ls = sub.add_parser("list-endpoints", help="parse a spec and print endpoints (no network)")
    ls.add_argument("--spec", required=True)
    return p


def _selected_checks(arg: str):
    names = list(ALL_CHECKS) if arg == "all" else [n.strip() for n in arg.split(",") if n.strip()]
    unknown = [n for n in names if n not in ALL_CHECKS]
    if unknown:
        raise SystemExit(f"unknown check(s): {', '.join(unknown)}")
    return [ALL_CHECKS[n]() for n in names]


def run_scan(args: argparse.Namespace) -> list[Finding]:
    print(WARNING_BANNER, file=sys.stderr)
    if not args.i_am_authorized:
        raise SafetyError("refusing to scan: pass --i-am-authorized to confirm you may test it")
    check_target_allowed(args.base_url, set(args.allow_host))
    endpoints = load_endpoints(args.spec)
    identities = []
    if args.token_a:
        identities.append(Identity("user_a", args.token_a))
    if args.token_b:
        identities.append(Identity("user_b", args.token_b))
    client = ApiClient(args.base_url, rate_limit_rps=args.rate)
    ctx = ScanContext(endpoints, client, identities)
    findings: list[Finding] = []
    for check in _selected_checks(args.checks):
        print(f"[*] running {check.id} ...", file=sys.stderr)
        findings.extend(check.run(ctx))
    print(f"[*] {client.request_count} requests sent", file=sys.stderr)
    return findings


def write_reports(findings: list[Finding], args: argparse.Namespace) -> list[Path]:
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for fmt in [f.strip() for f in args.format.split(",") if f.strip()]:
        if fmt not in WRITERS:
            raise SystemExit(f"unknown format: {fmt}")
        writer, ext = WRITERS[fmt]
        path = out / f"report.{ext}"
        if writer is to_sarif:
            path.write_text(writer(findings, args.base_url, args.spec), encoding="utf-8")
        else:
            path.write_text(writer(findings, args.base_url), encoding="utf-8")
        written.append(path)
    return written


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "list-endpoints":
            for ep in load_endpoints(args.spec):
                print(f"{ep.key}  secured={ep.secured}  params={[p.name for p in ep.params]}")
            return 0
        findings = run_scan(args)
        for path in write_reports(findings, args):
            print(f"[+] wrote {path}", file=sys.stderr)
        print(f"[+] {len(findings)} finding(s)", file=sys.stderr)
        return 1 if findings else 0  # non-zero exit lets CI fail the build
    except (SafetyError, SpecError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
