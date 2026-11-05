# PLAN: api-security-toolkit

Python CLI that reads an OpenAPI/Swagger spec and runs automated checks for OWASP API Security Top 10 risks against an API you own or are authorized to test.

## Real AppSec work this maps to
DAST / API security testing in a CI pipeline (what teams do with ZAP, RESTler, Schemathesis). Output is SARIF so findings appear in GitHub code scanning.

## Features
1. **Spec loader**: OpenAPI 3.x / Swagger 2.0 (JSON/YAML) into an internal model of endpoints, params, auth schemes.
2. **Request model + sessions**: two or more configured users (tokens) so cross-user checks are possible.
3. **Checks** (each a small plugin class with `id`, `owasp_category`, `run()`):
   - API1 BOLA/IDOR: user B requests user A's object IDs.
   - API2 Broken authentication: endpoints reachable with no/invalid/expired token; weak token handling.
   - API8/injection: basic SQLi/NoSQLi error-based probes on parameters, with response-diff detection.
   - API3 Excessive data exposure (stretch): flags sensitive-looking fields (password, token, ssn) in responses.
4. **Sequence awareness (light RESTler idea)**: infer "producer to consumer" (e.g. POST /books returns id, GET /books/{id} consumes it) so IDs used in checks are real.
5. **Reports**: JSON, Markdown, SARIF 2.1.0.
6. **Safety**: required `--i-am-authorized` flag, host allowlist (localhost by default), rate limiting, clear warning banner.
7. **Targets**: VAmPI run locally from Python (no Docker), plus a small intentionally vulnerable Flask app inside `tests/` for self-contained tests. `docker-compose.yml` included for crAPI/VAmPI for people who have Docker (untested by me; documented as optional).
8. **Tests**: pytest unit tests (spec parsing, each check against the mock app, report schemas) + CI.

## How it differs from references
- RESTler: heavy fuzzing engine; mine is a small, readable, check-per-class tool focused on authorization bugs (BOLA) that fuzzers miss.
- ZAP: full proxy/scanner; mine is spec-driven and CLI-only with SARIF out of the box.
- Schemathesis: property-based conformance testing; mine targets security semantics.
- Nuclei: static templates; mine builds requests from the spec and uses multi-user state.

## Industry tool integration
OpenAPI specs (same input as ZAP/RESTler), SARIF output for GitHub code scanning, VAmPI/crAPI as targets. Example GitHub Actions snippet uploads SARIF.

## Layout
`src/apisec/{spec.py,model.py,session.py,checks/,reporters/,cli.py}`, `tests/`, `examples/`, `docker-compose.yml`, `.github/workflows/ci.yml` (pytest, ruff, bandit).

## Credits
Microsoft RESTler, OWASP ZAP, Schemathesis, ProjectDiscovery nuclei, OWASP crAPI, erev0s VAmPI, OWASP API Security Top 10.

## Risks / limits (to be honest in README)
Heuristic detection, so false positives and negatives. Only tested against VAmPI and the local mock.
