# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and versions aim for
[SemVer](https://semver.org/).

## [Unreleased]

### Added
- `full` — one-shot pipeline: recon + crawl + scan + active parameter checks + plan.
- `--min-severity` — keep only findings at or above a severity (scan/full/report).
- crawl now also mines robots.txt Allow/Disallow paths and sitemap.xml locations.
- `crawl` — mine endpoints and parameters from HTML and same-host JavaScript.
- `fuzz` — content discovery over a built-in common-paths wordlist (soft-404 aware).
- `reflect` / `xss` — reflected-parameter detection (potential XSS), detection-only.
- `redirect` — open-redirect detection via a canary host in common parameters.
- `ssrf` — out-of-band SSRF detection through a built-in collaborator callback.
- `cmdi` — out-of-band OS command injection via shell-metacharacter callbacks.
- `sqli` — error-based SQL injection detection (quote probes, DB error signatures).
- `ssti` — server-side template injection detection (marked arithmetic evaluation).
- `lfi` — local file inclusion / path traversal detection (system-file signatures).
- `hostheader` — host-header injection detection (canary Host / X-Forwarded-Host).
- Styled ANSI startup banner (steel "hunt" + red "x", tagline), NO_COLOR aware.
- `api` — discover GraphQL introspection and exposed OpenAPI/Swagger specs.
- `bola` / `idor` — object-level authorization testing across named identities.
- `greybox` — correlate dangerous source sinks with live endpoints.
- `plan` — rank findings by expected value and compose known attack chains.
- `monitor` — diff a run against the last; `--interval` to repeat, `--notify` webhook.
- `feedback` — record triage decisions and calibrate confidence (false-positive loop).
- `dashboard` — interactive console: click-through finding detail drawer (evidence,
  repro, extracted, tags), severity filter chips, search, and a Findings/Hosts/
  Surface (attack-surface graph) view.
- `coordinate` / `worker` — distributed scanning over HTTP.
- SARIF 2.1.0 report output (`report -o *.sarif`).

## [0.1.0]

### Added
- Safety core: scope gate (wildcard + CIDR, out-of-scope precedence), per-host rate
  limiter with backoff, blast-radius guard, authorization gate.
- `recon` — passive subdomain discovery (crt.sh, Wayback, OTX) + gated HTTP probing,
  attack-surface graph.
- `scan` — nuclei-compatible template engine (built-in templates), tech-aware
  selection, secret scanning.
- `verify` — OOB collaborator, deterministic re-confirmation, BOLA/IDOR differential.
- `report` — HackerOne/Bugcrowd-ready markdown.
- `mcp` — Model Context Protocol server (stdio) exposing scope_check/recon/scan.
- `/huntx` skill for LLM-driven triage and reporting.
