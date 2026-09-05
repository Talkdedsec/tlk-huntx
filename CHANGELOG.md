# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/), and versions aim for
[SemVer](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-09-06

First public release.

### Safety core

- Scope gate — machine-readable in/out-of-scope decision (wildcards + CIDR,
  out-of-scope precedence) on every outbound request.
- Per-host rate limiter with global concurrency cap and 429/WAF back-off.
- Blast-radius guard — total-request budget and a block on state-changing methods
  unless explicitly opted in.
- Authorization gate — active pipelines refuse to run without a scope file and
  `--authorized`. The `fetch` client is the only component allowed to touch a target.

### Discovery

- `recon` — passive subdomain discovery (crt.sh, Wayback, OTX, HackerTarget) plus
  gated HTTP probing and an attack-surface graph.
- `crawl` — mine endpoints and parameters from HTML, same-host JavaScript,
  robots.txt Allow/Disallow, and sitemap.xml.
- `fuzz` — content discovery over a built-in common-paths wordlist (soft-404 aware).
- `api` — GraphQL introspection and OpenAPI/Swagger discovery.
- Session identities for authenticated crawling and authz testing.

### Detection

- `scan` — nuclei-compatible template engine with built-in templates, tech-aware
  selection, and secret scanning.
- Active, detection-only checks: `reflect`/`xss`, `sqli`, `ssti`, `lfi`,
  `redirect`, `ssrf`, `cmdi`, `hostheader`.
- `bola`/`idor` — object-level authorization testing across named identities.
- `greybox` — correlate dangerous source sinks with live endpoints.

### Verification

- Deterministic re-confirmation out-of-band; the engine proves a finding before a
  model ever sees it.
- Built-in OOB collaborator for SSRF/command-injection callbacks.
- BOLA/IDOR differential checks.

### Intelligence

- `plan` — rank findings by expected value and compose known attack chains.
- `feedback` — record triage decisions and self-calibrate confidence.
- `monitor` — diff a run against the last; `--interval` to repeat, `--notify` webhook.
- `mcp` — Model Context Protocol server (stdio) exposing scope/recon/scan/plan as
  typed tools, plus the `/huntx` skill for LLM-driven triage and reporting.

### Interface

- `full` — one-shot pipeline: recon + crawl + scan + active checks + ranked plan.
- `dashboard` — interactive local console with a finding detail drawer, severity
  filters, search, and a Findings/Hosts/Surface (attack-surface graph) view.
- `report` — HackerOne/Bugcrowd-ready Markdown and SARIF 2.1.0 output;
  `--min-severity` to filter.
- `coordinate`/`worker` — distributed scanning over HTTP.
- Styled ANSI startup banner (`NO_COLOR` aware).

[Unreleased]: https://github.com/Talkdedsec/tlk-huntx/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Talkdedsec/tlk-huntx/releases/tag/v0.1.0
