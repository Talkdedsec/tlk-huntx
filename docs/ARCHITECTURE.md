# Architecture

huntx is a single Go binary organized in layers. Everything that touches a target
goes through the safety layer first; the LLM only ever sees findings the engine has
already verified.

```
INTERFACE   cli · mcp · dashboard · report/sarif · notify
INTELLIGENCE agent (plan) · feedback (FP-learning) · /huntx skill (external)
VERIFY      verify (reconfirm · BOLA/IDOR) · collaborator (OOB)
DETECT      template · secrets · apidisco · greybox · reflectx · openredirect ·
            ssrf · cmdi · sqli · ssti · lfi · hostheader
DISCOVER    recon · crawl · fuzz · session
KNOWLEDGE   graph · monitor
SAFETY      scope · ratelimit · blastradius · authz · fetch
```

## Packages

| Package | Responsibility |
|---|---|
| `scope` | In/out scope decision (wildcard + CIDR, out-of-scope precedence). The gate. |
| `ratelimit` | Per-host token bucket, global concurrency, 429/WAF backoff. |
| `blastradius` | Total-request cap and state-changing-method block. |
| `authz` | Requires a scope file and `--authorized` before any active run. |
| `fetch` | The only client that talks to a target; enforces the three gates above. |
| `finding` | Canonical finding schema shared by every layer (JSONL / SARIF / triage). |
| `graph` | Attack-surface graph (nodes/edges), JSON persistence, diff. |
| `recon` | Passive subdomain sources + gated probing + tech fingerprint. |
| `crawl` | Endpoint/param mining from HTML, JS, robots.txt and sitemap.xml. |
| `fuzz` | Content discovery over a wordlist with soft-404 baselining. |
| `reflectx` | Reflected-parameter detection (potential XSS), marker-based. |
| `openredirect` | Open-redirect detection via a canary host in redirect params. |
| `ssrf` | Out-of-band SSRF via collaborator callback correlation. |
| `cmdi` | Out-of-band OS command injection via collaborator callback. |
| `sqli` | Error-based SQL injection detection (quote probes + DB error signatures). |
| `ssti` | Server-side template injection detection (marked arithmetic). |
| `lfi` | Local file inclusion / path traversal detection (system-file signatures). |
| `hostheader` | Host-header injection detection (canary Host / X-Forwarded-Host). |
| `session` | Named identities (headers) for access-control testing. |
| `template` | nuclei-compatible template engine + built-ins + tech-aware selection. |
| `secrets` | High-confidence leaked-credential detection (masked evidence). |
| `apidisco` | GraphQL introspection + OpenAPI/Swagger discovery. |
| `greybox` | Source-sink to live-endpoint correlation. |
| `collaborator` | Self-hosted OOB interaction server (blind detection proof). |
| `verify` | Deterministic re-confirmation + BOLA/IDOR differential. |
| `agent` | Expected-value ranking + attack-chain composition (plans, never attacks). |
| `feedback` | Records triage decisions and calibrates confidence. |
| `monitor` | Diffs a run against the last (new hosts / new findings). |
| `report` | HackerOne/Bugcrowd markdown. |
| `sarif` | SARIF 2.1.0 export for CI / code scanning. |
| `notify` | Slack/Discord webhook push. |
| `distributed` | Coordinator + worker for spreading a scan across machines. |
| `dashboard` | Embedded local view of the graph and findings. |
| `engine` | Shared recon/scan orchestration used by both the CLI and MCP. |
| `mcp` | Model Context Protocol server exposing the engine as typed tools. |
| `cli` | Command router and flag surface. |

## Principles

- The engine finds and proves; a language model clusters, explains, and reports —
  it is never the verification authority.
- Detection, not exploitation: probes prove a condition and do not cause damage.
- Minimal dependencies: standard library plus `gopkg.in/yaml.v3` for templates.
