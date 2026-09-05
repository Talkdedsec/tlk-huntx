---
name: huntx
description: Drive the huntx bug bounty engine end to end — scope-gated recon and scanning, then triage the verified findings and write a HackerOne/Bugcrowd-ready report. Use when the user wants to hunt on an authorized program, turn a raw scan into a submittable report, or synthesize a detection template from an advisory.
---

# huntx

huntx is a single-binary engine that discovers, scans, and deterministically
verifies. This skill is the intelligence layer on top: it decides what to run,
triages what comes back, and writes the human report. The engine finds and proves;
you (the model) never invent or confirm a vulnerability — you cluster, explain, and
report what the engine already verified.

## Ground rules

- Never run an active command without a scope file and `--authorized`. If the user
  has not confirmed authorization for the exact program, ask once and stop.
- Keep the defaults on: rate limiting, blast-radius cap, no state-changing methods.
  Do not suggest removing them.
- Treat `verified: true` findings as real. For `verified: false`, reason about
  whether it is plausible; if unsure, label it "needs manual confirmation" rather
  than reporting it as confirmed.

## Workflow

1. **Scope.** Confirm the program and build a scope file (`examples/scope.example.json`
   is the shape). Sanity-check targets: `huntx --scope scope.json scope check <host>`.

2. **Recon.**
   ```
   huntx --scope scope.json --authorized recon
   ```
   Writes the attack-surface graph to `huntx.graph.json`. Read it to understand the
   live hosts and their tech before scanning.

3. **Scan + verify.**
   ```
   huntx --scope scope.json --authorized --verify -o findings.jsonl scan
   ```
   With no targets, scan reads the live hosts from the graph. `--verify` re-confirms
   each finding deterministically.

4. **Triage** (this is your job). Read `findings.jsonl` and:
   - Cluster by root cause, not by URL. The same misconfig across 40 hosts is one
     issue with 40 instances — collapse it using `dedup_key` and semantic similarity.
   - Drop noise: an unverified finding you cannot justify, an out-of-scope-by-policy
     class the program excludes, a self-XSS with no impact.
   - Assess real impact and set severity/CVSS from what an attacker gains, not from
     the template's default.

5. **Report.** Start from the deterministic baseline and rewrite it into the
   program's format:
   ```
   huntx --scope scope.json report findings.jsonl -o report.md
   ```
   For each surviving finding produce: title, severity + CVSS vector, affected URL,
   step-by-step reproduction, impact, and remediation. Warn the user if a finding
   looks like a likely duplicate of a known common issue.

## More surface, when the target warrants it

- `crawl <targets>` — pull endpoints and parameters out of HTML/JS into the graph.
- `fuzz <targets>` — content discovery over a common-paths wordlist (soft-404 aware).
- `api <targets>` — GraphQL introspection and OpenAPI/Swagger discovery.
- `reflect` / `sqli` / `ssti` / `lfi` / `redirect` `<urls>` — per-class active checks
  on parameters (reflected XSS, error-based SQLi, template injection, path traversal,
  open redirect). Parameters come from the URL and from what `crawl` put in the graph.
- `full <domains>` — one-shot: recon + crawl + scan + all of the above + a ranked plan.
- `ssrf <urls> --base <public-url>` — out-of-band SSRF via the built-in collaborator;
  the base must be reachable by the target for the callback to land.
- `bola <url>... --identities ids.json --owner owner` — prove broken object-level
  authorization by replaying as different identities.
- `greybox --src <dir>` — if the program's source is in scope, correlate dangerous
  sinks with the live endpoints that reach them.
- `plan [findings.jsonl]` — get an expected-value-ranked playbook with composed
  attack chains before you decide what to write up.
- `monitor --interval 30m --notify <webhook>` — watch the surface and report only
  what changed.
- `feedback accept|reject <template-id>` — after triage, teach huntx which templates
  were right so their confidence self-calibrates.

## Driving via MCP

Instead of shelling out, you can drive huntx as an MCP server (`huntx mcp`, stdio,
JSON-RPC 2.0). Tools: `scope_check`, `recon`, `scan` (all take `scope_path`; active
tools require `authorized: true`). `scan` returns a markdown report directly.

## Template synthesis

To detect something not covered by the built-ins, write a nuclei-compatible YAML
template (the engine reads the common HTTP subset: `id`, `info`, `http` with
`matchers`/`extractors`), drop it in a directory, and run:
```
huntx --scope scope.json --authorized --templates ./mytemplates --verify -o findings.jsonl scan
```
Keep synthesized templates detection-only — they prove a condition, they do not
exploit it. Verify every synthesized template against a known-vulnerable and a
known-safe response before trusting it.
