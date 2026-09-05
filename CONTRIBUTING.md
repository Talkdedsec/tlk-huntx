# Contributing

Thanks for helping improve huntx.

## Before you start

- huntx is detection-oriented and safety-gated by design. Contributions must not
  add exploitation, DoS, or ways to bypass the scope gate, rate limiter, or
  blast-radius guard by default.
- Keep the dependency footprint minimal — prefer the standard library. A new
  third-party dependency needs a clear justification in the PR.

## Development

```
go test ./...
go vet ./...
go build ./cmd/huntx
golangci-lint run        # config in .golangci.yml
```

Every package has tests; add tests for new behavior. Detection templates live in
`internal/template/builtin/` and should ship with a matched and an unmatched case
in mind (test them against `engine_test.go`-style fixtures).

## Commits and PRs

- Small, focused commits with a clear message.
- CI runs gofmt, vet, golangci-lint, `go test -race`, build, and govulncheck on
  every PR — keep it green.
- Describe the change and its motivation in the PR body.

## Templates

New nuclei-compatible templates are welcome. Keep them detection-only: prove a
condition, never exploit it. High-signal matchers over broad ones — a template that
false-positives is worse than no template.
