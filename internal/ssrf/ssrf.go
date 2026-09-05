// Package ssrf detects server-side request forgery out-of-band: it places a unique
// collaborator URL into URL-shaped parameters and, after a grace period, checks
// whether the target's server called back. An OOB hit is deterministic proof of
// SSRF; nothing internal is accessed by huntx itself.
package ssrf

import (
	"context"
	"net/url"
	"time"

	"github.com/talkdedsec/tlk-huntx/internal/collaborator"
	"github.com/talkdedsec/tlk-huntx/internal/fetch"
	"github.com/talkdedsec/tlk-huntx/internal/finding"
)

var urlParams = []string{
	"url", "uri", "dest", "destination", "callback", "webhook", "redirect", "image",
	"img", "src", "source", "feed", "path", "domain", "host", "site", "link", "data",
	"reference", "proxy", "fetch", "load", "file", "upload", "avatar", "next",
}

type injected struct {
	token  string
	param  string
	target string
}

// Test injects a collaborator payload into each candidate parameter, waits grace
// for asynchronous callbacks, then reports any parameter that produced an OOB hit.
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
	for _, name := range append(urlParams, extra...) {
		names[name] = true
	}

	var shots []injected
	for name := range names {
		token, payload := collab.Payload()
		target := withParam(u, q, name, payload)
		if resp, err := c.Do(ctx, "GET", target, nil); err != nil || resp == nil || resp.DryRun {
			if resp != nil && resp.DryRun {
				return nil
			}
			continue
		}
		shots = append(shots, injected{token: token, param: name, target: target})
	}

	if grace > 0 {
		select {
		case <-time.After(grace):
		case <-ctx.Done():
		}
	}

	var out []finding.Finding
	for _, s := range shots {
		if !collab.Hit(s.token) {
			continue
		}
		hits := collab.Interactions(s.token)
		proof := ""
		if len(hits) > 0 {
			proof = hits[0].Method + " from " + hits[0].Remote + " at " + hits[0].Seen.Format(time.RFC3339)
		}
		f := finding.Finding{
			Target:     u.String(),
			Type:       "Server-side request forgery (OOB)",
			TemplateID: "ssrf-oob",
			Severity:   finding.High,
			Confidence: 95,
			Verified:   true,
			MatchedAt:  s.target,
			CWE:        "CWE-918",
			Extracted:  map[string]string{"parameter": s.param},
			Evidence:   finding.Evidence{Request: "GET " + s.target, OOBProof: proof},
			Repro:      "inject a collaborator URL into the " + s.param + " parameter and watch for the callback",
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
