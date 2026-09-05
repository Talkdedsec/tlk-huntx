// Package openredirect detects open redirects: it puts a canary host into common
// redirect parameters and checks whether the response's Location points off-site to
// that canary. The gated client never follows redirects, so nothing is actually
// visited — the Location header alone is the proof.
package openredirect

import (
	"context"
	"net/url"
	"strings"

	"github.com/talkdedsec/tlk-huntx/internal/fetch"
	"github.com/talkdedsec/tlk-huntx/internal/finding"
)

const canary = "huntx-redir.example"

var commonParams = []string{
	"url", "redirect", "redirect_url", "redirect_uri", "redirectUrl", "next", "return",
	"return_url", "returnUrl", "dest", "destination", "r", "u", "link", "goto", "target",
	"redir", "continue", "returnTo", "checkout_url",
}

var payloads = []string{"https://" + canary + "/", "//" + canary + "/"}

func Test(ctx context.Context, c *fetch.Client, rawurl string, extra []string) []finding.Finding {
	u, err := url.Parse(rawurl)
	if err != nil {
		return nil
	}
	q := u.Query()
	names := map[string]bool{}
	for name := range q {
		names[name] = true
	}
	for _, name := range append(commonParams, extra...) {
		names[name] = true
	}

	var out []finding.Finding
	for name := range names {
		if f, ok := testParam(ctx, c, u, q, name); ok {
			out = append(out, f)
			break // one confirmed open redirect per URL is enough
		}
	}
	return out
}

func testParam(ctx context.Context, c *fetch.Client, base *url.URL, q url.Values, name string) (finding.Finding, bool) {
	for _, p := range payloads {
		target := withParam(base, q, name, p)
		resp, err := c.Do(ctx, "GET", target, nil)
		if err != nil || resp == nil || resp.DryRun {
			continue
		}
		if resp.Status < 300 || resp.Status >= 400 {
			continue
		}
		if !pointsToCanary(resp.Header.Get("Location")) {
			continue
		}
		f := finding.Finding{
			Target:     base.String(),
			Type:       "Open redirect",
			TemplateID: "open-redirect",
			Severity:   finding.Medium,
			Confidence: 85,
			Verified:   true,
			MatchedAt:  target,
			CWE:        "CWE-601",
			Extracted:  map[string]string{"parameter": name, "location": resp.Header.Get("Location")},
			Evidence:   finding.Evidence{Request: "GET " + target, Response: "Location: " + resp.Header.Get("Location")},
			Repro:      "curl -s -i " + target,
		}
		f.Finalize([]string{name})
		return f, true
	}
	return finding.Finding{}, false
}

func pointsToCanary(location string) bool {
	if location == "" {
		return false
	}
	loc := strings.TrimSpace(location)
	if strings.HasPrefix(loc, "//"+canary) {
		return true
	}
	if u, err := url.Parse(loc); err == nil {
		return strings.EqualFold(u.Host, canary)
	}
	return false
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
