// Package ssti detects server-side template injection: it sends a marked arithmetic
// expression in each parameter and looks for the evaluated result in the response.
// The marker (zq49, not a bare 49) keeps false positives near zero, and the payload
// only does harmless arithmetic — it proves evaluation, not code execution.
package ssti

import (
	"context"
	"net/url"
	"strings"

	"github.com/talkdedsec/tlk-huntx/internal/fetch"
	"github.com/talkdedsec/tlk-huntx/internal/finding"
)

const marker = "zq"
const evaluated = marker + "49"

var payloads = []string{
	marker + "{{7*7}}",
	marker + "${7*7}",
	marker + "<%= 7*7 %>",
	marker + "#{7*7}",
	marker + "{{7*'7'}}",
}

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
	for _, name := range extra {
		if name != "" {
			names[name] = true
		}
	}
	if len(names) == 0 {
		return nil
	}

	var out []finding.Finding
	for name := range names {
		if f, ok := testParam(ctx, c, u, q, name); ok {
			out = append(out, f)
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
		if !strings.Contains(string(resp.Body), evaluated) {
			continue
		}
		f := finding.Finding{
			Target:     base.String(),
			Type:       "Server-side template injection",
			TemplateID: "ssti",
			Severity:   finding.High,
			Confidence: 85,
			Verified:   true,
			MatchedAt:  target,
			CWE:        "CWE-94",
			Extracted:  map[string]string{"parameter": name, "payload": p},
			Evidence:   finding.Evidence{Request: "GET " + target, Response: "template evaluated " + p + " -> " + evaluated},
			Repro:      "curl -s " + target,
		}
		f.Finalize([]string{name})
		return f, true
	}
	return finding.Finding{}, false
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
