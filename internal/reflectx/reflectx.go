// Package reflectx detects reflected input, the precondition for reflected XSS. It
// sends a unique marker (not a payload) in each parameter and checks whether it
// comes back in the response, then whether the HTML-significant characters survive
// unencoded. It proves reflection; it does not inject a working exploit.
package reflectx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"strings"

	"github.com/talkdedsec/tlk-huntx/internal/fetch"
	"github.com/talkdedsec/tlk-huntx/internal/finding"
)

// Test probes each query parameter of rawurl (plus any extra names) for reflection.
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
		f, ok := testParam(ctx, c, u, q, name)
		if ok {
			out = append(out, f)
		}
	}
	return out
}

func testParam(ctx context.Context, c *fetch.Client, base *url.URL, q url.Values, name string) (finding.Finding, bool) {
	marker := "hxr" + token()
	if !reflects(ctx, c, base, q, name, marker, marker) {
		return finding.Finding{}, false
	}

	// Reflection confirmed. Check whether HTML-significant characters survive raw.
	breakout := marker + `"'<>`
	unfiltered := reflects(ctx, c, base, q, name, breakout, breakout)

	sev := finding.Low
	conf := 50
	typ := "Reflected parameter"
	tags := []string{"reflection"}
	if unfiltered {
		sev = finding.Medium
		conf = 70
		typ = "Reflected parameter with unencoded HTML characters (potential XSS)"
		tags = append(tags, "potential-xss")
	}

	target := withParam(base, q, name, marker)
	f := finding.Finding{
		Target:     base.String(),
		Type:       typ,
		TemplateID: "reflected-input",
		Severity:   sev,
		Confidence: conf,
		MatchedAt:  target,
		CWE:        "CWE-79",
		Extracted:  map[string]string{"parameter": name},
		Evidence:   finding.Evidence{Request: "GET " + target},
		Repro:      "curl -s " + target,
		Tags:       tags,
	}
	f.Finalize([]string{name})
	return f, true
}

func reflects(ctx context.Context, c *fetch.Client, base *url.URL, q url.Values, name, value, needle string) bool {
	target := withParam(base, q, name, value)
	resp, err := c.Do(ctx, "GET", target, nil)
	if err != nil || resp == nil || resp.DryRun {
		return false
	}
	return strings.Contains(string(resp.Body), needle)
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

func token() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}
