// Package hostheader detects host-header injection: it sends a canary host in the
// Host and X-Forwarded-Host headers and checks whether the application echoes it
// back into the body or a redirect. That reflection is what enables cache poisoning
// and password-reset poisoning; huntx only proves the reflection.
package hostheader

import (
	"context"
	"strings"

	"github.com/talkdedsec/tlk-huntx/internal/fetch"
	"github.com/talkdedsec/tlk-huntx/internal/finding"
)

const canary = "huntx-hhi.example"

func Test(ctx context.Context, c *fetch.Client, rawurl string) []finding.Finding {
	variants := []map[string]string{
		{"Host": canary},
		{"X-Forwarded-Host": canary},
		{"X-Forwarded-Host": canary, "X-Forwarded-Scheme": "https"},
	}
	for _, h := range variants {
		resp, err := c.DoReq(ctx, "GET", rawurl, h, nil)
		if err != nil || resp == nil || resp.DryRun {
			continue
		}
		loc := resp.Header.Get("Location")
		body := string(resp.Body)
		if !strings.Contains(loc, canary) && !strings.Contains(body, canary) {
			continue
		}
		where := "body"
		if strings.Contains(loc, canary) {
			where = "Location header"
		}
		f := finding.Finding{
			Target:     rawurl,
			Type:       "Host header injection",
			TemplateID: "host-header-injection",
			Severity:   finding.Medium,
			Confidence: 75,
			MatchedAt:  rawurl,
			CWE:        "CWE-644",
			Extracted:  map[string]string{"reflected_in": where, "header": headerName(h)},
			Evidence:   finding.Evidence{Request: "GET " + rawurl + " with spoofed host " + canary, Response: "canary reflected in " + where},
			Repro:      "curl -s -i -H 'Host: " + canary + "' " + rawurl,
		}
		f.Finalize([]string{"host"})
		return []finding.Finding{f}
	}
	return nil
}

func headerName(h map[string]string) string {
	for k := range h {
		if strings.EqualFold(k, "Host") || strings.EqualFold(k, "X-Forwarded-Host") {
			return k
		}
	}
	return "Host"
}
