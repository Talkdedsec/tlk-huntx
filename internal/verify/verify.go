// Package verify is the deterministic second tier: a finding is only trusted once
// re-confirmed without a language model in the loop. Template findings are re-run
// and must fire again; the differential engine proves broken object-level
// authorization by replaying one request under different identities.
package verify

import (
	"context"

	"github.com/talkdedsec/tlk-huntx/internal/fetch"
	"github.com/talkdedsec/tlk-huntx/internal/finding"
	"github.com/talkdedsec/tlk-huntx/internal/secrets"
	"github.com/talkdedsec/tlk-huntx/internal/template"
)

// Reconfirm re-runs whatever produced f and returns true if it fires a second time.
func Reconfirm(ctx context.Context, c *fetch.Client, tpls []*template.Template, f finding.Finding) bool {
	if isSecret(f.TemplateID) {
		resp, err := c.Do(ctx, "GET", f.MatchedAt, nil)
		if err != nil || resp == nil || resp.DryRun {
			return false
		}
		for _, g := range secrets.Scan(f.MatchedAt, string(resp.Body)) {
			if g.DedupKey == f.DedupKey {
				return true
			}
		}
		return false
	}
	for _, t := range tpls {
		if t.ID != f.TemplateID {
			continue
		}
		for _, g := range t.Run(ctx, c, f.Target) {
			if g.MatchedAt == f.MatchedAt {
				return true
			}
		}
	}
	return false
}

func isSecret(templateID string) bool {
	return len(templateID) > 7 && templateID[:7] == "secret-"
}

type Creds struct {
	Label   string
	Headers map[string]string
}

// Differential replays the same GET as the resource owner, another authenticated
// identity, and an anonymous client. If a non-owner receives the owner's response,
// object-level authorization is broken (BOLA/IDOR).
func Differential(ctx context.Context, c *fetch.Client, url string, owner Creds, others ...Creds) (finding.Finding, bool) {
	ownerResp, err := c.DoReq(ctx, "GET", url, owner.Headers, nil)
	if err != nil || ownerResp == nil || ownerResp.DryRun || ownerResp.Status != 200 {
		return finding.Finding{}, false
	}
	for _, o := range others {
		r, err := c.DoReq(ctx, "GET", url, o.Headers, nil)
		if err != nil || r == nil {
			continue
		}
		if r.Status == 200 && sameBody(ownerResp.Body, r.Body) {
			f := finding.Finding{
				Target:     url,
				Type:       "Broken object-level authorization (BOLA/IDOR)",
				TemplateID: "bola-differential",
				Severity:   finding.High,
				Confidence: 90,
				Verified:   true,
				MatchedAt:  url,
				CWE:        "CWE-639",
				Extracted:  map[string]string{"accessible_as": o.Label},
				Evidence: finding.Evidence{
					Request:  "GET " + url + " as " + o.Label,
					Response: "identical owner response returned to " + o.Label,
				},
				Repro: "compare GET " + url + " as owner vs " + o.Label,
			}
			f.Finalize([]string{o.Label})
			return f, true
		}
	}
	return finding.Finding{}, false
}

func sameBody(a, b []byte) bool {
	if len(a) == 0 || len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
