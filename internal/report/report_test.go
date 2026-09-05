package report

import (
	"strings"
	"testing"

	"github.com/talkdedsec/tlk-huntx/internal/finding"
)

func TestMarkdownOrderingAndContent(t *testing.T) {
	fs := []finding.Finding{
		{Type: "Directory listing", TemplateID: "directory-listing", Severity: finding.Low, MatchedAt: "https://a/"},
		{Type: "Exposed .env", TemplateID: "exposed-dotenv", Severity: finding.High, MatchedAt: "https://a/.env", Verified: true, Confidence: 95},
	}
	md := Markdown("acme", fs)

	if !strings.Contains(md, "# Security findings — acme") {
		t.Error("missing title")
	}
	// high must appear before low
	hi := strings.Index(md, "Exposed .env")
	lo := strings.Index(md, "Directory listing")
	if hi == -1 || lo == -1 || hi > lo {
		t.Fatalf("severity ordering wrong: hi=%d lo=%d", hi, lo)
	}
	if !strings.Contains(md, "1 deterministically verified") {
		t.Errorf("verified count missing:\n%s", md)
	}
	if !strings.Contains(md, "Rotate") && !strings.Contains(md, "rotate") {
		t.Error("expected remediation text for .env")
	}
}

func TestMarkdownRichFinding(t *testing.T) {
	fs := []finding.Finding{{
		Type: "SSRF", TemplateID: "ssrf-oob", Severity: finding.Critical, MatchedAt: "https://a/f",
		CVSS: "9.1", CWE: "CWE-918", Confidence: 95, Verified: true,
		Evidence: finding.Evidence{Request: "GET https://a/f", Response: "hit", OOBProof: "DNS from 1.2.3.4"},
		Repro:    "curl https://a/f",
	}}
	md := Markdown("", fs) // empty program -> "target"
	for _, want := range []string{"# Security findings — target", "CVSS 9.1", "CWE-918", "OOB: DNS from 1.2.3.4", "### Reproduction"} {
		if !strings.Contains(md, want) {
			t.Errorf("missing %q in report", want)
		}
	}
}

func TestSecretRemediationFallback(t *testing.T) {
	if r := remediationFor("secret-aws-access-key"); !strings.Contains(r, "rotate") {
		t.Errorf("secret remediation: %q", r)
	}
	if remediationFor("unknown-template") != "" {
		t.Error("unknown template should have no canned remediation")
	}
}
