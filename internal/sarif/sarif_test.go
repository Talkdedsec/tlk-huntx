package sarif

import (
	"encoding/json"
	"testing"

	"github.com/talkdedsec/tlk-huntx/internal/finding"
)

func TestBuild(t *testing.T) {
	fs := []finding.Finding{
		{TemplateID: "exposed-dotenv", Type: "Exposed dotenv", Severity: finding.High, MatchedAt: "https://a/config", Verified: true},
		{TemplateID: "exposed-dotenv", Type: "Exposed dotenv", Severity: finding.High, MatchedAt: "https://b/config"},
		{TemplateID: "directory-listing", Type: "Directory listing", Severity: finding.Low, MatchedAt: "https://a/"},
	}
	b, err := Build("0.1.0", fs)
	if err != nil {
		t.Fatal(err)
	}
	var d doc
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatalf("invalid SARIF json: %v", err)
	}
	if d.Version != "2.1.0" || len(d.Runs) != 1 {
		t.Fatalf("bad envelope: %+v", d)
	}
	r := d.Runs[0]
	if len(r.Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(r.Results))
	}
	if len(r.Tool.Driver.Rules) != 2 {
		t.Fatalf("expected 2 unique rules, got %d", len(r.Tool.Driver.Rules))
	}
	if r.Results[0].Level != "error" || r.Results[2].Level != "note" {
		t.Fatalf("severity->level mapping wrong: %s %s", r.Results[0].Level, r.Results[2].Level)
	}
}
