package agent

import (
	"testing"

	"github.com/talkdedsec/tlk-huntx/internal/finding"
)

func mkFinding(id, tid string, sev finding.Severity, conf int, verified bool) finding.Finding {
	return finding.Finding{ID: id, TemplateID: tid, Type: tid, Severity: sev, Confidence: conf, Verified: verified, MatchedAt: "https://a/x"}
}

func TestPlanEVOrder(t *testing.T) {
	fs := []finding.Finding{
		mkFinding("1", "directory-listing", finding.Low, 70, false),
		mkFinding("2", "exposed-dotenv", finding.High, 95, true),
	}
	actions := Plan(fs)
	if actions[0].Findings[0] != "2" {
		t.Fatalf("high-EV finding should rank first, got %+v", actions[0])
	}
}

func TestPlanComposesChain(t *testing.T) {
	fs := []finding.Finding{
		mkFinding("1", "cors-reflected-origin", finding.Medium, 85, true),
		mkFinding("2", "openapi-exposed", finding.Info, 90, false),
	}
	actions := Plan(fs)
	if !actions[0].Chain {
		t.Fatalf("chain should be planned first, got %+v", actions[0])
	}
	if len(actions[0].Findings) < 2 {
		t.Fatalf("chain should reference both findings: %+v", actions[0])
	}
	// EV of the chain must beat its members
	if actions[0].EV <= ev(fs[0]) {
		t.Fatalf("chain EV should exceed members: %v", actions[0].EV)
	}
}

func TestPlanNoChainWhenIncomplete(t *testing.T) {
	fs := []finding.Finding{mkFinding("1", "cors-reflected-origin", finding.Medium, 85, true)}
	for _, a := range Plan(fs) {
		if a.Chain {
			t.Fatal("no chain should form from a single member")
		}
	}
}
