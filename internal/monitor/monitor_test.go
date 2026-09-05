package monitor

import (
	"testing"

	"github.com/talkdedsec/tlk-huntx/internal/finding"
	"github.com/talkdedsec/tlk-huntx/internal/graph"
)

func TestNewHosts(t *testing.T) {
	old := graph.New()
	old.Upsert(graph.Subdomain, "api.acme.com", nil)
	cur := graph.New()
	cur.Upsert(graph.Subdomain, "api.acme.com", nil)
	cur.Upsert(graph.Subdomain, "new.acme.com", nil)
	cur.Upsert(graph.Domain, "acme.com", nil) // non-subdomain must be ignored

	got := NewHosts(old, cur)
	if len(got) != 1 || got[0].Value != "new.acme.com" {
		t.Fatalf("expected only new.acme.com, got %v", got)
	}
}

func TestNewFindings(t *testing.T) {
	prev := []finding.Finding{{DedupKey: "a"}}
	cur := []finding.Finding{{DedupKey: "a"}, {DedupKey: "b"}}
	got := NewFindings(prev, cur)
	if len(got) != 1 || got[0].DedupKey != "b" {
		t.Fatalf("expected only b, got %v", got)
	}
}

func TestMerge(t *testing.T) {
	prev := []finding.Finding{{DedupKey: "a"}}
	cur := []finding.Finding{{DedupKey: "a"}, {DedupKey: "b"}}
	got := Merge(prev, cur)
	if len(got) != 2 {
		t.Fatalf("expected union of 2, got %d", len(got))
	}
}
