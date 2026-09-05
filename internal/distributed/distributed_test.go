package distributed

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/talkdedsec/tlk-huntx/internal/finding"
)

func TestCoordinatorWorkerRoundTrip(t *testing.T) {
	c := NewCoordinator([]string{"https://a", "https://b", "https://c"})
	srv := httptest.NewServer(c.Handler())
	defer srv.Close()

	scan := func(target string) []finding.Finding {
		return []finding.Finding{{TemplateID: "t", MatchedAt: target, DedupKey: target}}
	}
	if err := Work(context.Background(), srv.URL, scan); err != nil {
		t.Fatal(err)
	}
	if !c.Complete() {
		t.Fatal("coordinator should be complete after draining the queue")
	}
	if len(c.Results()) != 3 {
		t.Fatalf("expected 3 findings aggregated, got %d", len(c.Results()))
	}
}

func TestNextDrains(t *testing.T) {
	c := NewCoordinator([]string{"only"})
	srv := httptest.NewServer(c.Handler())
	defer srv.Close()
	if _, ok, _ := next(context.Background(), srv.Client(), srv.URL); !ok {
		t.Fatal("first next should return a target")
	}
	if _, ok, _ := next(context.Background(), srv.Client(), srv.URL); ok {
		t.Fatal("second next should be empty (204)")
	}
}
