package greybox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanTreeFindsSinks(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "handler.go"), []byte(`
package h
func serve() {
	route := "/api/run"
	exec.Command("sh", "-c", userInput)
	_ = route
}
`), 0o644)
	os.WriteFile(filepath.Join(dir, "safe.go"), []byte("package h\nfunc ok() {}\n"), 0o644)
	os.MkdirAll(filepath.Join(dir, "node_modules"), 0o755)
	os.WriteFile(filepath.Join(dir, "node_modules", "evil.js"), []byte(`eval(x)`), 0o644)

	reports, err := ScanTree(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 1 {
		t.Fatalf("expected 1 file with a sink (node_modules skipped), got %d", len(reports))
	}
	if reports[0].Sinks[0].Rule != "command-exec" {
		t.Fatalf("wrong rule: %+v", reports[0].Sinks)
	}
	found := false
	for _, r := range reports[0].Routes {
		if r == "/api/run" {
			found = true
		}
	}
	if !found {
		t.Fatalf("route not extracted: %v", reports[0].Routes)
	}
}

func TestCorrelate(t *testing.T) {
	reports := []FileReport{{
		Path:   "handler.go",
		Sinks:  []Sink{{File: "handler.go", Line: 5, Rule: "command-exec", Snippet: "exec.Command(...)"}},
		Routes: []string{"/api/run"},
	}}
	got := Correlate(reports, []string{"https://acme.com/api/run", "https://acme.com/other"})
	if len(got) != 1 {
		t.Fatalf("expected 1 correlated finding, got %d", len(got))
	}
	if got[0].CWE != "CWE-78" || got[0].MatchedAt != "https://acme.com/api/run" {
		t.Fatalf("bad finding: %+v", got[0])
	}
}

func TestCorrelateNoMatch(t *testing.T) {
	reports := []FileReport{{
		Sinks:  []Sink{{Rule: "code-eval"}},
		Routes: []string{"/internal/only"},
	}}
	if got := Correlate(reports, []string{"https://acme.com/public"}); len(got) != 0 {
		t.Fatalf("expected no correlation, got %d", len(got))
	}
}
