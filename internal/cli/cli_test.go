package cli

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/talkdedsec/tlk-huntx/internal/finding"
)

func capture(fn func() int) (string, int) {
	oldOut, oldErr := os.Stdout, os.Stderr
	r, w, _ := os.Pipe()
	os.Stdout, os.Stderr = w, w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	code := fn()
	w.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	return <-done, code
}

func scopeFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scope.json")
	os.WriteFile(p, []byte(`{"program":"acme","in_scope":["*.acme.com"]}`), 0o644)
	return p
}

func TestExecuteVersion(t *testing.T) {
	out, code := capture(func() int { return Execute([]string{"version"}) })
	if code != 0 || !strings.Contains(out, "huntx") {
		t.Fatalf("version: code=%d out=%q", code, out)
	}
}

func TestExecuteScopeCheck(t *testing.T) {
	p := scopeFile(t)
	out, code := capture(func() int {
		return Execute([]string{"--scope", p, "scope", "check", "api.acme.com", "evil.com"})
	})
	if code != 0 || !strings.Contains(out, "IN ") || !strings.Contains(out, "OUT") {
		t.Fatalf("scope check: code=%d out=%q", code, out)
	}
}

func TestExecuteBlockedWithoutAuthorized(t *testing.T) {
	p := scopeFile(t)
	out, code := capture(func() int { return Execute([]string{"--scope", p, "recon"}) })
	if code != 1 || !strings.Contains(out, "blocked") {
		t.Fatalf("recon without --authorized should be blocked: code=%d out=%q", code, out)
	}
}

func TestExecuteTemplatesLists(t *testing.T) {
	out, code := capture(func() int { return Execute([]string{"templates"}) })
	if code != 0 || !strings.Contains(out, "exposed-dotenv") || !strings.Contains(out, "subdomain-takeover") {
		t.Fatalf("templates: code=%d out=%q", code, out)
	}
}

func TestFilterSeverity(t *testing.T) {
	fs := []finding.Finding{
		{Severity: finding.Info}, {Severity: finding.Low}, {Severity: finding.Medium},
		{Severity: finding.High}, {Severity: finding.Critical},
	}
	if got := filterSeverity(fs, ""); len(got) != 5 {
		t.Fatalf("empty threshold keeps all, got %d", len(got))
	}
	if got := filterSeverity(fs, "medium"); len(got) != 3 {
		t.Fatalf("medium+ should keep 3, got %d", len(got))
	}
	if got := filterSeverity(fs, "critical"); len(got) != 1 {
		t.Fatalf("critical should keep 1, got %d", len(got))
	}
}

func TestExecuteUnknownCommand(t *testing.T) {
	_, code := capture(func() int { return Execute([]string{"bogus"}) })
	if code != 2 {
		t.Fatalf("unknown command should exit 2, got %d", code)
	}
}

func TestExecuteFeedback(t *testing.T) {
	t.Chdir(t.TempDir())
	_, code := capture(func() int { return Execute([]string{"feedback", "accept", "exposed-dotenv"}) })
	if code != 0 {
		t.Fatalf("feedback exit %d", code)
	}
	if _, err := os.Stat("huntx.feedback.json"); err != nil {
		t.Fatalf("feedback file not written: %v", err)
	}
}

func TestExecutePlan(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.jsonl")
	os.WriteFile(in, []byte(`{"template_id":"exposed-dotenv","type":"Exposed dotenv","severity":"high","matched_at":"https://a/x","confidence":95}`+"\n"), 0o644)
	out, code := capture(func() int { return Execute([]string{"plan", in}) })
	if code != 0 || !strings.Contains(out, "Exposed dotenv") {
		t.Fatalf("plan: code=%d out=%q", code, out)
	}
}

func TestExecuteFeedbackBadArgs(t *testing.T) {
	_, code := capture(func() int { return Execute([]string{"feedback", "maybe", "x"}) })
	if code != 2 {
		t.Fatalf("bad feedback verb should exit 2, got %d", code)
	}
}

func TestFlagsAfterCommand(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.jsonl")
	out := filepath.Join(dir, "r.md")
	os.WriteFile(in, []byte(`{"template_id":"exposed-dotenv","type":"Exposed dotenv","severity":"high","matched_at":"https://a/x"}`+"\n"), 0o644)
	// -o placed AFTER the command and its positional must still be honored
	_, code := capture(func() int { return Execute([]string{"report", in, "-o", out}) })
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("output flag after command was ignored: %v", err)
	}
}

func TestExecuteReportMarkdown(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.jsonl")
	os.WriteFile(in, []byte(`{"template_id":"exposed-dotenv","type":"Exposed dotenv","severity":"high","matched_at":"https://a/x"}`+"\n"), 0o644)
	out, code := capture(func() int { return Execute([]string{"report", in}) })
	if code != 0 || !strings.Contains(out, "# Security findings") || !strings.Contains(out, "Exposed dotenv") {
		t.Fatalf("report markdown: code=%d out=%q", code, out)
	}
}

func TestExecuteScopeCheckStdin(t *testing.T) {
	p := scopeFile(t)
	oldIn := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r
	go func() { w.WriteString("api.acme.com\nevil.com\n"); w.Close() }()
	out, code := capture(func() int { return Execute([]string{"--scope", p, "scope", "check"}) })
	os.Stdin = oldIn
	if code != 0 || !strings.Contains(out, "api.acme.com") || !strings.Contains(out, "evil.com") {
		t.Fatalf("scope check stdin: code=%d out=%q", code, out)
	}
}

func TestExecuteReportSarif(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "f.jsonl")
	out := filepath.Join(dir, "out.sarif")
	os.WriteFile(in, []byte(`{"template_id":"exposed-dotenv","severity":"high","matched_at":"https://a/x"}`+"\n"), 0o644)
	_, code := capture(func() int { return Execute([]string{"-o", out, "report", in}) })
	if code != 0 {
		t.Fatalf("report sarif exit %d", code)
	}
	b, err := os.ReadFile(out)
	if err != nil || !strings.Contains(string(b), `"version": "2.1.0"`) {
		t.Fatalf("sarif not written: %v %s", err, b)
	}
}
