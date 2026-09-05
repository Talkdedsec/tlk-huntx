package engine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/talkdedsec/tlk-huntx/internal/scope"
)

func scopeFor(t *testing.T, rawurl string) *scope.Scope {
	t.Helper()
	u, _ := url.Parse(rawurl)
	s := &scope.Scope{InScope: []string{u.Hostname()}}
	if err := s.Compile(); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestScanEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.Write([]byte("DB_PASSWORD=secret\nAPI_KEY=abc\n"))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	opts := Options{Scope: scopeFor(t, srv.URL), RPS: 1000, Concurrency: 10}
	findings := Scan(context.Background(), []Target{{Base: srv.URL}}, opts)

	got := false
	for _, f := range findings {
		if f.TemplateID == "exposed-dotenv" {
			got = true
		}
	}
	if !got {
		t.Fatalf("expected exposed-dotenv finding, got %+v", findings)
	}
}

func TestScanVerifyMarks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.Write([]byte("SECRET_TOKEN=x\nDB_HOST=y\n"))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	opts := Options{Scope: scopeFor(t, srv.URL), RPS: 1000, Concurrency: 10, Verify: true}
	findings := Scan(context.Background(), []Target{{Base: srv.URL}}, opts)
	for _, f := range findings {
		if f.TemplateID == "exposed-dotenv" && (!f.Verified || f.Confidence != 95) {
			t.Fatalf("verify should mark the finding: %+v", f)
		}
	}
}

func TestScanMultipleTargetsConcurrent(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.Write([]byte("DB_PASSWORD=secret\nAPI_KEY=abc\n"))
			return
		}
		w.WriteHeader(404)
	})
	s1 := httptest.NewServer(handler)
	defer s1.Close()
	s2 := httptest.NewServer(handler)
	defer s2.Close()

	// both httptest servers share host 127.0.0.1; scope on that host covers both
	sc := &scope.Scope{InScope: []string{"127.0.0.1"}}
	if err := sc.Compile(); err != nil {
		t.Fatal(err)
	}
	opts := Options{Scope: sc, RPS: 2000, Concurrency: 8}
	findings := Scan(context.Background(), []Target{{Base: s1.URL}, {Base: s2.URL}}, opts)

	hits := 0
	for _, f := range findings {
		if f.TemplateID == "exposed-dotenv" {
			hits++
		}
	}
	if hits != 2 {
		t.Fatalf("expected one dotenv finding per distinct target (2), got %d (%+v)", hits, findings)
	}
}

func TestScanSkipsOutOfScopeTarget(t *testing.T) {
	opts := Options{Scope: scopeFor(t, "https://only.example"), RPS: 1000, Concurrency: 10}
	// target host is not in scope -> engine must not produce findings and must not panic
	findings := Scan(context.Background(), []Target{{Base: "https://evil.test/"}}, opts)
	if len(findings) != 0 {
		t.Fatalf("out-of-scope target must yield nothing, got %d", len(findings))
	}
}
