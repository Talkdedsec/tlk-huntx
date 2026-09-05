package fuzz

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/talkdedsec/tlk-huntx/internal/blastradius"
	"github.com/talkdedsec/tlk-huntx/internal/fetch"
	"github.com/talkdedsec/tlk-huntx/internal/ratelimit"
	"github.com/talkdedsec/tlk-huntx/internal/scope"
)

func client(t *testing.T, rawurl string) *fetch.Client {
	t.Helper()
	u, _ := url.Parse(rawurl)
	s := &scope.Scope{InScope: []string{u.Hostname()}}
	if err := s.Compile(); err != nil {
		t.Fatal(err)
	}
	return fetch.New(s, ratelimit.New(1000, 100, 20), blastradius.New(0, false), false)
}

func TestWordsDefault(t *testing.T) {
	w, err := Words("")
	if err != nil || len(w) < 20 {
		t.Fatalf("default wordlist too small: %d %v", len(w), err)
	}
}

func TestWordsFromFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "w.txt")
	os.WriteFile(p, []byte("# comment\n/admin\nlogin\n\n"), 0o644)
	w, err := Words(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(w) != 2 || w[0] != "admin" || w[1] != "login" {
		t.Fatalf("custom wordlist parse wrong: %v", w)
	}
}

func TestWordsFileMissing(t *testing.T) {
	if _, err := Words("/no/such/wordlist.txt"); err == nil {
		t.Fatal("expected error for missing wordlist")
	}
}

func TestRunFindsRealPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.WriteHeader(200)
			w.Write([]byte("admin panel"))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	hits := Run(context.Background(), client(t, srv.URL), srv.URL, []string{"admin", "login", "nope"}, 5)
	if len(hits) != 1 || hits[0].Status != 200 {
		t.Fatalf("expected only /admin, got %+v", hits)
	}
}

func TestRunSoft404Filtered(t *testing.T) {
	// catch-all: every path returns the same 200 body
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("same page for everything"))
	}))
	defer srv.Close()

	hits := Run(context.Background(), client(t, srv.URL), srv.URL, []string{"admin", "login", "config"}, 5)
	if len(hits) != 0 {
		t.Fatalf("soft-404 catch-all should filter everything, got %+v", hits)
	}
}
