package fetch

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/talkdedsec/tlk-huntx/internal/blastradius"
	"github.com/talkdedsec/tlk-huntx/internal/ratelimit"
	"github.com/talkdedsec/tlk-huntx/internal/scope"
)

func newScope(t *testing.T, host string) *scope.Scope {
	t.Helper()
	s := &scope.Scope{InScope: []string{host}}
	if err := s.Compile(); err != nil {
		t.Fatal(err)
	}
	return s
}

func hostOf(rawurl string) string {
	u, _ := url.Parse(rawurl)
	return u.Hostname()
}

func TestDoAllowed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "test")
		w.WriteHeader(200)
		w.Write([]byte("hello"))
	}))
	defer srv.Close()

	s := newScope(t, hostOf(srv.URL))
	c := New(s, ratelimit.New(1000, 100, 10), blastradius.New(0, false), false)
	resp, err := c.Do(context.Background(), "GET", srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != 200 || string(resp.Body) != "hello" {
		t.Fatalf("unexpected response: %d %q", resp.Status, resp.Body)
	}
}

func TestDoOutOfScope(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer srv.Close()

	s := newScope(t, "only-this-host.example")
	c := New(s, ratelimit.New(1000, 100, 10), blastradius.New(0, false), false)
	_, err := c.Do(context.Background(), "GET", srv.URL, nil)
	if !errors.Is(err, ErrOutOfScope) {
		t.Fatalf("expected ErrOutOfScope, got %v", err)
	}
	if hit {
		t.Fatal("out-of-scope request reached the server")
	}
}

func TestDoStateChangingBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	s := newScope(t, hostOf(srv.URL))
	c := New(s, ratelimit.New(1000, 100, 10), blastradius.New(0, false), false)
	if _, err := c.Do(context.Background(), "POST", srv.URL, nil); !errors.Is(err, ErrBudget) {
		t.Fatalf("expected ErrBudget for POST, got %v", err)
	}
}

func TestDoForbiddenPath(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer srv.Close()
	s := &scope.Scope{InScope: []string{hostOf(srv.URL)}, ForbiddenPaths: []string{"/admin"}}
	if err := s.Compile(); err != nil {
		t.Fatal(err)
	}
	c := New(s, ratelimit.New(1000, 100, 10), blastradius.New(0, false), false)
	if _, err := c.Do(context.Background(), "GET", srv.URL+"/admin/delete", nil); !errors.Is(err, ErrForbiddenPath) {
		t.Fatalf("expected ErrForbiddenPath, got %v", err)
	}
	if hit {
		t.Fatal("forbidden path reached the server")
	}
}

func TestDoMethodBlocked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	s := &scope.Scope{InScope: []string{hostOf(srv.URL)}, AllowedMethods: []string{"GET"}}
	if err := s.Compile(); err != nil {
		t.Fatal(err)
	}
	// allow state-changing at blast-radius so the block comes from scope, not budget
	c := New(s, ratelimit.New(1000, 100, 10), blastradius.New(0, true), false)
	if _, err := c.Do(context.Background(), "POST", srv.URL+"/", nil); !errors.Is(err, ErrMethodBlocked) {
		t.Fatalf("expected ErrMethodBlocked, got %v", err)
	}
}

func TestDoHostHeaderOverride(t *testing.T) {
	var gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost = r.Host
	}))
	defer srv.Close()
	s := newScope(t, hostOf(srv.URL))
	c := New(s, ratelimit.New(1000, 100, 10), blastradius.New(0, false), false)
	if _, err := c.DoReq(context.Background(), "GET", srv.URL, map[string]string{"Host": "spoofed.example"}, nil); err != nil {
		t.Fatal(err)
	}
	if gotHost != "spoofed.example" {
		t.Fatalf("Host override failed: %q", gotHost)
	}
}

func TestDoDryRun(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer srv.Close()
	s := newScope(t, hostOf(srv.URL))
	c := New(s, ratelimit.New(1000, 100, 10), blastradius.New(0, false), true)
	resp, err := c.Do(context.Background(), "GET", srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !resp.DryRun || hit {
		t.Fatal("dry-run should not touch the server")
	}
}
