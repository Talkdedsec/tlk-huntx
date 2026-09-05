package openredirect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	return fetch.New(s, ratelimit.New(2000, 200, 20), blastradius.New(0, false), false)
}

func TestOpenRedirectDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if next := r.URL.Query().Get("next"); next != "" {
			w.Header().Set("Location", next)
			w.WriteHeader(302)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	fs := Test(context.Background(), client(t, srv.URL), srv.URL+"/login?next=/home", nil)
	if len(fs) != 1 || fs[0].TemplateID != "open-redirect" {
		t.Fatalf("expected open-redirect, got %+v", fs)
	}
}

func TestNoRedirectSafe(t *testing.T) {
	// only ever redirects to a fixed internal path -> not an open redirect
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/dashboard")
		w.WriteHeader(302)
	}))
	defer srv.Close()
	if fs := Test(context.Background(), client(t, srv.URL), srv.URL+"/go?url=x", nil); len(fs) != 0 {
		t.Fatalf("internal redirect must not be flagged, got %+v", fs)
	}
}

func TestPointsToCanary(t *testing.T) {
	if !pointsToCanary("https://" + canary + "/x") {
		t.Error("absolute canary should match")
	}
	if !pointsToCanary("//" + canary + "/") {
		t.Error("scheme-relative canary should match")
	}
	if pointsToCanary("/internal/path") {
		t.Error("relative path should not match")
	}
	if pointsToCanary("https://legit.example/") {
		t.Error("other host should not match")
	}
}
