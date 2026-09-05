package ssrf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/talkdedsec/tlk-huntx/internal/blastradius"
	"github.com/talkdedsec/tlk-huntx/internal/collaborator"
	"github.com/talkdedsec/tlk-huntx/internal/fetch"
	"github.com/talkdedsec/tlk-huntx/internal/ratelimit"
	"github.com/talkdedsec/tlk-huntx/internal/scope"
)

func TestSSRFDetectedViaOOB(t *testing.T) {
	collab := collaborator.NewServer("")
	oob := httptest.NewServer(collab.Handler())
	defer oob.Close()
	collab.SetBase(oob.URL)

	// The vulnerable target fetches whatever the "url" param points to (server-side).
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if dst := r.URL.Query().Get("url"); dst != "" {
			resp, err := http.Get(dst)
			if err == nil {
				resp.Body.Close()
			}
		}
		w.WriteHeader(200)
	}))
	defer target.Close()

	u, _ := url.Parse(target.URL)
	s := &scope.Scope{InScope: []string{u.Hostname()}}
	if err := s.Compile(); err != nil {
		t.Fatal(err)
	}
	c := fetch.New(s, ratelimit.New(2000, 200, 20), blastradius.New(0, false), false)

	fs := Test(context.Background(), c, collab, target.URL+"/fetch?url=x", nil, 0)
	if len(fs) == 0 {
		t.Fatal("expected an SSRF finding from the OOB callback")
	}
	if fs[0].TemplateID != "ssrf-oob" || !fs[0].Verified {
		t.Fatalf("unexpected finding: %+v", fs[0])
	}
}

func TestNoSSRFNoCallback(t *testing.T) {
	collab := collaborator.NewServer("")
	oob := httptest.NewServer(collab.Handler())
	defer oob.Close()
	collab.SetBase(oob.URL)

	// Target ignores the param -> no callback -> no finding.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer target.Close()

	u, _ := url.Parse(target.URL)
	s := &scope.Scope{InScope: []string{u.Hostname()}}
	s.Compile()
	c := fetch.New(s, ratelimit.New(2000, 200, 20), blastradius.New(0, false), false)

	if fs := Test(context.Background(), c, collab, target.URL+"/x?url=y", nil, 0); len(fs) != 0 {
		t.Fatalf("no SSRF expected, got %+v", fs)
	}
}
