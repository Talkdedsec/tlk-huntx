package ssti

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

func TestSSTIEvaluated(t *testing.T) {
	// naive template that evaluates {{7*7}} inside the value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query().Get("name")
		v = strings.ReplaceAll(v, "{{7*7}}", "49")
		w.Write([]byte("Hello " + v))
	}))
	defer srv.Close()

	fs := Test(context.Background(), client(t, srv.URL), srv.URL+"/?name=x", nil)
	if len(fs) != 1 || fs[0].TemplateID != "ssti" {
		t.Fatalf("expected ssti finding, got %+v", fs)
	}
}

func TestSSTIReflectedButNotEvaluated(t *testing.T) {
	// reflects the payload literally -> zq{{7*7}}, never zq49 -> no finding
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello " + r.URL.Query().Get("name")))
	}))
	defer srv.Close()
	if fs := Test(context.Background(), client(t, srv.URL), srv.URL+"/?name=x", nil); len(fs) != 0 {
		t.Fatalf("literal reflection must not be flagged as SSTI, got %+v", fs)
	}
}
