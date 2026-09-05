package reflectx

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/talkdedsec/tlk-huntx/internal/blastradius"
	"github.com/talkdedsec/tlk-huntx/internal/fetch"
	"github.com/talkdedsec/tlk-huntx/internal/finding"
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

func TestReflectedRaw(t *testing.T) {
	// echoes the q parameter verbatim -> reflected + unfiltered
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello " + r.URL.Query().Get("q")))
	}))
	defer srv.Close()

	fs := Test(context.Background(), client(t, srv.URL), srv.URL+"/?q=x", nil)
	if len(fs) != 1 || fs[0].Severity != finding.Medium {
		t.Fatalf("expected medium potential-xss, got %+v", fs)
	}
}

func TestReflectedEscaped(t *testing.T) {
	// echoes but HTML-escapes -> reflected (marker) but not unfiltered -> low
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello " + html.EscapeString(r.URL.Query().Get("q"))))
	}))
	defer srv.Close()

	fs := Test(context.Background(), client(t, srv.URL), srv.URL+"/?q=x", nil)
	if len(fs) != 1 || fs[0].Severity != finding.Low {
		t.Fatalf("expected low reflected (escaped), got %+v", fs)
	}
}

func TestNotReflected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("static page"))
	}))
	defer srv.Close()
	if fs := Test(context.Background(), client(t, srv.URL), srv.URL+"/?q=x", nil); len(fs) != 0 {
		t.Fatalf("no reflection expected, got %+v", fs)
	}
}

func TestExtraParams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.URL.Query().Get("search")))
	}))
	defer srv.Close()
	// URL has no query, but we supply the param name
	fs := Test(context.Background(), client(t, srv.URL), srv.URL+"/", []string{"search"})
	if len(fs) != 1 {
		t.Fatalf("extra param should be tested, got %+v", fs)
	}
}
