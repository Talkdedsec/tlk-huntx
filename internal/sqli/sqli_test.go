package sqli

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

func TestErrorBasedDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.ContainsAny(id, "'\"") {
			w.WriteHeader(500)
			w.Write([]byte("You have an error in your SQL syntax near ''' at line 1"))
			return
		}
		w.Write([]byte("ok product 1"))
	}))
	defer srv.Close()

	fs := Test(context.Background(), client(t, srv.URL), srv.URL+"/p?id=1", nil)
	if len(fs) != 1 || fs[0].TemplateID != "sqli-error" || fs[0].Extracted["dbms"] != "MySQL" {
		t.Fatalf("expected MySQL sqli finding, got %+v", fs)
	}
}

func TestNoErrorNoFinding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("normal page, no db errors ever"))
	}))
	defer srv.Close()
	if fs := Test(context.Background(), client(t, srv.URL), srv.URL+"/p?id=1", nil); len(fs) != 0 {
		t.Fatalf("no sqli expected, got %+v", fs)
	}
}

func TestNoParamsNoRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("no parameters means no requests should be sent")
	}))
	defer srv.Close()
	if fs := Test(context.Background(), client(t, srv.URL), srv.URL+"/", nil); fs != nil {
		t.Fatalf("expected nil for a URL with no params, got %+v", fs)
	}
}

func TestBaselineErrorNotFlagged(t *testing.T) {
	// page always contains the error string, even without injection -> must not flag
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("debug: You have an error in your SQL syntax (static text)"))
	}))
	defer srv.Close()
	if fs := Test(context.Background(), client(t, srv.URL), srv.URL+"/p?id=1", nil); len(fs) != 0 {
		t.Fatalf("baseline error text must not be flagged, got %+v", fs)
	}
}
