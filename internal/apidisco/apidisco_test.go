package apidisco

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
	return fetch.New(s, ratelimit.New(1000, 100, 10), blastradius.New(0, false), false)
}

func TestGraphQLIntrospection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/graphql" {
			w.Write([]byte(`{"data":{"__schema":{"queryType":{"name":"Query"}}}}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	fs, eps := GraphQL(context.Background(), client(t, srv.URL), srv.URL)
	if len(fs) != 1 || fs[0].TemplateID != "graphql-introspection" {
		t.Fatalf("expected introspection finding, got %+v", fs)
	}
	if len(eps) != 1 {
		t.Fatalf("expected 1 endpoint, got %v", eps)
	}
}

func TestOpenAPIExposed(t *testing.T) {
	spec := `{"openapi":"3.0.0","paths":{"/users":{"get":{},"post":{}},"/orders":{"get":{}}}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			w.Write([]byte(spec))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	fs, eps := OpenAPI(context.Background(), client(t, srv.URL), srv.URL)
	if len(fs) != 1 || fs[0].Extracted["endpoints"] != "3" {
		t.Fatalf("expected spec finding with 3 endpoints, got %+v", fs)
	}
	if len(eps) != 3 {
		t.Fatalf("expected 3 endpoints, got %d", len(eps))
	}
}

func TestNoApiSurface(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()
	fs, eps := Discover(context.Background(), client(t, srv.URL), srv.URL)
	if len(fs) != 0 || len(eps) != 0 {
		t.Fatalf("expected nothing, got %v %v", fs, eps)
	}
}
