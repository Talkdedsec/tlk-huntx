package hostheader

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

func TestHostReflectedInBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// naive app builds an absolute link from the Host header
		w.Write([]byte(`<a href="https://` + r.Host + `/reset">reset</a>`))
	}))
	defer srv.Close()

	fs := Test(context.Background(), client(t, srv.URL), srv.URL+"/")
	if len(fs) != 1 || fs[0].TemplateID != "host-header-injection" {
		t.Fatalf("expected host-header finding, got %+v", fs)
	}
}

func TestForwardedHostReflected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
			w.Header().Set("Location", "https://"+xfh+"/next")
			w.WriteHeader(302)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	fs := Test(context.Background(), client(t, srv.URL), srv.URL+"/")
	if len(fs) != 1 || fs[0].Extracted["reflected_in"] != "Location header" {
		t.Fatalf("expected XFH reflection in Location, got %+v", fs)
	}
}

func TestNoReflection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("static site, fixed canonical host"))
	}))
	defer srv.Close()
	if fs := Test(context.Background(), client(t, srv.URL), srv.URL+"/"); len(fs) != 0 {
		t.Fatalf("no reflection expected, got %+v", fs)
	}
}
