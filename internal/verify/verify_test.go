package verify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/talkdedsec/tlk-huntx/internal/blastradius"
	"github.com/talkdedsec/tlk-huntx/internal/fetch"
	"github.com/talkdedsec/tlk-huntx/internal/finding"
	"github.com/talkdedsec/tlk-huntx/internal/ratelimit"
	"github.com/talkdedsec/tlk-huntx/internal/scope"
	"github.com/talkdedsec/tlk-huntx/internal/secrets"
	"github.com/talkdedsec/tlk-huntx/internal/template"
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

func TestReconfirmTemplate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.Write([]byte("SECRET_KEY=abc\nDB_HOST=localhost\n"))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	tpls, _ := template.Builtin()
	c := client(t, srv.URL)
	var f finding.Finding
	for _, tpl := range tpls {
		if tpl.ID == "exposed-dotenv" {
			f = tpl.Run(context.Background(), c, srv.URL)[0]
		}
	}
	if !Reconfirm(context.Background(), c, tpls, f) {
		t.Fatal("expected reconfirm to fire again")
	}
}

func TestReconfirmSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`var k = "AKIAIOSFODNN7EXAMPLE";`))
	}))
	defer srv.Close()
	c := client(t, srv.URL)
	fs := secrets.Scan(srv.URL, `var k = "AKIAIOSFODNN7EXAMPLE";`)
	if len(fs) == 0 {
		t.Fatal("setup: expected a secret finding")
	}
	if !Reconfirm(context.Background(), c, nil, fs[0]) {
		t.Fatal("secret should re-confirm by re-fetching")
	}
}

func TestReconfirmMiss(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()
	c := client(t, srv.URL)
	tpls, _ := template.Builtin()
	f := finding.Finding{TemplateID: "exposed-dotenv", Target: srv.URL, MatchedAt: srv.URL + "/.env"}
	if Reconfirm(context.Background(), c, tpls, f) {
		t.Fatal("should not re-confirm a finding that no longer fires")
	}
}

func TestDifferentialBOLA(t *testing.T) {
	// Broken: returns the owner's data to anyone.
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("account balance: 4200"))
	}))
	defer broken.Close()

	c := client(t, broken.URL)
	owner := Creds{Label: "userA", Headers: map[string]string{"X-User": "A"}}
	other := Creds{Label: "userB", Headers: map[string]string{"X-User": "B"}}
	if _, ok := Differential(context.Background(), c, broken.URL+"/api/account/1", owner, other); !ok {
		t.Fatal("expected BOLA on broken endpoint")
	}
}

func TestDifferentialProperAuth(t *testing.T) {
	// Correct: only the owner sees the data, others get 403.
	secure := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-User") == "A" {
			w.WriteHeader(200)
			w.Write([]byte("account balance: 4200"))
			return
		}
		w.WriteHeader(403)
	}))
	defer secure.Close()

	c := client(t, secure.URL)
	owner := Creds{Label: "userA", Headers: map[string]string{"X-User": "A"}}
	other := Creds{Label: "userB", Headers: map[string]string{"X-User": "B"}}
	anon := Creds{Label: "anonymous"}
	if _, ok := Differential(context.Background(), c, secure.URL+"/api/account/1", owner, other, anon); ok {
		t.Fatal("properly authorized endpoint must not be flagged")
	}
}
