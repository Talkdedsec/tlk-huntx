package recon

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

func TestParseCrtSh(t *testing.T) {
	body := `[{"name_value":"*.acme.com\napi.acme.com","common_name":"www.acme.com"},
	          {"name_value":"mail.acme.com","common_name":"acme.com"}]`
	got, err := parseCrtSh(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("parsed nothing")
	}
}

func TestParseWayback(t *testing.T) {
	body := `[["original"],["https://api.acme.com/a"],["http://cdn.acme.com/x.js"]]`
	got, err := parseWayback(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "api.acme.com" || got[1] != "cdn.acme.com" {
		t.Fatalf("unexpected: %v", got)
	}
}

func TestParseOTX(t *testing.T) {
	body := `{"passive_dns":[{"hostname":"vpn.acme.com"},{"hostname":"api.acme.com"}]}`
	got, err := parseOTX(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2, got %v", got)
	}
}

func TestParseHackerTarget(t *testing.T) {
	body := "api.acme.com,192.0.2.1\nwww.acme.com,192.0.2.2\nAPI count exceeded\n"
	got, err := parseHackerTarget(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "api.acme.com" || got[1] != "www.acme.com" {
		t.Fatalf("unexpected: %v", got)
	}
}

func TestCleanHost(t *testing.T) {
	cases := map[string]string{
		"*.acme.com":    "acme.com",
		"API.ACME.COM":  "api.acme.com",
		"api.acme.com.": "api.acme.com",
		"evil.com":      "",
		"a b":           "",
		"sub.acme.com":  "sub.acme.com",
	}
	for in, want := range cases {
		if got := cleanHost(in, "acme.com"); got != want {
			t.Errorf("cleanHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExtractTitleAndFingerprint(t *testing.T) {
	if got := extractTitle([]byte("<html><TITLE> Hello &amp; Co </TITLE>")); got != "Hello & Co" {
		t.Errorf("title = %q", got)
	}
	if got := fingerprint("nginx", "PHP/8.2", []byte("<div class=wp-content>")); !strings.Contains(got, "WordPress") || !strings.Contains(got, "nginx") {
		t.Errorf("fingerprint = %q", got)
	}
}

func TestProbeGated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Write([]byte("<title>ok</title>"))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)

	s := &scope.Scope{InScope: []string{u.Hostname()}}
	if err := s.Compile(); err != nil {
		t.Fatal(err)
	}
	c := fetch.New(s, ratelimit.New(1000, 100, 10), blastradius.New(0, false), false)

	// The probe uses scheme+host; feed it host:port so it reaches the test server.
	results := Probe(context.Background(), c, []string{u.Host}, 4)
	if len(results) != 1 || !results[0].Live || results[0].Server != "nginx" {
		t.Fatalf("probe result: %+v", results)
	}
}
