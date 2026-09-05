package template

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/talkdedsec/tlk-huntx/internal/blastradius"
	"github.com/talkdedsec/tlk-huntx/internal/fetch"
	"github.com/talkdedsec/tlk-huntx/internal/ratelimit"
	"github.com/talkdedsec/tlk-huntx/internal/scope"
)

func gatedClient(t *testing.T, rawurl string) *fetch.Client {
	t.Helper()
	u, _ := url.Parse(rawurl)
	s := &scope.Scope{InScope: []string{u.Hostname()}}
	if err := s.Compile(); err != nil {
		t.Fatal(err)
	}
	return fetch.New(s, ratelimit.New(1000, 100, 10), blastradius.New(0, false), false)
}

func TestBuiltinLoad(t *testing.T) {
	tpls, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if len(tpls) < 4 {
		t.Fatalf("expected builtin templates, got %d", len(tpls))
	}
	for _, tpl := range tpls {
		if tpl.ID == "" || len(tpl.blocks()) == 0 {
			t.Fatalf("bad template: %+v", tpl)
		}
	}
}

func TestRunDotenvMatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.WriteHeader(200)
			w.Write([]byte("DB_PASSWORD=hunter2\nAPI_KEY=abc123\n"))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	tpls, _ := Builtin()
	var dotenv *Template
	for _, tpl := range tpls {
		if tpl.ID == "exposed-dotenv" {
			dotenv = tpl
		}
	}
	if dotenv == nil {
		t.Fatal("exposed-dotenv template missing")
	}
	got := dotenv.Run(context.Background(), gatedClient(t, srv.URL), srv.URL)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].TemplateID != "exposed-dotenv" || got[0].Extracted["key"] == "" {
		t.Fatalf("unexpected finding: %+v", got[0])
	}
}

func TestRunNoMatchOnHTML(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("<!DOCTYPE html><html>FOO=bar not a real env</html>"))
	}))
	defer srv.Close()
	tpls, _ := Builtin()
	for _, tpl := range tpls {
		if tpl.ID == "exposed-dotenv" {
			if got := tpl.Run(context.Background(), gatedClient(t, srv.URL), srv.URL); len(got) != 0 {
				t.Fatalf("HTML page should not match .env, got %+v", got)
			}
		}
	}
}

func TestCorsReflection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	tpls, _ := Builtin()
	for _, tpl := range tpls {
		if tpl.ID == "cors-reflected-origin" {
			got := tpl.Run(context.Background(), gatedClient(t, srv.URL), srv.URL)
			if len(got) != 1 {
				t.Fatalf("expected CORS finding, got %d", len(got))
			}
		}
	}
}

func TestSelectByTech(t *testing.T) {
	tpls := []*Template{
		{ID: "generic"},
		{ID: "wp", Info: Info{Tags: "wordpress"}},
		{ID: "django", Info: Info{Tags: "django,cve"}},
	}
	got := SelectByTech(tpls, []string{"WordPress"})
	ids := map[string]bool{}
	for _, tpl := range got {
		ids[tpl.ID] = true
	}
	if !ids["generic"] || !ids["wp"] || ids["django"] {
		t.Fatalf("tech selection wrong: %v", ids)
	}
}

func TestSubdomainTakeover(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte("<h1>NoSuchBucket</h1>The specified bucket does not exist"))
	}))
	defer srv.Close()
	tpls, _ := Builtin()
	fired := false
	for _, tpl := range tpls {
		if tpl.ID == "subdomain-takeover" {
			if len(tpl.Run(context.Background(), gatedClient(t, srv.URL), srv.URL)) == 1 {
				fired = true
			}
		}
	}
	if !fired {
		t.Fatal("subdomain-takeover should fire on NoSuchBucket fingerprint")
	}
}

func TestSecurityHeaderNegativeLogic(t *testing.T) {
	tpls, _ := Builtin()
	var tpl *Template
	for _, x := range tpls {
		if x.ID == "security-header-missing" {
			tpl = x
		}
	}
	if tpl == nil {
		t.Fatal("template missing")
	}

	// no X-Frame-Options -> should fire
	bare := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer bare.Close()
	if len(tpl.Run(context.Background(), gatedClient(t, bare.URL), bare.URL)) != 1 {
		t.Fatal("missing header should fire")
	}

	// X-Frame-Options present -> must NOT fire
	protected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.WriteHeader(200)
	}))
	defer protected.Close()
	if len(tpl.Run(context.Background(), gatedClient(t, protected.URL), protected.URL)) != 0 {
		t.Fatal("present header should suppress the finding (negative matcher)")
	}
}

func TestParseJSON(t *testing.T) {
	tpl, err := Parse([]byte(`{"id":"x","http":[{"method":"GET","matchers":[{"type":"status","status":[200]}]}]}`), true)
	if err != nil || tpl.ID != "x" {
		t.Fatalf("json parse: %v %+v", err, tpl)
	}
}

func TestLoadDirSkipsBroken(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "good.yaml"), []byte("id: good\nhttp:\n  - matchers:\n      - type: status\n        status: [200]\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte("id: \nhttp: not-a-list\n:::"), 0o644)

	tpls, err := LoadDir(dir)
	if len(tpls) != 1 || tpls[0].ID != "good" {
		t.Fatalf("expected only the good template, got %+v", tpls)
	}
	if err == nil {
		t.Fatal("LoadDir should report the skipped broken template")
	}
}

func TestHeaderPartMatcher(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Express")
		w.WriteHeader(200)
	}))
	defer srv.Close()
	tpl, err := Parse([]byte(`id: hdr
http:
  - matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: header
        words: ["x-powered-by: Express"]
        case-insensitive: true
`), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(tpl.Run(context.Background(), gatedClient(t, srv.URL), srv.URL)) != 1 {
		t.Fatal("header-part word matcher should fire")
	}
}

func TestSizeMatcher(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("12345")) // 5 bytes
	}))
	defer srv.Close()
	tpl, _ := Parse([]byte("id: sz\nhttp:\n  - matchers:\n      - type: size\n        status: [5]\n"), false)
	if len(tpl.Run(context.Background(), gatedClient(t, srv.URL), srv.URL)) != 1 {
		t.Fatal("size matcher should match a 5-byte body")
	}
}
