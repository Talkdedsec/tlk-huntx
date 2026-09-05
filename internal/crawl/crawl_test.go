package crawl

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

func TestEndpointsAndParams(t *testing.T) {
	body := `
	fetch("/api/users?id=1");
	<form><input name="email"><input name="csrf_token"></form>
	const u = "https://cdn.acme.com/v2/orders?status=open";
	`
	eps := Endpoints(body)
	if !has(eps, "/api/users") || !has(eps, "/v2/orders") {
		t.Fatalf("endpoints: %v", eps)
	}
	ps := Params(body)
	if !has(ps, "id") || !has(ps, "email") || !has(ps, "csrf_token") || !has(ps, "status") {
		t.Fatalf("params: %v", ps)
	}
}

func TestParamsIgnoresMetaNames(t *testing.T) {
	body := `
	<meta name="application-name" content="x">
	<meta name="format-detection" content="telephone=no">
	<link rel="icon" name="whatever">
	<form><input name="realparam"></form>
	`
	ps := Params(body)
	if !has(ps, "realparam") {
		t.Fatalf("real form field missing: %v", ps)
	}
	for _, junk := range []string{"application-name", "format-detection", "whatever"} {
		if has(ps, junk) {
			t.Fatalf("meta/link name %q must not be treated as a parameter: %v", junk, ps)
		}
	}
}

func TestParamsFromRealURLsOnly(t *testing.T) {
	body := `
	<a href="/search?q=x&title=hi">s</a>
	const frag = "f?g=h";        // code fragment, no path slash -> ignore
	const asset = "/app.js?v=3"; // real url -> v
	const num = "/x?13=y";       // numeric-only key -> ignore
	`
	ps := Params(body)
	for _, want := range []string{"q", "title", "v"} {
		if !has(ps, want) {
			t.Errorf("missing real param %q: %v", want, ps)
		}
	}
	for _, junk := range []string{"g", "13"} {
		if has(ps, junk) {
			t.Errorf("junk %q must be filtered: %v", junk, ps)
		}
	}
}

func TestRobotsAndSitemapParse(t *testing.T) {
	robots := "User-agent: *\nDisallow: /admin\nAllow: /public\nDisallow: /api/secret\nSitemap: http://x/sitemap.xml\n"
	rp := RobotsPaths(robots)
	if !has(rp, "/admin") || !has(rp, "/public") || !has(rp, "/api/secret") {
		t.Fatalf("robots paths: %v", rp)
	}
	sm := `<urlset><url><loc>https://a/one</loc></url><url><loc>https://a/two</loc></url></urlset>`
	locs := SitemapURLs(sm)
	if len(locs) != 2 || !has(locs, "https://a/one") {
		t.Fatalf("sitemap locs: %v", locs)
	}
}

func TestRunPullsRobotsAndSitemap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Write([]byte("<html>home</html>"))
		case "/robots.txt":
			w.Write([]byte("Disallow: /hidden-admin\n"))
		case "/sitemap.xml":
			w.Write([]byte(`<urlset><url><loc>` + "http://" + r.Host + `/from-sitemap</loc></url></urlset>`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	s := &scope.Scope{InScope: []string{u.Hostname()}}
	s.Compile()
	c := fetch.New(s, ratelimit.New(2000, 200, 10), blastradius.New(0, false), false)

	res := Run(context.Background(), c, srv.URL)
	if !has(res.Endpoints, "/hidden-admin") {
		t.Fatalf("robots path not discovered: %v", res.Endpoints)
	}
	if !has(res.Endpoints, "/from-sitemap") {
		t.Fatalf("sitemap path not discovered: %v", res.Endpoints)
	}
}

func TestScriptSrcsSameHostOnly(t *testing.T) {
	body := `<script src="/app.js"></script><script src="https://evil.com/x.js"></script>`
	got := ScriptSrcs(body, "https://acme.com/")
	if len(got) != 1 || got[0] != "https://acme.com/app.js" {
		t.Fatalf("script srcs: %v", got)
	}
}

func TestRunFollowsScripts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Write([]byte(`<script src="/bundle.js"></script><form><input name="q"></form>`))
		case "/bundle.js":
			w.Write([]byte(`axios.get("/api/secret?token=1")`))
		}
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	s := &scope.Scope{InScope: []string{u.Hostname()}}
	s.Compile()
	c := fetch.New(s, ratelimit.New(1000, 100, 10), blastradius.New(0, false), false)

	res := Run(context.Background(), c, srv.URL)
	if !has(res.Endpoints, "/api/secret") {
		t.Fatalf("endpoint from script not found: %v", res.Endpoints)
	}
	if !has(res.Params, "q") || !has(res.Params, "token") {
		t.Fatalf("params merged wrong: %v", res.Params)
	}
}

func has(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
