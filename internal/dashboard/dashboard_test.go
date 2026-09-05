package dashboard

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHandlerServesPageAndData(t *testing.T) {
	dir := t.TempDir()
	gp := filepath.Join(dir, "g.json")
	fp := filepath.Join(dir, "f.jsonl")
	os.WriteFile(gp, []byte(`{"nodes":{"subdomain:a":{"kind":"subdomain","value":"a"}},"edges":[]}`), 0o644)
	os.WriteFile(fp, []byte(`{"template_id":"x","severity":"high"}`+"\n"+`{"template_id":"y","severity":"low"}`+"\n"), 0o644)

	srv := httptest.NewServer(Handler(gp, fp))
	defer srv.Close()

	if body := get(t, srv.URL+"/"); !strings.Contains(body, "<title>huntx</title>") {
		t.Fatal("index page not served")
	}
	if body := get(t, srv.URL+"/api/graph"); !strings.Contains(body, "subdomain:a") {
		t.Fatalf("graph api wrong: %s", body)
	}
	body := get(t, srv.URL+"/api/findings")
	if !strings.HasPrefix(strings.TrimSpace(body), "[") || !strings.Contains(body, `"template_id":"x"`) {
		t.Fatalf("findings api should be a json array: %s", body)
	}
}

func TestMissingFilesAreEmpty(t *testing.T) {
	srv := httptest.NewServer(Handler("/nope/g.json", "/nope/f.jsonl"))
	defer srv.Close()
	if get(t, srv.URL+"/api/findings") != "[]" {
		t.Fatal("missing findings should be []")
	}
}

func get(t *testing.T, u string) string {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}
