package lfi

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

func TestLFIDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("file"), "etc/passwd") {
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:"))
			return
		}
		w.Write([]byte("normal content"))
	}))
	defer srv.Close()

	fs := Test(context.Background(), client(t, srv.URL), srv.URL+"/?file=a.txt", nil)
	if len(fs) != 1 || fs[0].TemplateID != "lfi" || fs[0].Extracted["file"] != "/etc/passwd" {
		t.Fatalf("expected lfi finding, got %+v", fs)
	}
}

func TestLFINotVulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("file not found"))
	}))
	defer srv.Close()
	if fs := Test(context.Background(), client(t, srv.URL), srv.URL+"/?file=a.txt", nil); len(fs) != 0 {
		t.Fatalf("no lfi expected, got %+v", fs)
	}
}
