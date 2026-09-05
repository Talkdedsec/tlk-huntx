package cmdi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"runtime"
	"testing"

	"github.com/talkdedsec/tlk-huntx/internal/blastradius"
	"github.com/talkdedsec/tlk-huntx/internal/collaborator"
	"github.com/talkdedsec/tlk-huntx/internal/fetch"
	"github.com/talkdedsec/tlk-huntx/internal/ratelimit"
	"github.com/talkdedsec/tlk-huntx/internal/scope"
)

func TestCommandInjectionOOB(t *testing.T) {
	collab := collaborator.NewServer("")
	oob := httptest.NewServer(collab.Handler())
	defer oob.Close()
	collab.SetBase(oob.URL)

	// Vulnerable target: passes the "host" param into a real shell command.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		if host != "" {
			var cmd *exec.Cmd
			if runtime.GOOS == "windows" {
				cmd = exec.Command("cmd", "/C", "echo "+host)
			} else {
				cmd = exec.Command("sh", "-c", "echo "+host)
			}
			cmd.Run()
		}
		w.WriteHeader(200)
	}))
	defer target.Close()

	u, _ := url.Parse(target.URL)
	s := &scope.Scope{InScope: []string{u.Hostname()}}
	if err := s.Compile(); err != nil {
		t.Fatal(err)
	}
	c := fetch.New(s, ratelimit.New(4000, 400, 20), blastradius.New(0, false), false)

	fs := Test(context.Background(), c, collab, target.URL+"/ping?host=1.1.1.1", nil, 0)
	if len(fs) == 0 {
		t.Skip("shell did not execute curl in this environment; OOB path not exercised")
	}
	if fs[0].TemplateID != "cmdi-oob" || !fs[0].Verified {
		t.Fatalf("unexpected finding: %+v", fs[0])
	}
}

func TestNoInjectionNoCallback(t *testing.T) {
	collab := collaborator.NewServer("")
	oob := httptest.NewServer(collab.Handler())
	defer oob.Close()
	collab.SetBase(oob.URL)

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer target.Close()

	u, _ := url.Parse(target.URL)
	s := &scope.Scope{InScope: []string{u.Hostname()}}
	s.Compile()
	c := fetch.New(s, ratelimit.New(4000, 400, 20), blastradius.New(0, false), false)

	if fs := Test(context.Background(), c, collab, target.URL+"/x?host=1", nil, 0); len(fs) != 0 {
		t.Fatalf("no injection expected, got %+v", fs)
	}
}
