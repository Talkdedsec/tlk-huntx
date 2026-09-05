// Package engine is the shared orchestration behind both the CLI and the MCP
// server: passive discovery + gated probing for recon, and template + secret
// detection with optional deterministic verification for scan. Neither transport
// duplicates this logic.
package engine

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/talkdedsec/tlk-huntx/internal/blastradius"
	"github.com/talkdedsec/tlk-huntx/internal/feedback"
	"github.com/talkdedsec/tlk-huntx/internal/fetch"
	"github.com/talkdedsec/tlk-huntx/internal/finding"
	"github.com/talkdedsec/tlk-huntx/internal/graph"
	"github.com/talkdedsec/tlk-huntx/internal/ratelimit"
	"github.com/talkdedsec/tlk-huntx/internal/recon"
	"github.com/talkdedsec/tlk-huntx/internal/scope"
	"github.com/talkdedsec/tlk-huntx/internal/secrets"
	"github.com/talkdedsec/tlk-huntx/internal/template"
	"github.com/talkdedsec/tlk-huntx/internal/verify"
)

type Options struct {
	Scope              *scope.Scope
	RPS                float64
	Burst              int
	Concurrency        int
	MaxRequests        int
	AllowStateChanging bool
	DryRun             bool
	Verify             bool
	TemplatesDir       string
	Feedback           *feedback.Store
	Log                func(string)
}

func (o Options) client() *fetch.Client {
	return fetch.New(o.Scope, ratelimit.New(o.RPS, o.Burst, o.Concurrency), blastradius.New(o.MaxRequests, o.AllowStateChanging), o.DryRun)
}

// Client builds the gated HTTP client for callers that run their own probes
// (e.g. API discovery) but still want the scope, rate-limit, and blast-radius gate.
func (o Options) Client() *fetch.Client { return o.client() }

func (o Options) log(msg string) {
	if o.Log != nil {
		o.Log(msg)
	}
}

func Recon(ctx context.Context, seeds []string, o Options) ([]recon.Result, *graph.Graph) {
	client := o.client()
	osint := &http.Client{Timeout: 25 * time.Second}

	found := map[string]struct{}{}
	for _, d := range seeds {
		subs, err := recon.PassiveSubdomains(ctx, d, osint)
		if err != nil {
			o.log("passive " + d + ": " + err.Error())
		}
		for _, h := range subs {
			found[h] = struct{}{}
		}
		found[d] = struct{}{}
	}

	var inScope []string
	for h := range found {
		if o.Scope.Check(h).Allowed {
			inScope = append(inScope, h)
		}
	}
	sort.Strings(inScope)

	results := recon.Probe(ctx, client, inScope, o.Concurrency)

	gr := graph.New()
	for _, r := range results {
		attrs := map[string]string{}
		if r.Live {
			attrs["status"] = strconv.Itoa(r.Status)
		}
		if r.Server != "" {
			attrs["server"] = r.Server
		}
		if r.Tech != "" {
			attrs["tech"] = r.Tech
		}
		if r.Title != "" {
			attrs["title"] = r.Title
		}
		if r.URL != "" {
			attrs["url"] = r.URL
		}
		n := gr.Upsert(graph.Subdomain, r.Host, attrs)
		for _, d := range seeds {
			if r.Host == d || strings.HasSuffix(r.Host, "."+d) {
				gr.Link(gr.Upsert(graph.Domain, d, nil), n, "has_subdomain")
			}
		}
	}
	return results, gr
}

type Target struct {
	Base  string
	Techs []string
}

func Scan(ctx context.Context, targets []Target, o Options) []finding.Finding {
	tpls, _ := template.Builtin()
	if o.TemplatesDir != "" {
		if extra, err := template.LoadDir(o.TemplatesDir); err == nil {
			tpls = append(tpls, extra...)
		} else {
			o.log("templates: " + err.Error())
		}
	}
	client := o.client()

	var mu sync.Mutex
	var out []finding.Finding
	seen := map[string]bool{}
	add := func(fs []finding.Finding) {
		mu.Lock()
		defer mu.Unlock()
		for _, f := range fs {
			if seen[f.DedupKey] {
				continue
			}
			seen[f.DedupKey] = true
			out = append(out, f)
		}
	}

	// Scan targets concurrently; the rate limiter still bounds real request rate
	// and per-host politeness, this just overlaps the waiting across hosts.
	workers := o.Concurrency
	if workers <= 0 {
		workers = 10
	}
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, t := range targets {
		if ctx.Err() != nil {
			break
		}
		if !o.Scope.Check(t.Base).Allowed {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(t Target) {
			defer wg.Done()
			defer func() { <-sem }()
			for _, tpl := range template.SelectByTech(tpls, t.Techs) {
				add(tpl.Run(ctx, client, t.Base))
			}
			if resp, err := client.Do(ctx, "GET", t.Base, nil); err == nil && resp != nil && !resp.DryRun {
				add(secrets.Scan(t.Base, string(resp.Body)))
			}
		}(t)
	}
	wg.Wait()

	if o.Verify {
		for i := range out {
			if verify.Reconfirm(ctx, client, tpls, out[i]) {
				out[i].Verified = true
				out[i].Confidence = 95
			}
		}
	}
	if o.Feedback != nil {
		for i := range out {
			out[i] = o.Feedback.Adjust(out[i])
		}
	}
	return out
}
