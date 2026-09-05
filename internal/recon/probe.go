package recon

import (
	"context"
	"regexp"
	"strings"
	"sync"

	"github.com/talkdedsec/tlk-huntx/internal/fetch"
)

type Result struct {
	Host   string `json:"host"`
	Live   bool   `json:"live"`
	Status int    `json:"status,omitempty"`
	URL    string `json:"url,omitempty"`
	Title  string `json:"title,omitempty"`
	Server string `json:"server,omitempty"`
	Tech   string `json:"tech,omitempty"`
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// Probe checks each host over https then http through the gated client and
// records liveness, title, server, and a rough tech guess. Concurrency is bounded
// here and further throttled by the rate limiter inside the client.
func Probe(ctx context.Context, c *fetch.Client, hosts []string, workers int) []Result {
	if workers <= 0 {
		workers = 20
	}
	in := make(chan string)
	out := make(chan Result)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range in {
				out <- probeOne(ctx, c, h)
			}
		}()
	}
	go func() {
		for _, h := range hosts {
			select {
			case in <- h:
			case <-ctx.Done():
				close(in)
				return
			}
		}
		close(in)
	}()
	go func() { wg.Wait(); close(out) }()

	results := make([]Result, 0, len(hosts))
	for r := range out {
		results = append(results, r)
	}
	return results
}

func probeOne(ctx context.Context, c *fetch.Client, host string) Result {
	for _, scheme := range []string{"https://", "http://"} {
		resp, err := c.Do(ctx, "GET", scheme+host, nil)
		if err != nil {
			continue
		}
		if resp.DryRun {
			return Result{Host: host, URL: scheme + host}
		}
		return Result{
			Host:   host,
			Live:   true,
			Status: resp.Status,
			URL:    resp.URL,
			Title:  extractTitle(resp.Body),
			Server: resp.Header.Get("Server"),
			Tech:   fingerprint(resp.Header.Get("Server"), resp.Header.Get("X-Powered-By"), resp.Body),
		}
	}
	return Result{Host: host}
}

func extractTitle(body []byte) string {
	m := titleRe.FindSubmatch(body)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(html(string(m[1])))
}

func html(s string) string {
	r := strings.NewReplacer("&amp;", "&", "&lt;", "<", "&gt;", ">", "&quot;", `"`, "&#39;", "'")
	return r.Replace(s)
}

func fingerprint(server, poweredBy string, body []byte) string {
	var tags []string
	add := func(t string) {
		for _, x := range tags {
			if x == t {
				return
			}
		}
		tags = append(tags, t)
	}
	s := strings.ToLower(server + " " + poweredBy)
	for probe, tag := range map[string]string{
		"cloudflare": "Cloudflare", "nginx": "nginx", "apache": "Apache",
		"php": "PHP", "express": "Express", "iis": "IIS",
	} {
		if strings.Contains(s, probe) {
			add(tag)
		}
	}
	b := strings.ToLower(string(body))
	for probe, tag := range map[string]string{
		"wp-content": "WordPress", "/_next/": "Next.js", "csrfmiddlewaretoken": "Django",
	} {
		if strings.Contains(b, probe) {
			add(tag)
		}
	}
	return strings.Join(tags, ", ")
}
