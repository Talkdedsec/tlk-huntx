// Package fuzz is lightweight content discovery: it requests a wordlist of common
// paths through the gated client and reports the ones that exist, using a soft-404
// baseline so a catch-all page does not drown the results in false hits.
package fuzz

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"os"
	"strings"
	"sync"

	"github.com/talkdedsec/tlk-huntx/internal/fetch"
)

//go:embed common.txt
var defaultWords string

func Words(path string) ([]string, error) {
	raw := defaultWords
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		raw = string(b)
	}
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		if w := strings.TrimSpace(line); w != "" && !strings.HasPrefix(w, "#") {
			out = append(out, strings.TrimPrefix(w, "/"))
		}
	}
	return out, nil
}

type Hit struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Length int    `json:"length"`
}

type baseline struct {
	status int
	length int
}

// Run probes base+/word for each word and returns the paths that look real.
func Run(ctx context.Context, c *fetch.Client, base string, words []string, workers int) []Hit {
	base = strings.TrimRight(base, "/")
	bl := probeBaseline(ctx, c, base)
	if workers <= 0 {
		workers = 20
	}

	in := make(chan string)
	out := make(chan Hit)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for w := range in {
				if h, ok := probeOne(ctx, c, base, w, bl); ok {
					out <- h
				}
			}
		}()
	}
	go func() {
		for _, w := range words {
			select {
			case in <- w:
			case <-ctx.Done():
				close(in)
				return
			}
		}
		close(in)
	}()
	go func() { wg.Wait(); close(out) }()

	var hits []Hit
	for h := range out {
		hits = append(hits, h)
	}
	return hits
}

func probeBaseline(ctx context.Context, c *fetch.Client, base string) baseline {
	b := make([]byte, 8)
	rand.Read(b)
	resp, err := c.Do(ctx, "GET", base+"/huntx404-"+hex.EncodeToString(b), nil)
	if err != nil || resp == nil || resp.DryRun {
		return baseline{status: 404}
	}
	return baseline{status: resp.Status, length: len(resp.Body)}
}

func probeOne(ctx context.Context, c *fetch.Client, base, word string, bl baseline) (Hit, bool) {
	resp, err := c.Do(ctx, "GET", base+"/"+word, nil)
	if err != nil || resp == nil || resp.DryRun {
		return Hit{}, false
	}
	if resp.Status == 404 {
		return Hit{}, false
	}
	// same status and near-identical size as the soft-404 baseline -> catch-all noise
	if resp.Status == bl.status && abs(len(resp.Body)-bl.length) < 32 {
		return Hit{}, false
	}
	return Hit{URL: base + "/" + word, Status: resp.Status, Length: len(resp.Body)}, true
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
