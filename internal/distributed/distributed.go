// Package distributed spreads a scan across machines: a coordinator hands out
// targets over HTTP and collects findings, workers pull a target, scan it locally
// (through their own scope gate), and post results back. Each worker enforces scope
// itself, so distribution never widens what may be touched.
package distributed

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/talkdedsec/tlk-huntx/internal/finding"
)

type Coordinator struct {
	mu        sync.Mutex
	queue     []string
	total     int
	completed int
	results   []finding.Finding
}

func NewCoordinator(targets []string) *Coordinator {
	return &Coordinator{queue: append([]string(nil), targets...), total: len(targets)}
}

func (c *Coordinator) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/next", c.next)
	mux.HandleFunc("/findings", c.findings)
	mux.HandleFunc("/status", c.status)
	return mux
}

func (c *Coordinator) next(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.queue) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	target := c.queue[0]
	c.queue = c.queue[1:]
	_ = json.NewEncoder(w).Encode(map[string]string{"target": target})
}

func (c *Coordinator) findings(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Findings []finding.Finding `json:"findings"`
	}
	b, _ := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	_ = json.Unmarshal(b, &payload)
	c.mu.Lock()
	c.results = append(c.results, payload.Findings...)
	c.completed++
	c.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (c *Coordinator) status(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]int{
		"queued": len(c.queue), "completed": c.completed, "total": c.total, "findings": len(c.results),
	})
}

func (c *Coordinator) Complete() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.completed >= c.total
}

func (c *Coordinator) Results() []finding.Finding {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]finding.Finding(nil), c.results...)
}

// Work pulls targets from the coordinator until the queue is drained, scanning each
// with the supplied function and posting the findings back.
func Work(ctx context.Context, coordinator string, scan func(string) []finding.Finding) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		target, ok, err := next(ctx, client, coordinator)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		post(ctx, client, coordinator, scan(target))
	}
}

func next(ctx context.Context, client *http.Client, base string) (string, bool, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", base+"/next", nil)
	resp, err := client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNoContent {
		return "", false, nil
	}
	var payload struct {
		Target string `json:"target"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return "", false, err
	}
	return payload.Target, payload.Target != "", nil
}

func post(ctx context.Context, client *http.Client, base string, fs []finding.Finding) {
	body, _ := json.Marshal(map[string]any{"findings": fs})
	req, _ := http.NewRequestWithContext(ctx, "POST", base+"/findings", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if resp, err := client.Do(req); err == nil {
		_ = resp.Body.Close()
	}
}
