// Package dashboard serves a local read-only view of the attack surface and
// findings straight from the binary — the graph and findings files rendered as a
// single embedded page, no external services, no docker.
package dashboard

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"net/http"
	"os"
	"strings"
)

//go:embed index.html
var indexHTML []byte

func Handler(graphPath, findingsPath string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexHTML)
	})
	mux.HandleFunc("/api/graph", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		b, err := os.ReadFile(graphPath)
		if err != nil {
			_, _ = w.Write([]byte(`{"nodes":{},"edges":[]}`))
			return
		}
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/api/findings", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(findingsJSON(findingsPath))
	})
	return mux
}

// findingsJSON turns the JSONL findings file into a single JSON array the page can
// fetch. A missing file yields an empty array.
func findingsJSON(path string) []byte {
	f, err := os.Open(path)
	if err != nil {
		return []byte("[]")
	}
	defer func() { _ = f.Close() }()
	var items []json.RawMessage
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		items = append(items, json.RawMessage(line))
	}
	b, err := json.Marshal(items)
	if err != nil {
		return []byte("[]")
	}
	return b
}
