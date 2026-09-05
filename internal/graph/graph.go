// Package graph holds the attack surface as nodes (domain, subdomain, ip, port,
// service, endpoint, param, finding) and typed edges between them. It persists to
// JSON so a run is resumable and two snapshots can be diffed for monitoring.
package graph

import (
	"encoding/json"
	"os"
	"sort"
	"sync"
	"time"
)

type Kind string

const (
	Domain    Kind = "domain"
	Subdomain Kind = "subdomain"
	IP        Kind = "ip"
	Port      Kind = "port"
	Service   Kind = "service"
	Endpoint  Kind = "endpoint"
	Param     Kind = "param"
	Finding   Kind = "finding"
)

type Node struct {
	ID        string            `json:"id"`
	Kind      Kind              `json:"kind"`
	Value     string            `json:"value"`
	Attrs     map[string]string `json:"attrs,omitempty"`
	FirstSeen time.Time         `json:"first_seen"`
	LastSeen  time.Time         `json:"last_seen"`
}

type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Rel  string `json:"rel"`
}

type Graph struct {
	mu    sync.Mutex
	Nodes map[string]*Node `json:"nodes"`
	Edges []Edge           `json:"edges"`
}

func New() *Graph {
	return &Graph{Nodes: map[string]*Node{}}
}

func id(k Kind, value string) string { return string(k) + ":" + value }

// Upsert inserts or refreshes a node and merges attrs. Timestamps track first and
// most recent sighting, which the monitoring diff relies on.
func (g *Graph) Upsert(k Kind, value string, attrs map[string]string) *Node {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now().UTC()
	nid := id(k, value)
	n := g.Nodes[nid]
	if n == nil {
		n = &Node{ID: nid, Kind: k, Value: value, Attrs: map[string]string{}, FirstSeen: now}
		g.Nodes[nid] = n
	}
	n.LastSeen = now
	for key, v := range attrs {
		if n.Attrs == nil {
			n.Attrs = map[string]string{}
		}
		n.Attrs[key] = v
	}
	return n
}

func (g *Graph) Link(from, to *Node, rel string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, e := range g.Edges {
		if e.From == from.ID && e.To == to.ID && e.Rel == rel {
			return
		}
	}
	g.Edges = append(g.Edges, Edge{From: from.ID, To: to.ID, Rel: rel})
}

func (g *Graph) Save(path string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	b, err := json.MarshalIndent(struct {
		Nodes map[string]*Node `json:"nodes"`
		Edges []Edge           `json:"edges"`
	}{g.Nodes, g.Edges}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

func Load(path string) (*Graph, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	g := New()
	if err := json.Unmarshal(b, g); err != nil {
		return nil, err
	}
	if g.Nodes == nil {
		g.Nodes = map[string]*Node{}
	}
	return g, nil
}

// Added returns nodes present here but not in old — the "what's new" for monitoring.
func (g *Graph) Added(old *Graph) []*Node {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []*Node
	for nid, n := range g.Nodes {
		if _, ok := old.Nodes[nid]; !ok {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
