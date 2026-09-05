package graph

import (
	"path/filepath"
	"testing"
)

func TestUpsertDedup(t *testing.T) {
	g := New()
	a := g.Upsert(Subdomain, "api.acme.com", map[string]string{"status": "200"})
	b := g.Upsert(Subdomain, "api.acme.com", map[string]string{"server": "nginx"})
	if a != b {
		t.Fatal("upsert should return the same node for the same value")
	}
	if len(g.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(g.Nodes))
	}
	if b.Attrs["status"] != "200" || b.Attrs["server"] != "nginx" {
		t.Fatalf("attrs not merged: %v", b.Attrs)
	}
}

func TestLinkDedup(t *testing.T) {
	g := New()
	d := g.Upsert(Domain, "acme.com", nil)
	s := g.Upsert(Subdomain, "api.acme.com", nil)
	g.Link(d, s, "has_subdomain")
	g.Link(d, s, "has_subdomain")
	if len(g.Edges) != 1 {
		t.Fatalf("duplicate edge not collapsed: %d", len(g.Edges))
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	g := New()
	d := g.Upsert(Domain, "acme.com", nil)
	s := g.Upsert(Subdomain, "api.acme.com", map[string]string{"status": "200"})
	g.Link(d, s, "has_subdomain")

	path := filepath.Join(t.TempDir(), "g.json")
	if err := g.Save(path); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Nodes) != 2 || len(loaded.Edges) != 1 {
		t.Fatalf("round trip lost data: %d nodes %d edges", len(loaded.Nodes), len(loaded.Edges))
	}
	if loaded.Nodes[id(Subdomain, "api.acme.com")].Attrs["status"] != "200" {
		t.Fatal("attrs lost on round trip")
	}
}

func TestAdded(t *testing.T) {
	old := New()
	old.Upsert(Subdomain, "api.acme.com", nil)
	cur := New()
	cur.Upsert(Subdomain, "api.acme.com", nil)
	cur.Upsert(Subdomain, "new.acme.com", nil)
	added := cur.Added(old)
	if len(added) != 1 || added[0].Value != "new.acme.com" {
		t.Fatalf("expected only new.acme.com, got %v", added)
	}
}
