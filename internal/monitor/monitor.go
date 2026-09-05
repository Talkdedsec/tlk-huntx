// Package monitor turns huntx into a watchdog: it diffs one run against the last
// so a scheduled sweep surfaces only what changed — a new subdomain, a newly live
// host, a finding that was not there before — instead of re-reporting the world.
package monitor

import (
	"github.com/talkdedsec/tlk-huntx/internal/finding"
	"github.com/talkdedsec/tlk-huntx/internal/graph"
)

// NewHosts returns subdomain nodes present in cur but not in old.
func NewHosts(old, cur *graph.Graph) []*graph.Node {
	var out []*graph.Node
	for _, n := range cur.Added(old) {
		if n.Kind == graph.Subdomain {
			out = append(out, n)
		}
	}
	return out
}

// NewFindings returns findings in cur whose dedup key was not in prev.
func NewFindings(prev, cur []finding.Finding) []finding.Finding {
	known := map[string]bool{}
	for _, f := range prev {
		known[f.DedupKey] = true
	}
	var out []finding.Finding
	for _, f := range cur {
		if !known[f.DedupKey] {
			out = append(out, f)
		}
	}
	return out
}

// Merge unions prev and cur by dedup key, keeping the earlier occurrence.
func Merge(prev, cur []finding.Finding) []finding.Finding {
	seen := map[string]bool{}
	out := make([]finding.Finding, 0, len(prev)+len(cur))
	for _, f := range append(append([]finding.Finding(nil), prev...), cur...) {
		if seen[f.DedupKey] {
			continue
		}
		seen[f.DedupKey] = true
		out = append(out, f)
	}
	return out
}
