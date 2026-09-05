// Package agent turns a pile of findings into a ranked playbook. It scores each
// finding by expected value (severity weight × confidence) and composes known
// multi-finding attack chains — e.g. a reflected CORS origin plus an exposed API is
// credential theft, not two unrelated notes. It plans; it does not attack. The LLM
// skill or a human executes the plan.
package agent

import (
	"sort"
	"strings"

	"github.com/talkdedsec/tlk-huntx/internal/finding"
)

type Action struct {
	Title     string   `json:"title"`
	EV        float64  `json:"ev"`
	Severity  string   `json:"severity"`
	Rationale string   `json:"rationale"`
	Findings  []string `json:"findings"`
	Chain     bool     `json:"chain"`
}

func weight(s finding.Severity) float64 {
	switch s {
	case finding.Critical:
		return 1.0
	case finding.High:
		return 0.8
	case finding.Medium:
		return 0.5
	case finding.Low:
		return 0.2
	default:
		return 0.05
	}
}

func ev(f finding.Finding) float64 {
	c := float64(f.Confidence)
	if c <= 0 {
		c = 50
	}
	return weight(f.Severity) * c / 100
}

var chains = []struct {
	title     string
	rationale string
	requires  []string // template-id prefixes that must all be present
}{
	{
		"Credential theft via CORS + exposed API",
		"Reflected Origin lets an attacker page read authenticated responses; an exposed API/GraphQL tells them exactly what to read.",
		[]string{"cors-reflected-origin", "openapi-exposed"},
	},
	{
		"Credential theft via CORS + GraphQL introspection",
		"CORS reflection plus a fully introspectable GraphQL schema is a map and a key for cross-origin data exfiltration.",
		[]string{"cors-reflected-origin", "graphql-introspection"},
	},
	{
		"Mass object access via BOLA on a documented API",
		"BOLA proven on one object plus the OpenAPI spec means every documented object id is likely enumerable.",
		[]string{"bola-differential", "openapi-exposed"},
	},
	{
		"Source disclosure to RCE path",
		"An exposed .git lets an attacker recover source; a reachable command-exec sink in that source is the exploitation path.",
		[]string{"exposed-git-config", "greybox-command-exec"},
	},
	{
		"Reflected XSS on a DOM sink",
		"A parameter reflects unencoded HTML and the source has a reachable DOM-XSS sink — the two together point at an exploitable XSS.",
		[]string{"reflected-input", "greybox-dom-xss"},
	},
	{
		"Mass data exfiltration via injectable documented API",
		"SQL injection on one parameter plus an exposed OpenAPI spec means every documented query parameter is a candidate for the same flaw.",
		[]string{"sqli-error", "openapi-exposed"},
	},
}

// Plan ranks single findings by expected value and prepends any composed chain
// whose members are all present. Highest EV first.
func Plan(findings []finding.Finding) []Action {
	present := map[string][]string{} // template-id prefix -> finding ids
	byID := map[string]finding.Finding{}
	for _, f := range findings {
		byID[f.ID] = f
		present[f.TemplateID] = append(present[f.TemplateID], f.ID)
	}

	var actions []Action
	for _, c := range chains {
		ids, ok := chainMembers(c.requires, present)
		if !ok {
			continue
		}
		best := 0.0
		for _, id := range ids {
			if e := ev(byID[id]); e > best {
				best = e
			}
		}
		actions = append(actions, Action{
			Title:     c.title,
			EV:        best + 0.15,
			Severity:  string(finding.High),
			Rationale: c.rationale,
			Findings:  ids,
			Chain:     true,
		})
	}

	for _, f := range findings {
		title := f.Type
		if title == "" {
			title = f.TemplateID
		}
		actions = append(actions, Action{
			Title:     title,
			EV:        ev(f),
			Severity:  string(f.Severity),
			Rationale: verifiedNote(f) + f.MatchedAt,
			Findings:  []string{f.ID},
		})
	}

	sort.SliceStable(actions, func(i, j int) bool { return actions[i].EV > actions[j].EV })
	return actions
}

func chainMembers(prefixes []string, present map[string][]string) ([]string, bool) {
	var ids []string
	for _, want := range prefixes {
		matched := false
		for tid, fids := range present {
			if strings.HasPrefix(tid, want) {
				ids = append(ids, fids...)
				matched = true
			}
		}
		if !matched {
			return nil, false
		}
	}
	return ids, true
}

func verifiedNote(f finding.Finding) string {
	if f.Verified {
		return "verified · "
	}
	return "unverified · "
}
