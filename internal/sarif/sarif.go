// Package sarif renders findings as SARIF 2.1.0 so a huntx run drops straight into
// GitHub code scanning or any CI that speaks SARIF.
package sarif

import (
	"encoding/json"

	"github.com/talkdedsec/tlk-huntx/internal/finding"
)

func level(s finding.Severity) string {
	switch s {
	case finding.Critical, finding.High:
		return "error"
	case finding.Medium:
		return "warning"
	default:
		return "note"
	}
}

type doc struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool    tool     `json:"tool"`
	Results []result `json:"results"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri"`
	Rules          []rule `json:"rules"`
}

type rule struct {
	ID               string     `json:"id"`
	Name             string     `json:"name,omitempty"`
	ShortDescription textHolder `json:"shortDescription"`
}

type result struct {
	RuleID    string     `json:"ruleId"`
	Level     string     `json:"level"`
	Message   textHolder `json:"message"`
	Locations []location `json:"locations"`
}

type location struct {
	PhysicalLocation physLoc `json:"physicalLocation"`
}

type physLoc struct {
	ArtifactLocation artifact `json:"artifactLocation"`
}

type artifact struct {
	URI string `json:"uri"`
}

type textHolder struct {
	Text string `json:"text"`
}

func Build(version string, findings []finding.Finding) ([]byte, error) {
	rules := []rule{}
	seenRule := map[string]bool{}
	results := make([]result, 0, len(findings))

	for _, f := range findings {
		if f.TemplateID != "" && !seenRule[f.TemplateID] {
			seenRule[f.TemplateID] = true
			rules = append(rules, rule{
				ID:               f.TemplateID,
				Name:             f.Type,
				ShortDescription: textHolder{Text: f.Type},
			})
		}
		msg := f.Type
		if f.Verified {
			msg += " (verified)"
		}
		results = append(results, result{
			RuleID:  f.TemplateID,
			Level:   level(f.Severity),
			Message: textHolder{Text: msg},
			Locations: []location{{
				PhysicalLocation: physLoc{ArtifactLocation: artifact{URI: f.MatchedAt}},
			}},
		})
	}

	d := doc{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []run{{
			Tool: tool{Driver: driver{
				Name:           "huntx",
				Version:        version,
				InformationURI: "https://github.com/talkdedsec/tlk-huntx",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	return json.MarshalIndent(d, "", "  ")
}
