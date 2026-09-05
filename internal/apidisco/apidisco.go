// Package apidisco finds API attack surface: GraphQL endpoints that answer
// introspection, and exposed OpenAPI/Swagger specs whose declared paths become new
// endpoints to test. Probes are GET-only, so they stay inside the default
// blast-radius (no state-changing methods).
package apidisco

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"github.com/talkdedsec/tlk-huntx/internal/fetch"
	"github.com/talkdedsec/tlk-huntx/internal/finding"
)

var graphqlPaths = []string{"/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql"}
var openapiPaths = []string{"/openapi.json", "/swagger.json", "/v3/api-docs", "/api-docs", "/swagger/v1/swagger.json"}

const introspection = "{__schema{queryType{name}}}"

type Endpoint struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

func Discover(ctx context.Context, c *fetch.Client, base string) ([]finding.Finding, []Endpoint) {
	base = strings.TrimRight(base, "/")
	fs, eps := GraphQL(ctx, c, base)
	f2, e2 := OpenAPI(ctx, c, base)
	return append(fs, f2...), append(eps, e2...)
}

func GraphQL(ctx context.Context, c *fetch.Client, base string) ([]finding.Finding, []Endpoint) {
	var out []finding.Finding
	var eps []Endpoint
	for _, p := range graphqlPaths {
		u := base + p + "?query=" + url.QueryEscape(introspection)
		resp, err := c.Do(ctx, "GET", u, nil)
		if err != nil || resp == nil || resp.DryRun || resp.Status != 200 {
			continue
		}
		body := string(resp.Body)
		if strings.Contains(body, "__schema") || strings.Contains(body, "queryType") {
			f := finding.Finding{
				Target:     base,
				Type:       "GraphQL introspection enabled",
				TemplateID: "graphql-introspection",
				Severity:   finding.Medium,
				Confidence: 85,
				MatchedAt:  base + p,
				CWE:        "CWE-200",
				Evidence:   finding.Evidence{Request: "GET " + u, Response: trunc(body, 300)},
				Repro:      "curl -s " + u,
			}
			f.Finalize(nil)
			out = append(out, f)
			eps = append(eps, Endpoint{Method: "POST", Path: p})
		}
	}
	return out, eps
}

func OpenAPI(ctx context.Context, c *fetch.Client, base string) ([]finding.Finding, []Endpoint) {
	var out []finding.Finding
	var eps []Endpoint
	for _, p := range openapiPaths {
		u := base + p
		resp, err := c.Do(ctx, "GET", u, nil)
		if err != nil || resp == nil || resp.DryRun || resp.Status != 200 {
			continue
		}
		spec, ok := parseSpec(resp.Body)
		if !ok {
			continue
		}
		specEps := endpointsOf(spec)
		f := finding.Finding{
			Target:     base,
			Type:       "Exposed API specification",
			TemplateID: "openapi-exposed",
			Severity:   finding.Info,
			Confidence: 90,
			MatchedAt:  u,
			CWE:        "CWE-200",
			Extracted:  map[string]string{"endpoints": strconv.Itoa(len(specEps))},
			Evidence:   finding.Evidence{Request: "GET " + u},
			Repro:      "curl -s " + u,
		}
		f.Finalize(nil)
		out = append(out, f)
		eps = append(eps, specEps...)
		break // one spec is enough
	}
	return out, eps
}

type openapiSpec struct {
	OpenAPI string                                `json:"openapi"`
	Swagger string                                `json:"swagger"`
	Paths   map[string]map[string]json.RawMessage `json:"paths"`
}

func parseSpec(body []byte) (openapiSpec, bool) {
	var s openapiSpec
	if err := json.Unmarshal(body, &s); err != nil {
		return s, false
	}
	if s.OpenAPI == "" && s.Swagger == "" {
		return s, false
	}
	return s, true
}

func endpointsOf(s openapiSpec) []Endpoint {
	var eps []Endpoint
	for path, methods := range s.Paths {
		for m := range methods {
			eps = append(eps, Endpoint{Method: strings.ToUpper(m), Path: path})
		}
	}
	return eps
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
