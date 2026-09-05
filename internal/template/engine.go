package template

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/talkdedsec/tlk-huntx/internal/fetch"
	"github.com/talkdedsec/tlk-huntx/internal/finding"
)

// Run executes the template against baseURL and returns a finding per matched
// request block. baseURL is like "https://api.acme.com" (no trailing slash needed).
func (t *Template) Run(ctx context.Context, c *fetch.Client, baseURL string) []finding.Finding {
	base := strings.TrimRight(baseURL, "/")
	var out []finding.Finding
	for _, req := range t.blocks() {
		paths := req.Path
		if len(paths) == 0 {
			paths = []string{"{{BaseURL}}"}
		}
		method := req.Method
		if method == "" {
			method = "GET"
		}
		for _, p := range paths {
			target := expand(p, base)
			resp, err := c.DoReq(ctx, method, target, req.Headers, bodyReader(req.Body))
			if err != nil || resp == nil || resp.DryRun {
				continue
			}
			r := response{status: resp.Status, header: headerDump(resp.Header), body: string(resp.Body)}
			if matchBlock(req, r) {
				f := finding.Finding{
					Target:     base,
					Type:       t.Info.Name,
					TemplateID: t.ID,
					Severity:   finding.Severity(strings.ToLower(t.Info.Severity)),
					Confidence: 70,
					MatchedAt:  target,
					Extracted:  extractBlock(req, r),
					Evidence: finding.Evidence{
						Request:  method + " " + target,
						Response: snippet(r, 512),
					},
					Repro: fmt.Sprintf("curl -s -i -X %s %q", method, target),
				}
				f.Finalize(nil)
				out = append(out, f)
				if req.StopAtFirstMatch {
					break
				}
			}
		}
	}
	return out
}

type response struct {
	status int
	header string
	body   string
}

func partText(r response, part string) string {
	switch strings.ToLower(part) {
	case "header", "headers":
		return r.header
	case "all", "response", "raw":
		return r.header + "\n\n" + r.body
	default: // "body" and anything unset
		return r.body
	}
}

func matchBlock(req Request, r response) bool {
	if len(req.Matchers) == 0 {
		return false
	}
	and := strings.EqualFold(req.MatchersCondition, "and") || req.MatchersCondition == ""
	for _, m := range req.Matchers {
		ok := matchOne(m, r)
		if and && !ok {
			return false
		}
		if !and && ok {
			return true
		}
	}
	return and
}

func matchOne(m Matcher, r response) bool {
	var ok bool
	switch strings.ToLower(m.Type) {
	case "status":
		ok = containsInt(m.Status, r.status)
	case "word", "":
		ok = matchWords(m, partText(r, m.Part))
	case "regex":
		ok = matchRegex(m.Regex, partText(r, m.Part))
	case "size":
		ok = containsInt(m.Status, len(r.body)) // nuclei uses "size"; reuse ints if given
	default:
		ok = false
	}
	if m.Negative {
		return !ok
	}
	return ok
}

func matchWords(m Matcher, text string) bool {
	if len(m.Words) == 0 {
		return false
	}
	if m.CaseInsensitive {
		text = strings.ToLower(text)
	}
	all := strings.EqualFold(m.Condition, "and") // nuclei default within a matcher is "or"
	for _, w := range m.Words {
		if m.CaseInsensitive {
			w = strings.ToLower(w)
		}
		hit := strings.Contains(text, w)
		if all && !hit {
			return false
		}
		if !all && hit {
			return true
		}
	}
	return all
}

func matchRegex(patterns []string, text string) bool {
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			continue
		}
		if re.MatchString(text) {
			return true
		}
	}
	return false
}

func extractBlock(req Request, r response) map[string]string {
	out := map[string]string{}
	for i, e := range req.Extractors {
		for _, p := range e.Regex {
			re, err := regexp.Compile(p)
			if err != nil {
				continue
			}
			if m := re.FindStringSubmatch(partText(r, e.Part)); m != nil {
				val := m[0]
				if e.Group > 0 && e.Group < len(m) {
					val = m[e.Group]
				}
				name := e.Name
				if name == "" {
					name = fmt.Sprintf("extract%d", i+1)
				}
				out[name] = val
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func expand(p, base string) string {
	host := base
	if i := strings.Index(base, "://"); i >= 0 {
		host = base[i+3:]
	}
	s := strings.NewReplacer("{{BaseURL}}", base, "{{RootURL}}", base, "{{Hostname}}", host).Replace(p)
	if !strings.Contains(s, "://") {
		if !strings.HasPrefix(s, "/") {
			s = "/" + s
		}
		s = base + s
	}
	return s
}

func bodyReader(b string) io.Reader {
	if b == "" {
		return nil
	}
	return strings.NewReader(b)
}

func headerDump(h http.Header) string {
	var sb strings.Builder
	for k, vs := range h {
		for _, v := range vs {
			sb.WriteString(k + ": " + v + "\n")
		}
	}
	return sb.String()
}

func snippet(r response, n int) string {
	s := r.header
	if r.body != "" {
		s += "\n\n" + r.body
	}
	if len(s) > n {
		s = s[:n]
	}
	return s
}
