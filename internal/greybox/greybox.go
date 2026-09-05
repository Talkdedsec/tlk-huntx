// Package greybox correlates source with runtime. It scans a local source tree for
// dangerous sinks (command exec, eval, SQL string-building, deserialization, DOM
// XSS) and the route literals near them, then links a sink to a live endpoint that
// reaches it — turning "there is a scary line of code" into "it is reachable here".
package greybox

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/talkdedsec/tlk-huntx/internal/finding"
)

type Sink struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Rule    string `json:"rule"`
	Snippet string `json:"snippet"`
}

type FileReport struct {
	Path   string
	Sinks  []Sink
	Routes []string
}

var sinkRules = []struct {
	name string
	re   *regexp.Regexp
}{
	{"command-exec", regexp.MustCompile(`exec\.Command|child_process|subprocess\.(call|Popen|run)|os\.system|Runtime\.getRuntime\(\)\.exec`)},
	{"code-eval", regexp.MustCompile(`\beval\(|\bnew Function\(`)},
	{"sql-concat", regexp.MustCompile(`(?i)(select|insert|update|delete)\b[^"'` + "`" + `]*["'` + "`" + `]\s*\+|(?i)(query|execute)\([^)]*\+`)},
	{"deserialization", regexp.MustCompile(`pickle\.loads|yaml\.load\s*\(|unserialize\(|readObject\(`)},
	{"dom-xss", regexp.MustCompile(`innerHTML\s*=|document\.write\(|dangerouslySetInnerHTML`)},
	{"ssti", regexp.MustCompile(`render_template_string|Template\([^)]*\+`)},
}

var routeRe = regexp.MustCompile(`["'` + "`" + `](/[A-Za-z0-9_/{}:.\-]*)["'` + "`" + `]`)

var skipDir = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, "dist": true, "build": true,
}

var scanExt = map[string]bool{
	".go": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true, ".py": true,
	".rb": true, ".php": true, ".java": true, ".cs": true, ".vue": true,
}

func ScanTree(root string) ([]FileReport, error) {
	var out []FileReport
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !scanExt[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		rep, ok := scanFile(path)
		if ok {
			out = append(out, rep)
		}
		return nil
	})
	return out, err
}

func scanFile(path string) (FileReport, bool) {
	f, err := os.Open(path)
	if err != nil {
		return FileReport{}, false
	}
	defer func() { _ = f.Close() }()

	rep := FileReport{Path: path}
	routes := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 4<<20)
	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		for _, r := range sinkRules {
			if r.re.MatchString(text) {
				rep.Sinks = append(rep.Sinks, Sink{File: path, Line: line, Rule: r.name, Snippet: trim(text)})
			}
		}
		for _, m := range routeRe.FindAllStringSubmatch(text, -1) {
			if len(m[1]) > 1 {
				routes[m[1]] = true
			}
		}
	}
	for r := range routes {
		rep.Routes = append(rep.Routes, r)
	}
	return rep, len(rep.Sinks) > 0
}

// Correlate links a file's sinks to a live endpoint when the file references that
// endpoint's path — the grey-box signal that the sink is actually reachable.
func Correlate(reports []FileReport, endpointPaths []string) []finding.Finding {
	var out []finding.Finding
	for _, rep := range reports {
		for _, route := range rep.Routes {
			ep, ok := matchEndpoint(route, endpointPaths)
			if !ok {
				continue
			}
			for _, s := range rep.Sinks {
				f := finding.Finding{
					Target:     ep,
					Type:       "Reachable dangerous sink (" + s.Rule + ")",
					TemplateID: "greybox-" + s.Rule,
					Severity:   finding.Medium,
					Confidence: 60,
					MatchedAt:  ep,
					CWE:        cweFor(s.Rule),
					Extracted:  map[string]string{"source": s.File, "route": route},
					Evidence:   finding.Evidence{Request: s.File + ":" + strconv.Itoa(s.Line), Response: s.Snippet},
				}
				f.Finalize([]string{s.Rule, s.File})
				out = append(out, f)
			}
		}
	}
	return out
}

func matchEndpoint(route string, endpoints []string) (string, bool) {
	for _, ep := range endpoints {
		if ep == route || strings.HasSuffix(ep, route) || strings.Contains(ep, route) {
			return ep, true
		}
	}
	return "", false
}

func cweFor(rule string) string {
	switch rule {
	case "command-exec":
		return "CWE-78"
	case "code-eval", "ssti":
		return "CWE-94"
	case "sql-concat":
		return "CWE-89"
	case "deserialization":
		return "CWE-502"
	case "dom-xss":
		return "CWE-79"
	}
	return ""
}

func trim(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}
