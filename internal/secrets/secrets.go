// Package secrets flags high-confidence credentials leaked in a response or JS
// bundle. Patterns are deliberately narrow to keep false positives low; the value
// is masked in the evidence so the finding itself does not carry the live secret.
package secrets

import (
	"regexp"

	"github.com/talkdedsec/tlk-huntx/internal/finding"
)

type rule struct {
	name     string
	severity finding.Severity
	re       *regexp.Regexp
}

var rules = []rule{
	{"aws-access-key", finding.High, regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"google-api-key", finding.High, regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`)},
	{"github-token", finding.High, regexp.MustCompile(`gh[pousr]_[0-9A-Za-z]{36}`)},
	{"slack-token", finding.High, regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,48}`)},
	{"slack-webhook", finding.Medium, regexp.MustCompile(`https://hooks\.slack\.com/services/T[0-9A-Za-z_/]{20,}`)},
	{"stripe-secret-key", finding.Critical, regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`)},
	{"private-key", finding.High, regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`)},
}

func Scan(sourceURL, body string) []finding.Finding {
	seen := map[string]bool{}
	var out []finding.Finding
	for _, r := range rules {
		for _, hit := range r.re.FindAllString(body, -1) {
			if seen[hit] {
				continue
			}
			seen[hit] = true
			f := finding.Finding{
				Target:     sourceURL,
				Type:       "Leaked secret: " + r.name,
				TemplateID: "secret-" + r.name,
				Severity:   r.severity,
				Confidence: 90,
				MatchedAt:  sourceURL,
				CWE:        "CWE-200",
				Extracted:  map[string]string{"match": mask(hit)},
				Evidence:   finding.Evidence{Response: mask(hit)},
			}
			f.Finalize([]string{r.name})
			out = append(out, f)
		}
	}
	return out
}

func mask(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-2:]
}
