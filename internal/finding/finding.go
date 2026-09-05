package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"time"
)

type Severity string

const (
	Info     Severity = "info"
	Low      Severity = "low"
	Medium   Severity = "medium"
	High     Severity = "high"
	Critical Severity = "critical"
)

// Rank orders severities for filtering and sorting; higher is more severe.
func (s Severity) Rank() int {
	switch s {
	case Critical:
		return 4
	case High:
		return 3
	case Medium:
		return 2
	case Low:
		return 1
	default:
		return 0
	}
}

type Evidence struct {
	Request  string `json:"request,omitempty"`
	Response string `json:"response,omitempty"`
	OOBProof string `json:"oob_proof,omitempty"`
}

// Finding is the canonical unit that flows engine -> verify -> LLM triage -> report.
// The same struct serializes to JSONL, to SARIF, and to the triage prompt.
type Finding struct {
	ID         string            `json:"id"`
	Program    string            `json:"program,omitempty"`
	Target     string            `json:"target"`
	Type       string            `json:"type"`
	TemplateID string            `json:"template_id,omitempty"`
	Severity   Severity          `json:"severity"`
	Confidence int               `json:"confidence"`
	MatchedAt  string            `json:"matched_at"`
	CVSS       string            `json:"cvss,omitempty"`
	CWE        string            `json:"cwe,omitempty"`
	Extracted  map[string]string `json:"extracted,omitempty"`
	Evidence   Evidence          `json:"evidence,omitempty"`
	Repro      string            `json:"repro,omitempty"`
	Verified   bool              `json:"verified"`
	DedupKey   string            `json:"dedup_key"`
	Tags       []string          `json:"tags,omitempty"`
	Timestamp  time.Time         `json:"ts"`
}

// Fingerprint groups occurrences of the same root cause: template + host + the
// set of parameters involved. Two findings that share it are duplicates.
func Fingerprint(templateID, matchedAt string, params []string) string {
	host := matchedAt
	if u, err := url.Parse(matchedAt); err == nil && u.Host != "" {
		host = u.Host
	}
	p := append([]string(nil), params...)
	sort.Strings(p)
	sum := sha256.Sum256([]byte(templateID + "|" + strings.ToLower(host) + "|" + strings.Join(p, ",")))
	return hex.EncodeToString(sum[:8])
}

func (f *Finding) Finalize(params []string) {
	if f.Timestamp.IsZero() {
		f.Timestamp = time.Now().UTC()
	}
	if f.DedupKey == "" {
		f.DedupKey = Fingerprint(f.TemplateID, f.MatchedAt, params)
	}
	if f.ID == "" {
		sum := sha256.Sum256([]byte(f.DedupKey + f.Timestamp.String() + f.MatchedAt))
		f.ID = hex.EncodeToString(sum[:6])
	}
}

func (f Finding) JSONL() ([]byte, error) {
	return json.Marshal(f)
}
