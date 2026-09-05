// Package feedback closes the false-positive loop. Triage decisions (accept /
// reject) are recorded per template and persisted; on later runs the confidence of
// a finding is pulled down toward the template's historical reject rate, and a
// template that is almost always wrong gets tagged likely-fp instead of shouting.
package feedback

import (
	"encoding/json"
	"os"

	"github.com/talkdedsec/tlk-huntx/internal/finding"
)

type Stat struct {
	Accepted int `json:"accepted"`
	Rejected int `json:"rejected"`
}

type Store struct {
	path  string
	Stats map[string]Stat `json:"stats"`
}

func Load(path string) *Store {
	s := &Store{path: path, Stats: map[string]Stat{}}
	b, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	_ = json.Unmarshal(b, s)
	if s.Stats == nil {
		s.Stats = map[string]Stat{}
	}
	s.path = path
	return s
}

func (s *Store) Save() error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0o644)
}

func (s *Store) Record(templateID string, accepted bool) {
	st := s.Stats[templateID]
	if accepted {
		st.Accepted++
	} else {
		st.Rejected++
	}
	s.Stats[templateID] = st
}

// Adjust reweights a finding's confidence by the template's history. With enough
// evidence and a high reject rate it is demoted and tagged rather than trusted.
func (s *Store) Adjust(f finding.Finding) finding.Finding {
	st, ok := s.Stats[f.TemplateID]
	total := st.Accepted + st.Rejected
	if !ok || total == 0 {
		return f
	}
	rejectRate := float64(st.Rejected) / float64(total)
	f.Confidence = int(float64(f.Confidence) * (1 - rejectRate*0.7))
	if f.Confidence < 1 {
		f.Confidence = 1
	}
	if total >= 5 && rejectRate >= 0.8 {
		f.Tags = append(f.Tags, "likely-fp")
	}
	return f
}
