package feedback

import (
	"path/filepath"
	"testing"

	"github.com/talkdedsec/tlk-huntx/internal/finding"
)

func TestRecordSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fb.json")
	s := Load(path)
	s.Record("exposed-dotenv", true)
	s.Record("directory-listing", false)
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	back := Load(path)
	if back.Stats["exposed-dotenv"].Accepted != 1 || back.Stats["directory-listing"].Rejected != 1 {
		t.Fatalf("round trip wrong: %+v", back.Stats)
	}
}

func TestAdjustDemotesNoisyTemplate(t *testing.T) {
	s := Load(filepath.Join(t.TempDir(), "fb.json"))
	for i := 0; i < 9; i++ {
		s.Record("noisy", false)
	}
	s.Record("noisy", true)

	f := finding.Finding{TemplateID: "noisy", Confidence: 90}
	got := s.Adjust(f)
	if got.Confidence >= 90 {
		t.Fatalf("confidence should drop, got %d", got.Confidence)
	}
	tagged := false
	for _, tag := range got.Tags {
		if tag == "likely-fp" {
			tagged = true
		}
	}
	if !tagged {
		t.Fatal("high reject rate should tag likely-fp")
	}
}

func TestAdjustUntrackedUnchanged(t *testing.T) {
	s := Load(filepath.Join(t.TempDir(), "fb.json"))
	f := finding.Finding{TemplateID: "unseen", Confidence: 70}
	if s.Adjust(f).Confidence != 70 {
		t.Fatal("untracked template must be left alone")
	}
}
