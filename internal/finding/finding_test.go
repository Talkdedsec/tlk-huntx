package finding

import (
	"encoding/json"
	"testing"
)

func TestFingerprintStableAndParamOrderIndependent(t *testing.T) {
	a := Fingerprint("tpl", "https://acme.com/x", []string{"b", "a"})
	b := Fingerprint("tpl", "https://acme.com/x", []string{"a", "b"})
	if a != b {
		t.Fatal("fingerprint must not depend on param order")
	}
	if a == Fingerprint("tpl", "https://other.com/x", []string{"a", "b"}) {
		t.Fatal("different host should change fingerprint")
	}
}

func TestFinalizeFillsKeys(t *testing.T) {
	f := Finding{TemplateID: "tpl", MatchedAt: "https://acme.com/x"}
	f.Finalize([]string{"id"})
	if f.DedupKey == "" || f.ID == "" || f.Timestamp.IsZero() {
		t.Fatalf("Finalize left fields empty: %+v", f)
	}
	// same dedup inputs -> same dedup key
	g := Finding{TemplateID: "tpl", MatchedAt: "https://acme.com/x"}
	g.Finalize([]string{"id"})
	if g.DedupKey != f.DedupKey {
		t.Fatal("equal inputs should yield equal dedup keys")
	}
}

func TestSeverityRank(t *testing.T) {
	if !(Critical.Rank() > High.Rank() && High.Rank() > Medium.Rank() &&
		Medium.Rank() > Low.Rank() && Low.Rank() > Info.Rank()) {
		t.Fatal("severity ranks out of order")
	}
	if Severity("bogus").Rank() != Info.Rank() {
		t.Fatal("unknown severity should rank as info")
	}
}

func TestJSONLRoundTrip(t *testing.T) {
	f := Finding{TemplateID: "tpl", Severity: High, MatchedAt: "u", Confidence: 90}
	f.Finalize(nil)
	b, err := f.JSONL()
	if err != nil {
		t.Fatal(err)
	}
	var back Finding
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.DedupKey != f.DedupKey || back.Severity != High {
		t.Fatalf("round trip lost data: %+v", back)
	}
}
