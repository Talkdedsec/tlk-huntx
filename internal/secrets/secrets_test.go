package secrets

import (
	"strings"
	"testing"
)

func TestScanFindsKeys(t *testing.T) {
	// Keys are assembled from fragments so the source file holds no contiguous
	// secret-shaped literal (which would trip upstream secret-scanning).
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	stripeKey := "sk_" + "live_" + "abcdefghijklmnopqrstuvwx"
	body := `const awsKey = "` + awsKey + `"; const stripe = "` + stripeKey + `"; const nothing = "just some text";`
	got := Scan("https://api.acme.com/app.js", body)
	if len(got) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(got), got)
	}
	for _, f := range got {
		if strings.Contains(f.Evidence.Response, "EXAMPLE") || strings.Contains(f.Evidence.Response, "uvwx") {
			t.Errorf("secret not masked: %q", f.Evidence.Response)
		}
	}
}

func TestScanNoFalsePositive(t *testing.T) {
	if got := Scan("u", "just a normal page with no secrets AKIA-too-short"); len(got) != 0 {
		t.Fatalf("unexpected findings: %+v", got)
	}
}

func TestMask(t *testing.T) {
	if mask("AKIAIOSFODNN7EXAMPLE") != "AKIA****LE" {
		t.Fatalf("mask = %q", mask("AKIAIOSFODNN7EXAMPLE"))
	}
	if mask("short") != "****" {
		t.Fatalf("short mask = %q", mask("short"))
	}
}
