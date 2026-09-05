package authz

import (
	"os"
	"path/filepath"
	"testing"
)

func writeScope(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scope.json")
	os.WriteFile(p, []byte(`{"program":"acme","in_scope":["*.acme.com"]}`), 0o644)
	return p
}

func TestVerifyNeedsScopePath(t *testing.T) {
	if _, err := (Config{Authorized: true}).Verify(); err == nil {
		t.Fatal("expected error without scope path")
	}
}

func TestVerifyNeedsAuthorized(t *testing.T) {
	p := writeScope(t)
	if _, err := (Config{ScopePath: p}).Verify(); err == nil {
		t.Fatal("expected error without --authorized")
	}
}

func TestVerifyOK(t *testing.T) {
	p := writeScope(t)
	s, err := (Config{ScopePath: p, Authorized: true}).Verify()
	if err != nil || s == nil || s.Program != "acme" {
		t.Fatalf("verify should succeed: %v %+v", err, s)
	}
}

func TestVerifyBadScope(t *testing.T) {
	if _, err := (Config{ScopePath: "/does/not/exist.json", Authorized: true}).Verify(); err == nil {
		t.Fatal("expected error for missing scope file")
	}
}
