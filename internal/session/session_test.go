package session

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ids.json")
	os.WriteFile(path, []byte(`{
		"owner":{"headers":{"Authorization":"Bearer A"}},
		"userB":{"headers":{"Authorization":"Bearer B"}},
		"anon":{"headers":{}}
	}`), 0o644)

	ids, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 3 || ids["owner"].Headers["Authorization"] != "Bearer A" {
		t.Fatalf("bad identities: %+v", ids)
	}
}

func TestLoadEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.json")
	os.WriteFile(path, []byte(`{}`), 0o644)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error on empty identities")
	}
}

func TestLoadBadJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.json")
	os.WriteFile(path, []byte(`{not json`), 0o644)
	if _, err := Load(path); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestLoadMissing(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("expected error for missing file")
	}
}
