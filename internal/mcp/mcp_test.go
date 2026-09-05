package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func req(t *testing.T, method, params string) rpcRequest {
	t.Helper()
	return rpcRequest{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: method, Params: json.RawMessage(params)}
}

func TestInitialize(t *testing.T) {
	s := NewServer("0.1.0")
	resp, notif := s.dispatch(req(t, "initialize", ""))
	if notif || resp.Error != nil {
		t.Fatalf("initialize failed: %+v", resp)
	}
	m := resp.Result.(map[string]any)
	if m["protocolVersion"] != protocolVersion {
		t.Fatalf("bad protocol version: %v", m["protocolVersion"])
	}
}

func TestToolsList(t *testing.T) {
	s := NewServer("0.1.0")
	resp, _ := s.dispatch(req(t, "tools/list", ""))
	m := resp.Result.(map[string]any)
	tools := m["tools"].([]map[string]any)
	if len(tools) != 6 {
		t.Fatalf("expected 6 tools, got %d", len(tools))
	}
}

func TestUnknownMethodWithID(t *testing.T) {
	s := NewServer("0.1.0")
	resp, notif := s.dispatch(req(t, "does/not/exist", ""))
	if notif || resp.Error == nil || resp.Error.Code != -32601 {
		t.Fatalf("expected method-not-found error, got %+v", resp)
	}
}

func TestNotificationNoResponse(t *testing.T) {
	s := NewServer("0.1.0")
	r := rpcRequest{JSONRPC: "2.0", Method: "notifications/initialized"}
	_, notif := s.dispatch(r)
	if !notif {
		t.Fatal("notification should produce no response")
	}
}

func TestReconToolRefusesUnauthorized(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scope.json")
	os.WriteFile(path, []byte(`{"program":"acme","in_scope":["*.acme.com"]}`), 0o644)
	s := NewServer("0.1.0")
	args := `{"name":"recon","arguments":{"scope_path":"` + esc(path) + `","authorized":false}}`
	resp, _ := s.dispatch(req(t, "tools/call", args))
	m := resp.Result.(map[string]any)
	if m["isError"] != true {
		t.Fatalf("recon without authorized must be an error: %+v", m)
	}
}

func TestScanToolBadScope(t *testing.T) {
	s := NewServer("0.1.0")
	args := `{"name":"scan","arguments":{"scope_path":"/no/such/scope.json","authorized":true,"targets":["x"]}}`
	resp, _ := s.dispatch(req(t, "tools/call", args))
	m := resp.Result.(map[string]any)
	if m["isError"] != true {
		t.Fatalf("bad scope path must be an error: %+v", m)
	}
}

func TestUnknownTool(t *testing.T) {
	s := NewServer("0.1.0")
	resp, _ := s.dispatch(req(t, "tools/call", `{"name":"nope","arguments":{}}`))
	m := resp.Result.(map[string]any)
	if m["isError"] != true {
		t.Fatalf("unknown tool must be an error: %+v", m)
	}
}

func esc(p string) string { return strings.ReplaceAll(p, `\`, `\\`) }

func TestScopeCheckTool(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scope.json")
	os.WriteFile(path, []byte(`{"program":"acme","in_scope":["*.acme.com"]}`), 0o644)

	s := NewServer("0.1.0")
	args := `{"name":"scope_check","arguments":{"scope_path":"` + strings.ReplaceAll(path, `\`, `\\`) + `","targets":["api.acme.com","evil.com"]}}`
	resp, _ := s.dispatch(req(t, "tools/call", args))
	m := resp.Result.(map[string]any)
	text := m["content"].([]map[string]any)[0]["text"].(string)
	if !strings.Contains(text, `"api.acme.com": true`) || !strings.Contains(text, `"evil.com": false`) {
		t.Fatalf("unexpected scope_check output: %s", text)
	}
}
