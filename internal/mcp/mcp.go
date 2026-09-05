// Package mcp exposes huntx over the Model Context Protocol (JSON-RPC 2.0 on
// stdio), so an LLM agent drives recon/scan/scope as typed tools instead of
// parsing CLI text. Active tools still require the scope gate and an authorized flag.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"

	"github.com/talkdedsec/tlk-huntx/internal/agent"
	"github.com/talkdedsec/tlk-huntx/internal/apidisco"
	"github.com/talkdedsec/tlk-huntx/internal/crawl"
	"github.com/talkdedsec/tlk-huntx/internal/engine"
	"github.com/talkdedsec/tlk-huntx/internal/finding"
	"github.com/talkdedsec/tlk-huntx/internal/report"
	"github.com/talkdedsec/tlk-huntx/internal/scope"
)

const protocolVersion = "2024-11-05"

type Server struct {
	version string
}

func NewServer(version string) *Server { return &Server{version: version} }

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Serve reads newline-delimited JSON-RPC from in and writes responses to out.
func (s *Server) Serve(in io.Reader, out io.Writer) int {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	enc := json.NewEncoder(out)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			continue
		}
		resp, notification := s.dispatch(req)
		if notification {
			continue
		}
		if err := enc.Encode(resp); err != nil {
			return 1
		}
	}
	return 0
}

func (s *Server) dispatch(req rpcRequest) (rpcResponse, bool) {
	switch req.Method {
	case "initialize":
		return result(req.ID, map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "huntx", "version": s.version},
		}), false
	case "ping":
		return result(req.ID, map[string]any{}), false
	case "tools/list":
		return result(req.ID, map[string]any{"tools": toolDefs()}), false
	case "tools/call":
		return s.callTool(req), false
	default:
		if len(req.ID) == 0 { // notifications carry no id
			return rpcResponse{}, true
		}
		return fail(req.ID, -32601, "method not found: "+req.Method), false
	}
}

func result(id json.RawMessage, r any) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Result: r}
}

func fail(id json.RawMessage, code int, msg string) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

func toolText(id json.RawMessage, text string, isErr bool) rpcResponse {
	return result(id, map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": isErr,
	})
}

type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func (s *Server) callTool(req rpcRequest) rpcResponse {
	var p callParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return fail(req.ID, -32602, "bad params")
	}
	switch p.Name {
	case "scope_check":
		return s.scopeCheck(req.ID, p.Arguments)
	case "recon":
		return s.recon(req.ID, p.Arguments)
	case "scan":
		return s.scan(req.ID, p.Arguments)
	case "plan":
		return s.plan(req.ID, p.Arguments)
	case "api":
		return s.api(req.ID, p.Arguments)
	case "crawl":
		return s.crawl(req.ID, p.Arguments)
	default:
		return toolText(req.ID, "unknown tool: "+p.Name, true)
	}
}

type toolArgs struct {
	ScopePath   string   `json:"scope_path"`
	Authorized  bool     `json:"authorized"`
	Targets     []string `json:"targets"`
	Domains     []string `json:"domains"`
	Verify      bool     `json:"verify"`
	RPS         float64  `json:"rps"`
	Concurrency int      `json:"concurrency"`
	MaxRequests int      `json:"max_requests"`
}

func (a toolArgs) opts(s *scope.Scope) engine.Options {
	rps := a.RPS
	if rps <= 0 {
		rps = 5
	}
	conc := a.Concurrency
	if conc <= 0 {
		conc = 10
	}
	return engine.Options{Scope: s, RPS: rps, Concurrency: conc, MaxRequests: a.MaxRequests, Verify: a.Verify}
}

func (s *Server) loadScope(raw json.RawMessage) (*scope.Scope, toolArgs, error) {
	var a toolArgs
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, a, err
	}
	sc, err := scope.Load(a.ScopePath)
	return sc, a, err
}

func (s *Server) scopeCheck(id, raw json.RawMessage) rpcResponse {
	sc, a, err := s.loadScope(raw)
	if err != nil {
		return toolText(id, "scope: "+err.Error(), true)
	}
	out := map[string]bool{}
	for _, t := range a.Targets {
		out[t] = sc.Check(t).Allowed
	}
	return toolText(id, mustJSON(out), false)
}

func (s *Server) recon(id, raw json.RawMessage) rpcResponse {
	sc, a, err := s.loadScope(raw)
	if err != nil {
		return toolText(id, "scope: "+err.Error(), true)
	}
	if !a.Authorized {
		return toolText(id, "refusing recon without authorized:true", true)
	}
	seeds := a.Domains
	if len(seeds) == 0 {
		for _, r := range sc.InScope {
			seeds = append(seeds, r)
		}
	}
	results, _ := engine.Recon(context.Background(), seeds, a.opts(sc))
	return toolText(id, mustJSON(results), false)
}

func (s *Server) scan(id, raw json.RawMessage) rpcResponse {
	sc, a, err := s.loadScope(raw)
	if err != nil {
		return toolText(id, "scope: "+err.Error(), true)
	}
	if !a.Authorized {
		return toolText(id, "refusing scan without authorized:true", true)
	}
	var targets []engine.Target
	for _, t := range a.Targets {
		if len(t) > 0 {
			base := t
			if !hasScheme(base) {
				base = "https://" + base
			}
			targets = append(targets, engine.Target{Base: base})
		}
	}
	findings := engine.Scan(context.Background(), targets, a.opts(sc))
	return toolText(id, report.Markdown(sc.Program, findings), false)
}

func (a toolArgs) targets() []engine.Target {
	var out []engine.Target
	for _, t := range a.Targets {
		if len(t) == 0 {
			continue
		}
		base := t
		if !hasScheme(base) {
			base = "https://" + base
		}
		out = append(out, engine.Target{Base: base})
	}
	return out
}

func (s *Server) plan(id, raw json.RawMessage) rpcResponse {
	sc, a, err := s.loadScope(raw)
	if err != nil {
		return toolText(id, "scope: "+err.Error(), true)
	}
	if !a.Authorized {
		return toolText(id, "refusing plan without authorized:true", true)
	}
	findings := engine.Scan(context.Background(), a.targets(), a.opts(sc))
	return toolText(id, mustJSON(agent.Plan(findings)), false)
}

func (s *Server) api(id, raw json.RawMessage) rpcResponse {
	sc, a, err := s.loadScope(raw)
	if err != nil {
		return toolText(id, "scope: "+err.Error(), true)
	}
	if !a.Authorized {
		return toolText(id, "refusing api without authorized:true", true)
	}
	client := a.opts(sc).Client()
	var out []finding.Finding
	for _, t := range a.targets() {
		if !sc.Check(t.Base).Allowed {
			continue
		}
		fs, _ := apidisco.Discover(context.Background(), client, t.Base)
		out = append(out, fs...)
	}
	return toolText(id, mustJSON(out), false)
}

func (s *Server) crawl(id, raw json.RawMessage) rpcResponse {
	sc, a, err := s.loadScope(raw)
	if err != nil {
		return toolText(id, "scope: "+err.Error(), true)
	}
	if !a.Authorized {
		return toolText(id, "refusing crawl without authorized:true", true)
	}
	client := a.opts(sc).Client()
	result := map[string]crawl.Result{}
	for _, t := range a.targets() {
		if !sc.Check(t.Base).Allowed {
			continue
		}
		result[t.Base] = crawl.Run(context.Background(), client, t.Base)
	}
	return toolText(id, mustJSON(result), false)
}

func hasScheme(s string) bool { return bytes.Contains([]byte(s), []byte("://")) }

func mustJSON(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}

func toolDefs() []map[string]any {
	strArr := map[string]any{"type": "array", "items": map[string]any{"type": "string"}}
	return []map[string]any{
		{
			"name":        "scope_check",
			"description": "Check whether targets fall inside the program scope. No requests are sent.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"scope_path": map[string]any{"type": "string"},
					"targets":    strArr,
				},
				"required": []string{"scope_path", "targets"},
			},
		},
		{
			"name":        "recon",
			"description": "Passive subdomain discovery + gated HTTP probing. Requires authorized:true.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"scope_path":  map[string]any{"type": "string"},
					"authorized":  map[string]any{"type": "boolean"},
					"domains":     strArr,
					"rps":         map[string]any{"type": "number"},
					"concurrency": map[string]any{"type": "integer"},
				},
				"required": []string{"scope_path", "authorized"},
			},
		},
		{
			"name":        "scan",
			"description": "Run detection templates + secret scan and return a markdown report. Requires authorized:true.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"scope_path":   map[string]any{"type": "string"},
					"authorized":   map[string]any{"type": "boolean"},
					"targets":      strArr,
					"verify":       map[string]any{"type": "boolean"},
					"max_requests": map[string]any{"type": "integer"},
				},
				"required": []string{"scope_path", "authorized", "targets"},
			},
		},
		{
			"name":        "plan",
			"description": "Scan targets, then return an expected-value-ranked playbook with composed attack chains. Requires authorized:true.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"scope_path": map[string]any{"type": "string"},
					"authorized": map[string]any{"type": "boolean"},
					"targets":    strArr,
					"verify":     map[string]any{"type": "boolean"},
				},
				"required": []string{"scope_path", "authorized", "targets"},
			},
		},
		{
			"name":        "api",
			"description": "Discover GraphQL introspection and exposed OpenAPI/Swagger specs. Requires authorized:true.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"scope_path": map[string]any{"type": "string"},
					"authorized": map[string]any{"type": "boolean"},
					"targets":    strArr,
				},
				"required": []string{"scope_path", "authorized", "targets"},
			},
		},
		{
			"name":        "crawl",
			"description": "Mine endpoints and parameters from HTML and same-host JavaScript. Requires authorized:true.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"scope_path": map[string]any{"type": "string"},
					"authorized": map[string]any{"type": "boolean"},
					"targets":    strArr,
				},
				"required": []string{"scope_path", "authorized", "targets"},
			},
		},
	}
}
