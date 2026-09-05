// Package scope is the safety core: every outbound target is checked here before
// any request leaves the tool. Out-of-scope rules deny with precedence over
// in-scope rules, so an accidental match can never open a forbidden host.
package scope

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

type Scope struct {
	Program        string   `json:"program"`
	InScope        []string `json:"in_scope"`
	OutOfScope     []string `json:"out_of_scope"`
	ForbiddenPaths []string `json:"forbidden_paths"`
	AllowedMethods []string `json:"allowed_methods"`

	in  []matcher
	out []matcher
}

type matcher struct {
	raw      string
	wildcard bool
	host     string
	cidr     *net.IPNet
}

type Decision struct {
	Allowed bool
	Reason  string
}

func Load(path string) (*Scope, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Scope
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("parse scope %s: %w", path, err)
	}
	if err := s.Compile(); err != nil {
		return nil, err
	}
	return &s, nil
}

// Compile builds the matchers from the raw rule strings. Load calls it; callers
// that construct a Scope in memory (tests, MCP, monitoring) call it themselves.
func (s *Scope) Compile() error {
	for _, r := range s.InScope {
		m, err := newMatcher(r)
		if err != nil {
			return err
		}
		s.in = append(s.in, m)
	}
	for _, r := range s.OutOfScope {
		m, err := newMatcher(r)
		if err != nil {
			return err
		}
		s.out = append(s.out, m)
	}
	if len(s.in) == 0 {
		return errors.New("scope has no in_scope entries")
	}
	return nil
}

func newMatcher(raw string) (matcher, error) {
	r := strings.ToLower(strings.TrimSpace(raw))
	if r == "" {
		return matcher{}, errors.New("empty scope rule")
	}
	if strings.Contains(r, "/") {
		if _, ipnet, err := net.ParseCIDR(r); err == nil {
			return matcher{raw: raw, cidr: ipnet}, nil
		}
		return matcher{}, fmt.Errorf("invalid CIDR in scope: %q", raw)
	}
	if strings.HasPrefix(r, "*.") {
		return matcher{raw: raw, wildcard: true, host: strings.TrimPrefix(r, "*.")}, nil
	}
	return matcher{raw: raw, host: r}, nil
}

func (m matcher) matches(host string, ip net.IP) bool {
	if m.cidr != nil {
		return ip != nil && m.cidr.Contains(ip)
	}
	if m.wildcard {
		return strings.HasSuffix(host, "."+m.host)
	}
	return host == m.host
}

// Check resolves a URL, host, or IP to an in/out decision.
func (s *Scope) Check(target string) Decision {
	host, ip := hostOf(target)
	if host == "" {
		return Decision{false, "empty target"}
	}
	for _, m := range s.out {
		if m.matches(host, ip) {
			return Decision{false, "out-of-scope rule " + m.raw}
		}
	}
	for _, m := range s.in {
		if m.matches(host, ip) {
			return Decision{true, "in-scope rule " + m.raw}
		}
	}
	return Decision{false, "not covered by any in-scope rule"}
}

func (s *Scope) AllowsMethod(method string) bool {
	if len(s.AllowedMethods) == 0 {
		return true
	}
	method = strings.ToUpper(strings.TrimSpace(method))
	for _, a := range s.AllowedMethods {
		if strings.ToUpper(strings.TrimSpace(a)) == method {
			return true
		}
	}
	return false
}

func (s *Scope) AllowsPath(p string) bool {
	for _, f := range s.ForbiddenPaths {
		if f != "" && strings.HasPrefix(p, f) {
			return false
		}
	}
	return true
}

func hostOf(target string) (string, net.IP) {
	t := strings.TrimSpace(target)
	if strings.Contains(t, "://") {
		if u, err := url.Parse(t); err == nil && u.Host != "" {
			t = u.Host
		}
	}
	if h, _, err := net.SplitHostPort(t); err == nil {
		t = h
	}
	t = strings.Trim(t, "[]")
	t = strings.ToLower(strings.TrimSuffix(t, "."))
	return t, net.ParseIP(t)
}
