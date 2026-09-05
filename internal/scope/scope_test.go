package scope

import "testing"

func mk(t *testing.T) *Scope {
	t.Helper()
	s := &Scope{
		Program:        "acme",
		InScope:        []string{"*.acme.com", "acme.io", "192.0.2.0/24"},
		OutOfScope:     []string{"blog.acme.com", "*.internal.acme.com"},
		ForbiddenPaths: []string{"/logout", "/admin/delete"},
		AllowedMethods: []string{"GET", "POST", "HEAD"},
	}
	if err := s.Compile(); err != nil {
		t.Fatalf("compile: %v", err)
	}
	return s
}

func TestCheck(t *testing.T) {
	s := mk(t)
	cases := []struct {
		target string
		want   bool
	}{
		{"api.acme.com", true},
		{"deep.sub.acme.com", true},
		{"https://api.acme.com/v1/users?id=1", true},
		{"acme.io", true},
		{"acme.com", false},             // apex not matched by *.acme.com
		{"blog.acme.com", false},        // out-of-scope wins
		{"db.internal.acme.com", false}, // out-of-scope wildcard wins
		{"192.0.2.55", true},            // in CIDR
		{"192.0.2.55:8443", true},       // port stripped
		{"198.51.100.9", false},         // outside CIDR
		{"evil.com", false},             // not covered
		{"", false},
	}
	for _, c := range cases {
		if got := s.Check(c.target).Allowed; got != c.want {
			t.Errorf("Check(%q) = %v, want %v", c.target, got, c.want)
		}
	}
}

func TestOutOfScopePrecedence(t *testing.T) {
	s := mk(t)
	// blog.acme.com matches *.acme.com (in) but blog.acme.com (out) must win.
	if s.Check("blog.acme.com").Allowed {
		t.Fatal("out-of-scope did not take precedence")
	}
}

func TestAllowsMethod(t *testing.T) {
	s := mk(t)
	if !s.AllowsMethod("get") {
		t.Error("GET should be allowed")
	}
	if s.AllowsMethod("DELETE") {
		t.Error("DELETE not in allowed list")
	}
	empty := &Scope{}
	if !empty.AllowsMethod("DELETE") {
		t.Error("no allow-list means all methods allowed")
	}
}

func TestAllowsPath(t *testing.T) {
	s := mk(t)
	if s.AllowsPath("/logout") {
		t.Error("/logout is forbidden")
	}
	if s.AllowsPath("/admin/delete/42") {
		t.Error("prefix /admin/delete is forbidden")
	}
	if !s.AllowsPath("/api/users") {
		t.Error("/api/users should be allowed")
	}
}

func TestLoadRejectsEmptyInScope(t *testing.T) {
	s := &Scope{InScope: nil}
	if err := s.Compile(); err == nil {
		t.Fatal("expected error for empty in_scope")
	}
}

func TestCompileRejectsBadCIDR(t *testing.T) {
	s := &Scope{InScope: []string{"10.0.0.0/99"}}
	if err := s.Compile(); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestCheckURLWithPortAndPath(t *testing.T) {
	s := mk(t)
	if !s.Check("https://api.acme.com:8443/admin?x=1").Allowed {
		t.Fatal("url with port and path should resolve to the in-scope host")
	}
}

func TestCheckIPv6Bracketed(t *testing.T) {
	s := &Scope{InScope: []string{"::1"}}
	if err := s.Compile(); err != nil {
		t.Fatal(err)
	}
	if !s.Check("http://[::1]:8080/").Allowed {
		t.Fatal("bracketed IPv6 host should match")
	}
}
