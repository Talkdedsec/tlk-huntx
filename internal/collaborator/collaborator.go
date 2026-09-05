// Package collaborator is an out-of-band interaction server, like a self-hosted
// Burp Collaborator. A payload carries a unique token; when a target fetches or
// resolves it (blind SSRF, blind XSS, OOB RCE), the server records the hit and the
// scanner correlates it by token. An OOB hit is deterministic proof, not a guess.
package collaborator

import (
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Interaction struct {
	Token  string    `json:"token"`
	Remote string    `json:"remote"`
	Method string    `json:"method"`
	Path   string    `json:"path"`
	Host   string    `json:"host"`
	Agent  string    `json:"agent"`
	Seen   time.Time `json:"seen"`
}

type Server struct {
	base  string
	mu    sync.Mutex
	store map[string][]Interaction
}

// NewServer builds a collaborator reachable at base (e.g. https://oob.example.com).
func NewServer(base string) *Server {
	return &Server{base: strings.TrimRight(base, "/"), store: map[string][]Interaction{}}
}

// SetBase updates the public base URL payloads are minted from (used when the
// listen address is known only after the server starts).
func (s *Server) SetBase(base string) { s.base = strings.TrimRight(base, "/") }

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := tokenFrom(r)
		if tok != "" {
			ip, _, _ := net.SplitHostPort(r.RemoteAddr)
			s.record(Interaction{
				Token:  tok,
				Remote: ip,
				Method: r.Method,
				Path:   r.URL.Path,
				Host:   r.Host,
				Agent:  r.UserAgent(),
				Seen:   time.Now().UTC(),
			})
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("huntx"))
	})
}

// tokenFrom reads the token from the leftmost host label (token.oob.example.com)
// or the first path segment (/token/...), whichever is present.
func tokenFrom(r *http.Request) string {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if i := strings.IndexByte(host, '.'); i > 0 {
		if label := host[:i]; isToken(label) {
			return label
		}
	}
	seg := strings.SplitN(strings.Trim(r.URL.Path, "/"), "/", 2)[0]
	if isToken(seg) {
		return seg
	}
	return ""
}

func isToken(s string) bool {
	if len(s) != 16 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func (s *Server) record(i Interaction) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store[i.Token] = append(s.store[i.Token], i)
}

// Payload mints a token and the URL to embed in a probe.
func (s *Server) Payload() (token, url string) {
	b := make([]byte, 8)
	rand.Read(b)
	token = hex.EncodeToString(b)
	return token, s.base + "/" + token
}

func (s *Server) Interactions(token string) []Interaction {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Interaction(nil), s.store[token]...)
}

func (s *Server) Hit(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.store[token]) > 0
}
