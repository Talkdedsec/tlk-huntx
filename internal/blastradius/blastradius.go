// Package blastradius bounds the damage a run can do: a hard cap on total
// requests, and a block on state-changing HTTP methods unless explicitly allowed.
// huntx proves vulnerabilities, it does not exploit them.
package blastradius

import (
	"strings"
	"sync/atomic"
)

var safeMethods = map[string]bool{"GET": true, "HEAD": true, "OPTIONS": true}

type Guard struct {
	maxRequests        int64
	count              int64
	allowStateChanging bool
}

func New(maxRequests int, allowStateChanging bool) *Guard {
	return &Guard{maxRequests: int64(maxRequests), allowStateChanging: allowStateChanging}
}

type Decision struct {
	Allowed bool
	Reason  string
}

// Allow accounts for one request of the given method, denying it if a
// state-changing method is not permitted or the request budget is spent.
func (g *Guard) Allow(method string) Decision {
	m := strings.ToUpper(strings.TrimSpace(method))
	if m == "" {
		m = "GET"
	}
	if !g.allowStateChanging && !safeMethods[m] {
		return Decision{false, "state-changing method " + m + " blocked (pass --allow-state-changing)"}
	}
	if g.maxRequests > 0 {
		for {
			c := atomic.LoadInt64(&g.count)
			if c >= g.maxRequests {
				return Decision{false, "request budget exhausted"}
			}
			if atomic.CompareAndSwapInt64(&g.count, c, c+1) {
				break
			}
		}
	} else {
		atomic.AddInt64(&g.count, 1)
	}
	return Decision{true, ""}
}

func (g *Guard) Count() int64 { return atomic.LoadInt64(&g.count) }
