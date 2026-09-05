package blastradius

import (
	"sync"
	"testing"
)

func TestStateChangingBlocked(t *testing.T) {
	g := New(0, false)
	if g.Allow("POST").Allowed {
		t.Error("POST must be blocked without --allow-state-changing")
	}
	if !g.Allow("GET").Allowed {
		t.Error("GET must be allowed")
	}
	if g.Allow("delete").Allowed {
		t.Error("DELETE must be blocked (case-insensitive)")
	}
}

func TestStateChangingAllowed(t *testing.T) {
	g := New(0, true)
	if !g.Allow("POST").Allowed {
		t.Error("POST must be allowed with the flag set")
	}
}

func TestBudget(t *testing.T) {
	g := New(2, false)
	if !g.Allow("GET").Allowed {
		t.Fatal("first request should pass")
	}
	if !g.Allow("GET").Allowed {
		t.Fatal("second request should pass")
	}
	if g.Allow("GET").Allowed {
		t.Fatal("third request must exceed budget")
	}
}

func TestBudgetConcurrent(t *testing.T) {
	g := New(100, false)
	var wg sync.WaitGroup
	var allowed int64
	var mu sync.Mutex
	for i := 0; i < 500; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if g.Allow("GET").Allowed {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if allowed != 100 {
		t.Fatalf("budget of 100 leaked under concurrency: allowed=%d", allowed)
	}
}
