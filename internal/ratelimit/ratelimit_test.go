package ratelimit

import (
	"context"
	"testing"
	"time"
)

func TestBucketReserve(t *testing.T) {
	b := &bucket{rate: 10, burst: 3, tokens: 3, last: time.Now()}
	for i := 0; i < 3; i++ {
		if d := b.reserve(b.last); d != 0 {
			t.Fatalf("burst token %d should be immediate, got %v", i, d)
		}
	}
	// bucket drained; next token must wait ~1/rate = 100ms
	d := b.reserve(b.last)
	if d <= 0 || d > 200*time.Millisecond {
		t.Fatalf("expected ~100ms wait, got %v", d)
	}
}

func TestBucketRefill(t *testing.T) {
	start := time.Now()
	b := &bucket{rate: 10, burst: 3, tokens: 0, last: start}
	// 500ms later, ~5 tokens accrue but cap at burst=3
	if d := b.reserve(start.Add(500 * time.Millisecond)); d != 0 {
		t.Fatalf("token should be available after refill, got %v", d)
	}
	if b.tokens < 1.9 || b.tokens > 2.1 {
		t.Fatalf("expected ~2 tokens left after consuming 1 of 3, got %.2f", b.tokens)
	}
}

func TestAcquireReleasesSlot(t *testing.T) {
	l := New(1000, 100, 1)
	ctx := context.Background()
	rel, err := l.Acquire(ctx, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		rel2, err := l.Acquire(ctx, "example.com")
		if err == nil {
			rel2()
		}
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("second Acquire should block while the single slot is held")
	case <-time.After(30 * time.Millisecond):
	}
	rel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("second Acquire never proceeded after release")
	}
}

func TestPenalizeDelaysAcquire(t *testing.T) {
	l := New(1000, 100, 5)
	l.Penalize("h", 60*time.Millisecond)
	start := time.Now()
	rel, err := l.Acquire(context.Background(), "h")
	if err != nil {
		t.Fatal(err)
	}
	defer rel()
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond {
		t.Fatalf("penalty not honored, waited only %v", elapsed)
	}
}

func TestPenalizeKeepsLongest(t *testing.T) {
	l := New(1000, 100, 5)
	l.Penalize("h", 10*time.Millisecond)
	l.Penalize("h", 500*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := l.Acquire(ctx, "h"); err == nil {
		t.Fatal("longer penalty should still be in effect")
	}
}

func TestAcquireContextCancel(t *testing.T) {
	l := New(1, 1, 1)
	rel, _ := l.Acquire(context.Background(), "h")
	defer rel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := l.Acquire(ctx, "h"); err == nil {
		t.Fatal("expected context cancellation error")
	}
}
