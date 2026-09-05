// Package ratelimit keeps huntx polite and ban-safe: a per-host token bucket
// caps request rate, a global semaphore caps concurrency, and Penalize backs off
// a host that answered 429 or tripped a WAF. Defaults are on; this is not evasion.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

type bucket struct {
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
}

func (b *bucket) reserve(now time.Time) time.Duration {
	elapsed := now.Sub(b.last).Seconds()
	b.last = now
	b.tokens += elapsed * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	if b.tokens >= 1 {
		b.tokens--
		return 0
	}
	wait := (1 - b.tokens) / b.rate
	b.tokens = 0
	return time.Duration(wait * float64(time.Second))
}

type Limiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[string]*bucket
	penalty map[string]time.Time
	sem     chan struct{}
}

func New(rps float64, burst, concurrency int) *Limiter {
	if rps <= 0 {
		rps = 5
	}
	if burst <= 0 {
		burst = int(rps)
		if burst < 1 {
			burst = 1
		}
	}
	if concurrency <= 0 {
		concurrency = 10
	}
	return &Limiter{
		rate:    rps,
		burst:   float64(burst),
		buckets: map[string]*bucket{},
		penalty: map[string]time.Time{},
		sem:     make(chan struct{}, concurrency),
	}
}

// Acquire blocks until the host's bucket has a token and a global concurrency
// slot is free. The returned release frees the slot; call it after the request.
func (l *Limiter) Acquire(ctx context.Context, host string) (release func(), err error) {
	l.mu.Lock()
	if until, ok := l.penalty[host]; ok {
		if d := time.Until(until); d > 0 {
			l.mu.Unlock()
			if err := sleep(ctx, d); err != nil {
				return nil, err
			}
			l.mu.Lock()
		}
	}
	b := l.buckets[host]
	if b == nil {
		b = &bucket{rate: l.rate, burst: l.burst, tokens: l.burst, last: time.Now()}
		l.buckets[host] = b
	}
	wait := b.reserve(time.Now())
	l.mu.Unlock()

	if wait > 0 {
		if err := sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
	select {
	case l.sem <- struct{}{}:
		return func() { <-l.sem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Penalize holds off further requests to host for d (e.g. after a 429).
func (l *Limiter) Penalize(host string, d time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	until := time.Now().Add(d)
	if cur, ok := l.penalty[host]; !ok || until.After(cur) {
		l.penalty[host] = until
	}
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
