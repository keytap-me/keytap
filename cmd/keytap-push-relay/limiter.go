package main

import (
	"sync"
	"time"
)

// limiter is a fixed-window counter per key, in memory only. Windows older than the period are
// dropped on access and swept periodically, so nothing about a token outlives a few minutes.
type limiter struct {
	mu     sync.Mutex
	max    int
	period time.Duration
	seen   map[string]*window
}

type window struct {
	start time.Time
	count int
}

func newLimiter(max int, period time.Duration) *limiter {
	l := &limiter{max: max, period: period, seen: map[string]*window{}}
	go func() {
		for range time.Tick(period) {
			l.sweep()
		}
	}()
	return l
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	w := l.seen[key]
	if w == nil || now.Sub(w.start) >= l.period {
		l.seen[key] = &window{start: now, count: 1}
		return true
	}
	if w.count >= l.max {
		return false
	}
	w.count++
	return true
}

func (l *limiter) sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, w := range l.seen {
		if time.Since(w.start) >= l.period {
			delete(l.seen, k)
		}
	}
}
