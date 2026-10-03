package app

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
)

const maxRateLimitKeys = 4096

// Window is a process-local sliding-window limiter. Keys use prefixes
// password:, bind:, and reset: to select compiled rates. Other keys use
// the general requests-per-minute budget.
type Window struct {
	nextSweep      time.Time
	mu             sync.Mutex
	hits           map[string][]time.Time
	now            func() time.Time
	passwordPerMin int
	bindPerMin     int
	requestPerMin  int
	resetPerHour   int
}

func NewWindow(passwordPerMin, bindPerMin, requestPerMin, resetPerHour int) *Window {
	return &Window{
		hits:           map[string][]time.Time{},
		now:            time.Now,
		passwordPerMin: passwordPerMin,
		bindPerMin:     bindPerMin,
		requestPerMin:  requestPerMin,
		resetPerHour:   resetPerHour,
	}
}

func (w *Window) Allow(_ context.Context, key string) error {
	if w == nil {
		return nil
	}
	limit, window := w.budget(key)
	if limit <= 0 {
		return nil
	}
	now := w.now
	if now == nil {
		now = time.Now
	}
	t := now()
	w.mu.Lock()
	defer w.mu.Unlock()
	if !t.Before(w.nextSweep) || len(w.hits) >= maxRateLimitKeys {
		for old, hits := range w.hits {
			_, duration := w.budget(old)
			if len(hits) == 0 || !hits[len(hits)-1].After(t.Add(-duration)) {
				delete(w.hits, old)
			}
		}
		w.nextSweep = t.Add(time.Minute)
	}
	if _, exists := w.hits[key]; !exists && len(w.hits) >= maxRateLimitKeys {
		return rateLimited()
	}
	cutoff := t.Add(-window)
	q := w.hits[key]
	i := 0
	for i < len(q) && !q[i].After(cutoff) {
		i++
	}
	q = q[i:]
	if len(q) >= limit {
		w.hits[key] = q
		return rateLimited()
	}
	w.hits[key] = append(q, t)
	return nil
}

// AllowKey is the HTTP limiter adapter (true means admit).
func (w *Window) AllowKey(key string) bool {
	return w.Allow(context.Background(), key) == nil
}

func (w *Window) budget(key string) (int, time.Duration) {
	switch {
	case strings.HasPrefix(key, "password:"):
		return w.passwordPerMin, time.Minute
	case strings.HasPrefix(key, "bind:"):
		return w.bindPerMin, time.Minute
	case strings.HasPrefix(key, "reset:"):
		return w.resetPerHour, time.Hour
	default:
		return w.requestPerMin, time.Minute
	}
}

func rateLimited() error {
	return apperr.New(apperr.CodeAuth, "rate limit exceeded").WithField(apperr.Field{Path: "rateLimit", Code: "rate_limited", Message: "rate limit exceeded"}).Retry()
}
