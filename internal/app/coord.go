package app

import (
	"strings"
	"sync"
)

// Coordinator is a process-local keyed lock (KD-R24). Callers still check
// revision / If-Match; the lock only serializes same-DN mutations.
type Coordinator struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func NewCoordinator() *Coordinator {
	return &Coordinator{locks: map[string]*sync.Mutex{}}
}

func (c *Coordinator) Lock(key string) func() {
	if c == nil {
		return func() {}
	}
	key = strings.ToLower(strings.TrimSpace(key))
	c.mu.Lock()
	if c.locks == nil {
		c.locks = map[string]*sync.Mutex{}
	}
	l, ok := c.locks[key]
	if !ok {
		l = &sync.Mutex{}
		c.locks[key] = l
	}
	c.mu.Unlock()
	l.Lock()
	return l.Unlock
}

func userLockKey(id string) string  { return "user:" + id }
func groupLockKey(id string) string { return "group:" + id }
