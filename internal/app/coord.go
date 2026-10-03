package app

import (
	"strings"
	"sync"
)

type keyedLock struct {
	mu   sync.Mutex
	refs int
}

// Coordinator is a process-local keyed lock (KD-R24). Callers still check
// revision / If-Match; the lock only serializes same-DN mutations.
type Coordinator struct {
	mu    sync.Mutex
	locks map[string]*keyedLock
}

func NewCoordinator() *Coordinator {
	return &Coordinator{locks: map[string]*keyedLock{}}
}

func (c *Coordinator) Lock(key string) func() {
	if c == nil {
		return func() {}
	}
	key = strings.ToLower(strings.TrimSpace(key))
	c.mu.Lock()
	if c.locks == nil {
		c.locks = map[string]*keyedLock{}
	}
	l, ok := c.locks[key]
	if !ok {
		l = &keyedLock{}
		c.locks[key] = l
	}
	l.refs++
	c.mu.Unlock()
	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		c.mu.Lock()
		l.refs--
		if l.refs == 0 {
			delete(c.locks, key)
		}
		c.mu.Unlock()
	}
}

func userLockKey(id string) string  { return "user:" + id }
func groupLockKey(id string) string { return "group:" + id }
