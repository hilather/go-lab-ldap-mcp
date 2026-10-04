package app

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
)

type keyedLock struct {
	mu   sync.Mutex
	refs int
}

// Coordinator is a process-local keyed lock (KD-R24). Callers still check
// revision / If-Match. A shared mutation lease additionally serializes writes
// across user/group/entry surfaces whose identifiers can name the same entry.
type Coordinator struct {
	mu       sync.Mutex
	locks    map[string]*keyedLock
	mutation chan struct{}
	waiters  atomic.Int32
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

// AcquireMutation serializes application writes before their live revision
// reads. Waiting remains cancellable, including while reset drains admissions.
func (c *Coordinator) AcquireMutation(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c == nil {
		return func() {}, nil
	}
	c.mu.Lock()
	if c.mutation == nil {
		c.mutation = make(chan struct{}, 1)
	}
	semaphore := c.mutation
	c.mu.Unlock()
	acquired := func() (func(), error) {
		if err := ctx.Err(); err != nil {
			<-semaphore
			return nil, err
		}
		var once sync.Once
		return func() { once.Do(func() { <-semaphore }) }, nil
	}
	select {
	case semaphore <- struct{}{}:
		return acquired()
	default:
	}
	c.waiters.Add(1)
	defer c.waiters.Add(-1)
	select {
	case semaphore <- struct{}{}:
		return acquired()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// MutationWaiters reports callers that found the shared mutation lease held
// and are waiting for it. A caller counts as waiting once its non-blocking
// attempt observed the lease held, just before it parks. Test/diagnostic
// only: no transport or handler reads it, and it carries no stability
// guarantee.
func (c *Coordinator) MutationWaiters() int {
	if c == nil {
		return 0
	}
	return int(c.waiters.Load())
}
