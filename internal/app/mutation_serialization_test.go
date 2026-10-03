package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/reset"
)

type notifyingAdmissionGate struct {
	*reset.Gate
	admitted chan struct{}
}

func (g notifyingAdmissionGate) AcquireWrite(ctx context.Context) (func(), error) {
	release, err := g.Gate.AcquireWrite(ctx)
	if err == nil {
		g.admitted <- struct{}{}
	}
	return release, err
}

func TestMutationWaitCancellationReleasesResetAdmission(t *testing.T) {
	gate := reset.NewGate()
	admitted := make(chan struct{}, 2)
	h := hooks{gate: notifyingAdmissionGate{gate, admitted}, locks: NewCoordinator()}
	release, err := h.acquireWrite(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	<-admitted
	ctx, cancel := context.WithCancel(t.Context())
	waiting := make(chan error, 1)
	go func() {
		done, err := h.acquireWrite(ctx)
		if done != nil {
			done()
		}
		waiting <- err
	}()
	<-admitted // waiter owns a reset lease before waiting on the shared mutation lock
	cancel()
	if err := <-waiting; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled waiter: %v", err)
	}
	release()
	generation, err := gate.Begin()
	if err != nil {
		t.Fatal(err)
	}
	deadline, stop := context.WithTimeout(t.Context(), time.Second)
	defer stop()
	if err := gate.WaitIdle(deadline, generation); err != nil {
		t.Fatalf("canceled mutation retained admission: %v", err)
	}
}

func TestSharedMutationAdmissionSerializesAndHonorsCancellation(t *testing.T) {
	c := NewCoordinator()
	first, err := c.AcquireMutation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if release, err := c.AcquireMutation(ctx); !errors.Is(err, context.DeadlineExceeded) || release != nil {
		t.Fatalf("contending write: %v", err)
	}
	first()
	first()
	next, err := c.AcquireMutation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	next()
	canceled, stop := context.WithCancel(t.Context())
	stop()
	if _, err := c.AcquireMutation(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled idle acquisition: %v", err)
	}
}

func TestEntryLockKeyCanonicalizesEscapedAliases(t *testing.T) {
	if entryLockKey("uid=alice,ou=people,dc=test") != entryLockKey(`uid=\61lice,ou=people,dc=test`) {
		t.Fatal("equivalent DN keys differ")
	}
	if entryLockKey(`uid=alice\,ou=people,dc=test`) == entryLockKey("uid=alice,ou=people,dc=test") {
		t.Fatal("distinct DN keys collide")
	}
}

func TestCoordinatorReportsMutationWaiters(t *testing.T) {
	c := NewCoordinator()
	release, err := c.AcquireMutation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if n := c.MutationWaiters(); n != 0 {
		t.Fatalf("waiters with uncontended holder = %d", n)
	}
	waitFor := func(want int) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for c.MutationWaiters() != want {
			if time.Now().After(deadline) {
				t.Fatalf("waiters = %d, want %d", c.MutationWaiters(), want)
			}
			time.Sleep(time.Millisecond)
		}
	}
	got := make(chan func(), 1)
	go func() {
		r, err := c.AcquireMutation(t.Context())
		if err != nil {
			t.Error(err)
			got <- nil
			return
		}
		got <- r
	}()
	waitFor(1)
	release()
	r := <-got
	if r == nil {
		t.FailNow()
	}
	if n := c.MutationWaiters(); n != 0 {
		t.Fatalf("waiters after hand-off = %d", n)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := c.AcquireMutation(ctx)
		done <- err
	}()
	waitFor(1)
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled waiter: %v", err)
	}
	if n := c.MutationWaiters(); n != 0 {
		t.Fatalf("waiters after cancel = %d", n)
	}
	r()
	var nilCoord *Coordinator
	if nilCoord.MutationWaiters() != 0 {
		t.Fatal("nil coordinator waiters")
	}
}
