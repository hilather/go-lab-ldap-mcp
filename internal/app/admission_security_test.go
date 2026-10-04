package app

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/reset"
)

func TestCoordinatorReclaimsKeysWithoutSplittingWaiters(t *testing.T) {
	c := NewCoordinator()
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			for i := range 100 {
				release := c.Lock(fmt.Sprintf("user:%d", i))
				release()
			}
		})
	}
	wg.Wait()
	if len(c.locks) != 0 {
		t.Fatalf("retained %d idle keys", len(c.locks))
	}
}

func TestWindowReclaimsExpiredKeysAndBoundsLiveKeys(t *testing.T) {
	w := NewWindow(1, 1, 1, 1)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	w.now = func() time.Time { return now }
	for i := range maxRateLimitKeys {
		if err := w.Allow(t.Context(), fmt.Sprint(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Allow(t.Context(), "overflow"); err == nil {
		t.Fatal("unbounded key admission")
	}
	now = now.Add(time.Minute)
	if err := w.Allow(t.Context(), "fresh"); err != nil {
		t.Fatal(err)
	}
	if len(w.hits) != 1 {
		t.Fatalf("retained %d expired keys", len(w.hits)-1)
	}
}

func TestResetRejectsChangedSeedBeforeMutation(t *testing.T) {
	users, groups := newFakeUsers(), newFakeGroups()
	inv := newLiveReset(users, groups)
	d := resetDeps(users, groups, inv, reset.NewGate())
	d.Secrets = config.MapResolver{"alice.pw": "updated-secret-value"}
	svc := New(d)
	_, err := svc.Reset.Start(t.Context(), resetter(), ResetRequest{Name: "lab", ExpectedRevision: "rev-dir"})
	if fieldCode(err) != directory.FieldConflict {
		t.Fatalf("changed seed: %v", err)
	}
	if len(inv.deleted) != 0 || svc.Reset.State() != string(reset.Ready) {
		t.Fatal("changed baseline reached mutation")
	}
	if strings.Contains(err.Error(), "updated-secret-value") {
		t.Fatal("secret leaked")
	}
}

type blockedAddUsers struct {
	*fakeUsers
	entered chan struct{}
	release chan struct{}
}

func (u *blockedAddUsers) Add(ctx context.Context, spec directory.UserSpec) (directory.User, error) {
	close(u.entered)
	<-u.release
	return u.fakeUsers.Add(ctx, spec)
}
func TestResetDrainsAdmittedWriteBeforeInventory(t *testing.T) {
	users, groups := newFakeUsers(), newFakeGroups()
	inv := newLiveReset(users, groups)
	d := resetDeps(users, groups, inv, reset.NewGate())
	blocked := &blockedAddUsers{fakeUsers: users, entered: make(chan struct{}), release: make(chan struct{})}
	d.Users = blocked
	svc := New(d)
	created := make(chan error, 1)
	go func() {
		_, err := svc.Users.Create(t.Context(), writer(), CreateUser{ID: "bob", Password: Secret("unit-user-pass-12")})
		created <- err
	}()
	<-blocked.entered
	// Reapplication must use the unblocked repository once the admitted write drains.
	svc.Reset.users = users
	resetDone := make(chan error, 1)
	go func() {
		_, err := svc.Reset.Start(t.Context(), resetter(), ResetRequest{Name: "lab", ExpectedRevision: "rev-dir"})
		resetDone <- err
	}()
	deadline := time.After(time.Second)
	for svc.Reset.State() != string(reset.PreparingReset) {
		select {
		case <-deadline:
			t.Fatal("reset never closed admission")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	inv.mu.Lock()
	deleted := len(inv.deleted)
	inv.mu.Unlock()
	if deleted != 0 {
		t.Fatal("reset mutated with admitted write still active")
	}
	close(blocked.release)
	if err := <-created; err != nil {
		t.Fatal(err)
	}
	if err := <-resetDone; err != nil {
		t.Fatal(err)
	}
	if _, err := users.Get(t.Context(), "bob"); fieldCode(err) != directory.FieldNotFound {
		t.Fatalf("admitted runtime extra survived reset: %v", err)
	}
}

func TestSearchRedactsSecretOptionsAndOIDs(t *testing.T) {
	for _, name := range []string{"userPassword;binary", "2.5.4.35", "authPassword", "1.3.6.1.4.1.4203.1.3.4", "2.16.840.1.113730.3.1.216;binary", "userPKCS12;binary", "nsMultiplexorCredentials;binary"} {
		if got := redactAttrs([]directory.AttrKV{{Name: name, Value: "secret"}}); len(got) != 0 {
			t.Fatalf("exposed %s", name)
		}
	}
}

func TestStructuredForbiddenAttributeIsAuditedWithoutSecret(t *testing.T) {
	audit := &MemoryAuditor{}
	svc := New(Deps{Entries: newFakeEntries(), Audit: audit})
	const secret = "unit-secret-must-not-enter-audit"
	_, err := svc.Entries.Create(t.Context(), writer(), directory.EntrySpec{DN: "ou=lab,dc=test", Attributes: map[string]string{"userPassword;binary": secret}})
	if err == nil {
		t.Fatal("forbidden create succeeded")
	}
	_, err = svc.Entries.Update(t.Context(), writer(), directory.EntryPatch{DN: "ou=lab,dc=test", Revision: "rev", Changes: []directory.EntryChange{{Name: "2.5.4.35", Op: "replace", Values: []string{secret}}}})
	if err == nil {
		t.Fatal("forbidden update succeeded")
	}
	events := audit.Snapshot()
	if len(events) != 2 {
		t.Fatalf("missing audit failure: %+v", events)
	}
	for _, ev := range events {
		if ev.Result != AuditFailure || strings.Contains(fmt.Sprint(ev), secret) {
			t.Fatalf("unsafe audit: %+v", ev)
		}
	}
}
