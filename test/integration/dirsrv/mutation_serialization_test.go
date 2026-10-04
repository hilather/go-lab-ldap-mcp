//go:build integration

package dirsrv

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

func TestControlMutationsSerializeAliasesAndServiceSurfaces(t *testing.T) {
	rt := startControlReviewRuntime(t)
	locks := app.NewCoordinator()
	svc := app.New(app.Deps{Users: rt.Users(), Entries: rt, Locks: locks})
	principal := app.Principal{Kind: app.KindToken, ID: "writer", Scopes: directory.ScopeSet{"directory:write"}}
	for _, mixed := range []bool{false, true} {
		name := "DN-alias"
		if mixed {
			name = "user-and-entry"
		}
		t.Run(name, func(t *testing.T) {
			ent, err := rt.GetEntryMeta(t.Context(), "uid=alice,ou=people,dc=example,dc=test")
			if err != nil {
				t.Fatal(err)
			}
			user, err := rt.Users().Get(t.Context(), "alice")
			if err != nil {
				t.Fatal(err)
			}
			entered := make(chan struct{}, 2)
			resume := make(chan struct{})
			var hits atomic.Int32
			rt.SetAfterSearch(func(context.Context, string) { hits.Add(1); entered <- struct{}{}; <-resume })
			defer rt.SetAfterSearch(nil)
			defer func() {
				select {
				case <-resume:
				default:
					close(resume)
				}
			}()
			first := make(chan error, 1)
			second := make(chan error, 1)
			go func() {
				_, err := svc.Entries.Update(t.Context(), principal, directory.EntryPatch{DN: ent.DN, Revision: ent.Revision, Changes: []directory.EntryChange{{Name: "cn", Op: "replace", Values: []string{"First " + name}}}})
				first <- err
			}()
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
				t.Fatal("first mutation never reached revision boundary")
			}
			started := make(chan struct{})
			go func() {
				close(started)
				var err error
				if mixed {
					_, err = svc.Users.Update(t.Context(), principal, "alice", app.UpdateUser{Revision: user.Revision, UserPatch: directory.UserPatch{Attributes: map[string]string{"cn": "Second " + name}}})
				} else {
					_, err = svc.Entries.Update(t.Context(), principal, directory.EntryPatch{DN: `uid=\61lice,ou=people,dc=example,dc=test`, Revision: ent.Revision, Changes: []directory.EntryChange{{Name: "cn", Op: "replace", Values: []string{"Second " + name}}}})
				}
				second <- err
			}()
			<-started
			// Positive proof, not a timing window: the first caller holds the
			// shared mutation lease while parked at the revision boundary, so
			// the second caller is observed waiting on that lease.
			deadline := time.After(10 * time.Second)
			for locks.MutationWaiters() != 1 {
				select {
				case <-entered:
					t.Fatal("second mutation passed stale check before first committed")
				case err := <-second:
					t.Fatalf("second mutation completed before first: %v", err)
				case <-deadline:
					t.Fatalf("second mutation never blocked on the mutation lease (waiters=%d)", locks.MutationWaiters())
				case <-time.After(time.Millisecond):
				}
			}
			select {
			case <-entered:
				t.Fatal("second mutation passed stale check before first committed")
			case err := <-second:
				t.Fatalf("second mutation completed before first: %v", err)
			default:
			}
			close(resume)
			if err := <-first; err != nil {
				t.Fatal(err)
			}
			assertControlRevisionConflict(t, <-second)
			if hits.Load() != 1 {
				t.Fatalf("stale mutation reached write boundary: %d", hits.Load())
			}
			final, err := rt.Users().Get(t.Context(), "alice")
			if err != nil {
				t.Fatal(err)
			}
			var cn string
			for _, attr := range final.Attributes {
				if attr.Name == "cn" {
					cn = attr.Value
				}
			}
			if cn != "First "+name {
				t.Fatalf("stale mutation replaced value: %q", cn)
			}
		})
	}
}
