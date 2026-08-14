package app

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
	"github.com/hilather/go-lab-ldap-mcp/internal/reset"
)

const seedAlice = "seed-alice-pass-12"

func resetter() Principal {
	return Principal{Kind: KindToken, ID: "admin", Scopes: directory.ScopeSet{
		"lab:reset", "directory:read", "directory:write", "directory:password",
	}}
}

type liveReset struct {
	mu       sync.Mutex
	users    *fakeUsers
	groups   *fakeGroups
	extras   []string
	preserve []string
	people   string
	groupsDN string
	runtime  string
	marker   string
	deleted  []string
	block    chan struct{}
	unblock  chan struct{}
}

func newLiveReset(users *fakeUsers, groups *fakeGroups) *liveReset {
	return &liveReset{
		users:    users,
		groups:   groups,
		people:   "ou=people,dc=example,dc=test",
		groupsDN: "ou=groups,dc=example,dc=test",
		runtime:  "uid=rt,ou=people,dc=example,dc=test",
		marker:   "cn=labldap-baseline,dc=example,dc=test",
		preserve: []string{
			"uid=rt,ou=people,dc=example,dc=test",
			"ou=people,dc=example,dc=test",
			"ou=groups,dc=example,dc=test",
			"cn=labldap-baseline,dc=example,dc=test",
		},
	}
}

func (f *liveReset) Inventory(context.Context) (directory.ManagedInventory, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	inv := directory.ManagedInventory{Preserve: append([]string(nil), f.preserve...)}
	if f.users != nil {
		f.users.mu.Lock()
		for _, u := range f.users.byID {
			dn := u.DN
			if dn == "" {
				dn = "uid=" + u.ID + "," + f.people
			}
			inv.Users = append(inv.Users, dn)
		}
		f.users.mu.Unlock()
	}
	if f.groups != nil {
		f.groups.mu.Lock()
		for _, g := range f.groups.byID {
			dn := g.DN
			if dn == "" {
				dn = "cn=" + g.ID + "," + f.groupsDN
			}
			inv.Groups = append(inv.Groups, dn)
		}
		f.groups.mu.Unlock()
	}
	inv.Extra = append([]string(nil), f.extras...)
	return inv, nil
}

func (f *liveReset) DeleteManaged(_ context.Context, dn string) error {
	f.mu.Lock()
	block, unblock := f.block, f.unblock
	f.block, f.unblock = nil, nil
	f.mu.Unlock()
	if block != nil {
		block <- struct{}{}
		if unblock != nil {
			<-unblock
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.preserve {
		if strings.EqualFold(p, dn) {
			return directory.Error("dn", directory.FieldForbidden, "protected directory entry cannot be deleted")
		}
	}
	low := strings.ToLower(dn)
	if !strings.Contains(low, "ou=people,") && !strings.Contains(low, "ou=groups,") {
		return directory.Error("dn", directory.FieldForbidden, "delete is outside managed containers")
	}
	var kept []string
	for _, e := range f.extras {
		if !strings.EqualFold(e, dn) {
			kept = append(kept, e)
		}
	}
	f.extras = kept
	leaf := dn
	if i := strings.Index(dn, ","); i > 0 {
		leaf = dn[:i]
	}
	if _, v, ok := strings.Cut(leaf, "="); ok {
		leaf = v
	}
	if f.users != nil {
		f.users.mu.Lock()
		delete(f.users.byID, directory.UserID(leaf))
		f.users.mu.Unlock()
	}
	if f.groups != nil {
		f.groups.mu.Lock()
		delete(f.groups.byID, directory.GroupID(leaf))
		f.groups.mu.Unlock()
	}
	f.deleted = append(f.deleted, dn)
	return nil
}

func (f *liveReset) Export(context.Context, io.Writer, directory.ExportOptions) error {
	return nil
}

func seedAliceUser() config.NormalizedUser {
	sec := config.ResolvedSecret{Path: "alice.pw", Value: observability.Secret(seedAlice)}
	return config.NormalizedUser{
		ID: "alice", UID: "alice", DN: "uid=alice,ou=people,dc=example,dc=test",
		Enabled: true, Password: &sec,
		Attributes: []config.AttrKV{{Name: "sn", Value: "Example"}},
	}
}

func seedStaff() config.NormalizedGroup {
	return config.NormalizedGroup{
		ID: "staff", DN: "cn=staff,ou=groups,dc=example,dc=test",
		Members: []config.MemberRef{{Kind: "user", ID: "alice", DN: "uid=alice,ou=people,dc=example,dc=test"}},
	}
}

func resetDeps(users *fakeUsers, groups *fakeGroups, inv *liveReset, gate *reset.Gate) Deps {
	alice := seedAliceUser()
	staff := seedStaff()
	return Deps{
		Users: users, Groups: groups, Bind: fakeBind{res: directory.BindTestResult{Outcome: directory.BindOutcomeSuccess}},
		Marker:           fakeMarker{m: directory.BaselineMarker{AppliedRevision: "rev-dir", DN: "cn=labldap-baseline,dc=example,dc=test"}},
		Gate:             gate,
		ResetLock:        gate,
		ResetDir:         inv,
		Secrets:          config.MapResolver{"alice.pw": seedAlice},
		SoftReset:        true,
		ScenarioName:     "lab",
		ExpectedRevision: "rev-dir",
		PeopleDN:         inv.people,
		GroupsDN:         inv.groupsDN,
		Suffix:           "dc=example,dc=test",
		RuntimeDN:        inv.runtime,
		MarkerDN:         inv.marker,
		ResetUsers:       []config.NormalizedUser{alice},
		ResetGroups:      []config.NormalizedGroup{staff},
	}
}

func TestResetRequiresLabResetScope(t *testing.T) {
	t.Parallel()
	users, groups := newFakeUsers(), newFakeGroups()
	inv := newLiveReset(users, groups)
	svc := New(resetDeps(users, groups, inv, reset.NewGate()))
	_, err := svc.Reset.Start(t.Context(), writer(), ResetRequest{Name: "lab", ExpectedRevision: "rev-dir"})
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuth {
		t.Fatalf("want auth: %v", err)
	}
}

func TestResetDisabledWhenSoftResetFalse(t *testing.T) {
	t.Parallel()
	users, groups := newFakeUsers(), newFakeGroups()
	inv := newLiveReset(users, groups)
	d := resetDeps(users, groups, inv, reset.NewGate())
	d.SoftReset = false
	svc := New(d)
	_, err := svc.Reset.Start(t.Context(), resetter(), ResetRequest{Name: "lab", ExpectedRevision: "rev-dir"})
	if err == nil {
		t.Fatal("disabled")
	}
	apperr.Assert(t, err).Code(apperr.CodeReset)
	if fieldCode(err) != "disabled" {
		t.Fatalf("field %s", fieldCode(err))
	}
}

func TestResetRefusesMissingSeedFilesBeforeDelete(t *testing.T) {
	t.Parallel()
	users, groups := newFakeUsers(), newFakeGroups()
	inv := newLiveReset(users, groups)
	inv.extras = []string{"uid=runtime-extra,ou=people,dc=example,dc=test"}
	d := resetDeps(users, groups, inv, reset.NewGate())
	d.Secrets = config.MapResolver{}
	d.ResetUsers[0].Password = &config.ResolvedSecret{Path: "/no/such/labldap-seed"}
	svc := New(d)
	_, err := svc.Reset.Start(t.Context(), resetter(), ResetRequest{Name: "lab", ExpectedRevision: "rev-dir"})
	if err == nil {
		t.Fatal("seed")
	}
	if fieldCode(err) != "secret_unreadable" {
		t.Fatalf("want secret_unreadable got %s %v", fieldCode(err), err)
	}
	if len(inv.deleted) != 0 {
		t.Fatalf("deleted before refuse: %v", inv.deleted)
	}
	if svc.Reset.State() != string(reset.Ready) && svc.Reset.State() != string(reset.Failed) {
		t.Fatalf("state %s", svc.Reset.State())
	}
}

func TestResetReappliesBaselineAndDropsExtras(t *testing.T) {
	t.Parallel()
	users, groups := newFakeUsers(), newFakeGroups()
	users.put(directory.User{ID: "alice", UID: "alice", DN: "uid=alice,ou=people,dc=example,dc=test", Enabled: true})
	users.put(directory.User{ID: "runtime-extra", UID: "runtime-extra", DN: "uid=runtime-extra,ou=people,dc=example,dc=test"})
	groups.put(directory.Group{ID: "staff", DN: "cn=staff,ou=groups,dc=example,dc=test", Members: []directory.MemberRef{{Kind: "user", ID: "runtime-extra"}}})
	inv := newLiveReset(users, groups)
	inv.extras = []string{"uid=runtime-extra,ou=people,dc=example,dc=test"}
	gate := reset.NewGate()
	svc := New(resetDeps(users, groups, inv, gate))
	st, err := svc.Reset.Start(t.Context(), resetter(), ResetRequest{Name: "lab", ExpectedRevision: "rev-dir"})
	if err != nil {
		t.Fatal(err)
	}
	if st.ExpectedRevision != st.AppliedRevision || st.ExpectedRevision != "rev-dir" {
		t.Fatalf("revisions %+v", st)
	}
	if st.State != string(reset.Ready) || st.Phase != string(reset.Ready) {
		t.Fatalf("status %+v", st)
	}
	if _, err := users.Get(t.Context(), "runtime-extra"); err == nil {
		t.Fatal("extra user remains")
	}
	if _, err := users.Get(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	if users.passwords["alice"] != seedAlice {
		t.Fatalf("seed password not applied")
	}
	g, err := groups.Get(t.Context(), "staff")
	if err != nil || len(g.Members) != 1 || g.Members[0].ID != "alice" {
		t.Fatalf("staff %+v %v", g, err)
	}
	for _, dn := range inv.deleted {
		if strings.Contains(dn, "uid=rt,") || strings.Contains(dn, "labldap-baseline") {
			t.Fatalf("protected deleted %s", dn)
		}
	}
}

func TestResetExclusiveAndBlocksWrites(t *testing.T) {
	t.Parallel()
	users, groups := newFakeUsers(), newFakeGroups()
	users.put(directory.User{ID: "alice", UID: "alice", DN: "uid=alice,ou=people,dc=example,dc=test", Enabled: true})
	inv := newLiveReset(users, groups)
	block := make(chan struct{}, 1)
	unblock := make(chan struct{})
	inv.block = block
	inv.unblock = unblock
	gate := reset.NewGate()
	svc := New(resetDeps(users, groups, inv, gate))
	errc := make(chan error, 1)
	go func() {
		_, err := svc.Reset.Start(t.Context(), resetter(), ResetRequest{Name: "lab", ExpectedRevision: "rev-dir"})
		errc <- err
	}()
	<-block
	_, err := svc.Reset.Start(t.Context(), resetter(), ResetRequest{Name: "lab", ExpectedRevision: "rev-dir"})
	if err == nil {
		t.Fatal("second reset")
	}
	apperr.Assert(t, err).Code(apperr.CodeReset).Retryable(true)
	_, err = svc.Users.Create(t.Context(), writer(), CreateUser{ID: "bob", Password: Secret("unit-user-pass-12")})
	if err == nil {
		t.Fatal("write during reset")
	}
	apperr.Assert(t, err).Code(apperr.CodeReset).Retryable(true)
	close(unblock)
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func TestResetVerificationDoesNotWriteMarker(t *testing.T) {
	t.Parallel()
	users, groups := newFakeUsers(), newFakeGroups()
	inv := newLiveReset(users, groups)
	mark := fakeMarker{m: directory.BaselineMarker{AppliedRevision: "rev-dir"}}
	d := resetDeps(users, groups, inv, reset.NewGate())
	d.Marker = mark
	svc := New(d)
	st, err := svc.Reset.Start(t.Context(), resetter(), ResetRequest{Name: "lab", ExpectedRevision: "rev-dir"})
	if err != nil {
		t.Fatal(err)
	}
	if st.AppliedRevision != "rev-dir" {
		t.Fatalf("%+v", st)
	}
	got, err := mark.ReadMarker(t.Context())
	if err != nil || got.AppliedRevision != "rev-dir" {
		t.Fatalf("marker mutated %+v %v", got, err)
	}
}

func TestResetFailureInjectionAndUnresolvedNotReady(t *testing.T) {
	t.Parallel()
	for _, phase := range []string{reset.PhaseDeleteGroups, reset.PhaseDeleteUsers, reset.PhaseDeleteExtra, reset.PhaseReapplyUsers, reset.PhaseVerify} {
		phase := phase
		t.Run(phase, func(t *testing.T) {
			t.Parallel()
			users, groups := newFakeUsers(), newFakeGroups()
			users.put(directory.User{ID: "alice", UID: "alice", DN: "uid=alice,ou=people,dc=example,dc=test", Enabled: true})
			groups.put(directory.Group{ID: "staff", DN: "cn=staff,ou=groups,dc=example,dc=test", Members: []directory.MemberRef{{Kind: "user", ID: "alice"}}})
			inv := newLiveReset(users, groups)
			inv.extras = []string{"uid=runtime-extra,ou=people,dc=example,dc=test"}
			gate := reset.NewGate()
			svc := New(resetDeps(users, groups, inv, gate))
			svc.Reset.SetFailPoint(phase)
			_, err := svc.Reset.Start(t.Context(), resetter(), ResetRequest{Name: "lab", ExpectedRevision: "rev-dir"})
			if err == nil {
				t.Fatal("injected")
			}
			if svc.Reset.State() != string(reset.Failed) {
				t.Fatalf("state %s", svc.Reset.State())
			}
			st := svc.Reset.Status()
			if st.Recovery == "" || strings.Contains(strings.ToLower(st.Recovery+st.Error), "password") {
				t.Fatalf("recovery %+v", st)
			}
			probe := &Probe{
				Ping:       func(context.Context) error { return nil },
				Marker:     fakeMarker{m: directory.BaselineMarker{AppliedRevision: "rev-dir"}},
				Caps:       fakeCaps{caps: directory.Capabilities{RequiredOK: true}},
				Expected:   "rev-dir",
				ResetState: svc.Reset.State,
				BaselineOK: svc.Reset.BaselinePresent,
			}
			d := probe.Evaluate(t.Context())
			if d.Ready {
				t.Fatalf("false ready after %s: %+v", phase, d)
			}
		})
	}
}

func TestResetRecoversPartialState(t *testing.T) {
	t.Parallel()
	users, groups := newFakeUsers(), newFakeGroups()
	users.put(directory.User{ID: "runtime-extra", UID: "runtime-extra", DN: "uid=runtime-extra,ou=people,dc=example,dc=test"})
	inv := newLiveReset(users, groups)
	inv.extras = []string{"uid=runtime-extra,ou=people,dc=example,dc=test"}
	gate := reset.NewGate()
	svc := New(resetDeps(users, groups, inv, gate))
	insp := svc.Reset.Inspect(t.Context())
	if insp.State != string(reset.Failed) || insp.Recovery == "" {
		t.Fatalf("inspect %+v", insp)
	}
	probe := &Probe{
		Ping:       func(context.Context) error { return nil },
		Marker:     fakeMarker{m: directory.BaselineMarker{AppliedRevision: "rev-dir"}},
		Caps:       fakeCaps{caps: directory.Capabilities{RequiredOK: true}},
		Expected:   "rev-dir",
		ResetState: svc.Reset.State,
		BaselineOK: svc.Reset.BaselinePresent,
	}
	if probe.Evaluate(t.Context()).Ready {
		t.Fatal("unresolved ready")
	}
	if _, err := svc.Reset.Start(t.Context(), resetter(), ResetRequest{Name: "lab", ExpectedRevision: "rev-dir"}); err != nil {
		t.Fatal(err)
	}
	if _, err := users.Get(t.Context(), "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := users.Get(t.Context(), "runtime-extra"); err == nil {
		t.Fatal("extra remains")
	}
	if !svc.Reset.BaselinePresent(t.Context()) {
		t.Fatal("baseline")
	}
	if !probe.Evaluate(t.Context()).Ready {
		t.Fatalf("ready after recover: %+v", probe.Evaluate(t.Context()))
	}
	raw, _ := json.Marshal(svc.Reset.Status())
	if hasSecret(string(raw), seedAlice) {
		t.Fatalf("status leaked seed: %s", raw)
	}
}

func TestResetCancelBeforeMutationReleasesGate(t *testing.T) {
	t.Parallel()
	users, groups := newFakeUsers(), newFakeGroups()
	inv := newLiveReset(users, groups)
	svc := New(resetDeps(users, groups, inv, reset.NewGate()))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := svc.Reset.Start(ctx, resetter(), ResetRequest{Name: "lab", ExpectedRevision: "rev-dir"})
	if err == nil {
		t.Fatal("canceled")
	}
	if svc.Reset.State() != string(reset.Ready) {
		t.Fatalf("state %s", svc.Reset.State())
	}
	if len(inv.deleted) != 0 {
		t.Fatalf("deleted %v", inv.deleted)
	}
}

func TestResetWrongNameOrRevisionFailsClosed(t *testing.T) {
	t.Parallel()
	users, groups := newFakeUsers(), newFakeGroups()
	inv := newLiveReset(users, groups)
	svc := New(resetDeps(users, groups, inv, reset.NewGate()))
	if _, err := svc.Reset.Start(t.Context(), resetter(), ResetRequest{Name: "other", ExpectedRevision: "rev-dir"}); err == nil {
		t.Fatal("name")
	}
	if _, err := svc.Reset.Start(t.Context(), resetter(), ResetRequest{Name: "lab", ExpectedRevision: "nope"}); err == nil {
		t.Fatal("rev")
	}
	if len(inv.deleted) != 0 {
		t.Fatalf("mutated %v", inv.deleted)
	}
}
