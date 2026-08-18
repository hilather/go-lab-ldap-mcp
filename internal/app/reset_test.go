package app

import (
	"context"
	"encoding/json"
	"io"
	"sort"
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

func failResetAt(s *Reset, phase string) {
	if s == nil {
		return
	}
	if s.inject == nil {
		s.inject = &reset.Injector{}
	}
	s.inject.Set(phase)
}

type recBind struct {
	mu   sync.Mutex
	got  directory.Transport
	uids []string
	res  directory.BindTestResult
	fail map[string]directory.BindTestResult
}

func (r *recBind) BindTest(_ context.Context, uid string, _ observability.Secret, t directory.Transport) (directory.BindTestResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = t
	r.uids = append(r.uids, uid)
	if r.fail != nil {
		if res, ok := r.fail[uid]; ok {
			return res, nil
		}
	}
	return r.res, nil
}

type writeCountMarker struct {
	fakeMarker
	writes int
}

func (w *writeCountMarker) WriteMarker(context.Context) { w.writes++ }

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

func (f *liveReset) Export(ctx context.Context, w io.Writer, opts directory.ExportOptions) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	enc := directory.NewEncoder(w, opts)
	f.mu.Lock()
	users, groups := f.users, f.groups
	f.mu.Unlock()
	if users != nil {
		users.mu.Lock()
		ids := make([]string, 0, len(users.byID))
		for id := range users.byID {
			ids = append(ids, string(id))
		}
		users.mu.Unlock()
		sort.Strings(ids)
		for _, id := range ids {
			if err := ctx.Err(); err != nil {
				return err
			}
			u, err := users.Get(ctx, directory.UserID(id))
			if err != nil {
				continue
			}
			attrs := append([]directory.AttrKV{{Name: "uid", Value: u.UID}, {Name: "objectClass", Value: "inetOrgPerson"}}, u.Attributes...)
			if err := enc.WriteEntry(ctx, directory.SearchEntry{DN: u.DN, Attributes: attrs}); err != nil {
				return err
			}
		}
	}
	if groups != nil {
		groups.mu.Lock()
		ids := make([]string, 0, len(groups.byID))
		for id := range groups.byID {
			ids = append(ids, string(id))
		}
		groups.mu.Unlock()
		sort.Strings(ids)
		for _, id := range ids {
			if err := ctx.Err(); err != nil {
				return err
			}
			g, err := groups.Get(ctx, directory.GroupID(id))
			if err != nil {
				continue
			}
			attrs := []directory.AttrKV{{Name: "cn", Value: g.ID}, {Name: "objectClass", Value: "groupOfNames"}}
			for _, m := range g.Members {
				attrs = append(attrs, directory.AttrKV{Name: "member", Value: m.DN})
			}
			if err := enc.WriteEntry(ctx, directory.SearchEntry{DN: g.DN, Attributes: attrs}); err != nil {
				return err
			}
		}
	}
	return enc.Close()
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
	st, err := svc.Reset.Start(t.Context(), writer(), ResetRequest{Name: "lab", ExpectedRevision: "rev-dir"})
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuth {
		t.Fatalf("want auth: %v", err)
	}
	if st != (ResetStatus{}) {
		t.Fatalf("auth failure leaked reset status: %+v", st)
	}
}

func TestBindCheckRequiresEverySeedUser(t *testing.T) {
	t.Parallel()
	bind := &recBind{
		res: directory.BindTestResult{Outcome: directory.BindOutcomeSuccess},
		fail: map[string]directory.BindTestResult{
			"bob": {Outcome: directory.BindOutcomeInvalidCredentials},
		},
	}
	s := &Reset{bind: bind}
	pw := &config.ResolvedSecret{Value: observability.Secret("seed-pass-12")}
	err := s.bindCheck(t.Context(), []config.NormalizedUser{
		{UID: "alice", Enabled: true, Password: pw},
		{UID: "bob", Enabled: true, Password: pw},
	})
	if err == nil {
		t.Fatal("expected bind failure for later seed user")
	}
	bind.mu.Lock()
	defer bind.mu.Unlock()
	if len(bind.uids) != 2 {
		t.Fatalf("bind-check stopped early: %v", bind.uids)
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
	apperr.Assert(t, err).Code(apperr.CodeReset).Retryable(false)
	if fieldCode(err) != "conflict" {
		t.Fatalf("duplicate field %s %v", fieldCode(err), err)
	}
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
	mark := &writeCountMarker{fakeMarker: fakeMarker{m: directory.BaselineMarker{AppliedRevision: "rev-dir"}}}
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
	if err != nil || got.AppliedRevision != "rev-dir" || mark.writes != 0 {
		t.Fatalf("marker mutated %+v writes=%d %v", got, mark.writes, err)
	}
	var _ directory.MarkerReader = mark
}

func TestResetFailureInjectionAndUnresolvedNotReady(t *testing.T) {
	t.Parallel()
	for _, phase := range []string{reset.PhaseDeleteGroups, reset.PhaseDeleteUsers, reset.PhaseDeleteExtra, reset.PhaseReapplyUsers, reset.PhaseReapplyGroups, reset.PhaseVerify} {
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
			failResetAt(svc.Reset, phase)
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
			if phase == reset.PhaseReapplyGroups {
				if _, err := svc.Reset.Start(t.Context(), resetter(), ResetRequest{Name: "lab", ExpectedRevision: "rev-dir"}); err != nil {
					t.Fatal(err)
				}
				if _, err := groups.Get(t.Context(), "staff"); err != nil {
					t.Fatal(err)
				}
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

func TestResetClientCancelAfterDeleteDoesNotFail(t *testing.T) {
	t.Parallel()
	users, groups := newFakeUsers(), newFakeGroups()
	users.put(directory.User{ID: "alice", UID: "alice", DN: "uid=alice,ou=people,dc=example,dc=test", Enabled: true})
	inv := newLiveReset(users, groups)
	inv.extras = []string{"uid=runtime-extra,ou=people,dc=example,dc=test"}
	block := make(chan struct{}, 1)
	unblock := make(chan struct{})
	inv.block = block
	inv.unblock = unblock
	svc := New(resetDeps(users, groups, inv, reset.NewGate()))
	ctx, cancel := context.WithCancel(t.Context())
	errc := make(chan error, 1)
	go func() {
		_, err := svc.Reset.Start(ctx, resetter(), ResetRequest{Name: "lab", ExpectedRevision: "rev-dir"})
		errc <- err
	}()
	<-block
	cancel()
	close(unblock)
	if err := <-errc; err != nil {
		t.Fatalf("cancel after mutation started: %v", err)
	}
	if svc.Reset.State() != string(reset.Ready) {
		t.Fatalf("state %s", svc.Reset.State())
	}
}

func TestResetWrongConfirmationDoesNotConsumeRateLimit(t *testing.T) {
	t.Parallel()
	users, groups := newFakeUsers(), newFakeGroups()
	inv := newLiveReset(users, groups)
	d := resetDeps(users, groups, inv, reset.NewGate())
	d.Limit = NewWindow(0, 0, 0, 1)
	svc := New(d)
	for i := 0; i < 3; i++ {
		if _, err := svc.Reset.Start(t.Context(), resetter(), ResetRequest{Name: "other", ExpectedRevision: "rev-dir"}); err == nil {
			t.Fatal("name")
		}
	}
	if _, err := svc.Reset.Start(t.Context(), resetter(), ResetRequest{Name: "lab", ExpectedRevision: "rev-dir"}); err != nil {
		t.Fatalf("valid reset after failed confirmations: %v", err)
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

func TestResetBindUsesConfiguredTransport(t *testing.T) {
	t.Parallel()
	users, groups := newFakeUsers(), newFakeGroups()
	inv := newLiveReset(users, groups)
	bind := &recBind{res: directory.BindTestResult{Outcome: directory.BindOutcomeSuccess}}
	d := resetDeps(users, groups, inv, reset.NewGate())
	d.Bind = bind
	d.BindTransport = directory.TransportStartTLS
	svc := New(d)
	if _, err := svc.Reset.Start(t.Context(), resetter(), ResetRequest{Name: "lab", ExpectedRevision: "rev-dir"}); err != nil {
		t.Fatal(err)
	}
	bind.mu.Lock()
	got := bind.got
	bind.mu.Unlock()
	if got != directory.TransportStartTLS {
		t.Fatalf("transport %q", got)
	}
}

func TestResetBlocksDirectoryReadsWhileMutating(t *testing.T) {
	t.Parallel()
	users, groups := newFakeUsers(), newFakeGroups()
	users.put(directory.User{ID: "alice", UID: "alice", DN: "uid=alice,ou=people,dc=example,dc=test", Enabled: true})
	inv := newLiveReset(users, groups)
	block := make(chan struct{}, 1)
	unblock := make(chan struct{})
	inv.block = block
	inv.unblock = unblock
	svc := New(resetDeps(users, groups, inv, reset.NewGate()))
	errc := make(chan error, 1)
	go func() {
		_, err := svc.Reset.Start(t.Context(), resetter(), ResetRequest{Name: "lab", ExpectedRevision: "rev-dir"})
		errc <- err
	}()
	<-block
	_, err := svc.Users.Get(t.Context(), writer(), "alice")
	if err == nil {
		t.Fatal("read during reset")
	}
	apperr.Assert(t, err).Code(apperr.CodeReset).Retryable(true)
	close(unblock)
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
}

func TestFailedResetBlocksWritesButAllowsReads(t *testing.T) {
	t.Parallel()
	users, groups := newFakeUsers(), newFakeGroups()
	users.put(directory.User{ID: "alice", UID: "alice", DN: "uid=alice,ou=people,dc=example,dc=test", Enabled: true})
	inv := newLiveReset(users, groups)
	gate := reset.NewGate()
	svc := New(resetDeps(users, groups, inv, gate))
	gate.Set(reset.Failed)
	_, err := svc.Users.Create(t.Context(), writer(), CreateUser{ID: "bob", Password: Secret("unit-user-pass-12")})
	if err == nil || fieldCode(err) != "reset_failed" {
		t.Fatalf("want reset_failed: %v", err)
	}
	if _, err := svc.Users.Get(t.Context(), writer(), "alice"); err != nil {
		t.Fatal(err)
	}
}

func TestInspectAllowsRuntimeExtras(t *testing.T) {
	t.Parallel()
	users, groups := newFakeUsers(), newFakeGroups()
	users.put(directory.User{ID: "alice", UID: "alice", DN: "uid=alice,ou=people,dc=example,dc=test", Enabled: true})
	groups.put(directory.Group{ID: "staff", DN: "cn=staff,ou=groups,dc=example,dc=test", Members: []directory.MemberRef{{Kind: "user", ID: "alice"}}})
	inv := newLiveReset(users, groups)
	inv.extras = []string{"uid=runtime-extra,ou=people,dc=example,dc=test"}
	svc := New(resetDeps(users, groups, inv, reset.NewGate()))
	insp := svc.Reset.Inspect(t.Context())
	if insp.State != string(reset.Ready) {
		t.Fatalf("merge extras must not fail inspect: %+v", insp)
	}
}

func TestBaselinePresentIgnoresTransportErrors(t *testing.T) {
	t.Parallel()
	users, groups := newFakeUsers(), newFakeGroups()
	users.getErr = directory.Error("connection", directory.FieldUnavailable, "directory unavailable")
	inv := newLiveReset(users, groups)
	svc := New(resetDeps(users, groups, inv, reset.NewGate()))
	if !svc.Reset.BaselinePresent(t.Context()) {
		t.Fatal("transport error must not look like missing baseline")
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
