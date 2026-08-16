package ldapserver

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// testNow is a fake clock for policy tests: no real sleeps, the test moves
// time explicitly (acceptance requirement).
type testNow struct {
	mu sync.Mutex
	t  time.Time
}

func newTestNow() *testNow {
	return &testNow{t: time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)}
}

func (n *testNow) Now() time.Time {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.t
}

func (n *testNow) Advance(d time.Duration) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.t = n.t.Add(d)
}

// fastHasher keeps policy tests quick; the format is iteration-agnostic.
func fastHasher(t *testing.T, scheme string) *StandardHasher {
	t.Helper()
	h, err := NewStandardHasher(scheme)
	if err != nil {
		t.Fatalf("NewStandardHasher: %v", err)
	}
	h.Iterations = 1_000
	return h
}

// policyOptions seeds the usual tree without alice's password: policy tests
// write credentials through the wire so hash-on-write runs.
func policyOptions(t *testing.T, clock *testNow, mutate func(*PasswordPolicy)) Options {
	t.Helper()
	opts := testOptions()
	opts.AllowCleartextBind = true
	opts.DirectoryManager = dmIdentity("dm-fixture-password")
	opts.Codec = NewBERCodec(BERCodecOptions{})
	// DM bypasses ACI; everyone else is denied. This mirrors the ACI
	// contract (aci.go: BypassACI subjects are allowed without evaluation).
	opts.ACI = &FakeACI{Decide: func(ctx context.Context, tx ReadTx, check ACICheck) (bool, error) {
		if check.Subject.BypassACI {
			return true, nil
		}
		// Bound users may write so self-service history tests are not
		// forced through Directory Manager (D29 skips history for DM).
		return !check.Subject.Anonymous && check.Subject.DN.String() != "", nil
	}}
	p := &PasswordPolicy{Now: clock.Now, Hasher: fastHasher(t, "")}
	if mutate != nil {
		mutate(p)
	}
	opts.PasswordPolicy = p
	// Policy tests deliberately fail many binds on one connection; keep the
	// per-connection auth budget (ADR-0009 decision 10) out of the way so
	// the policy lockout — not the connection guard — is what fires.
	opts.Limits.MaxAuthAttempts = 100
	ctx := context.Background()
	if err := opts.Store.Update(ctx, func(tx UpdateTx) error {
		for _, e := range []*Entry{
			NewEntry("dc=example,dc=test", StringAttribute("objectClass", "top", "domain")),
			NewEntry("ou=people,dc=example,dc=test", StringAttribute("objectClass", "top", "organizationalUnit")),
		} {
			if err := tx.Add(ctx, e); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return opts
}

func bindDM(t *testing.T, cl *ldapTestClient) {
	t.Helper()
	if res := bindResult(t, cl, "cn=Directory Manager", "dm-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("dm bind: %v", res)
	}
}

// addAlice creates the user over the wire as DM with a plaintext password.
func addAlice(t *testing.T, cl *ldapTestClient, password string) Result {
	t.Helper()
	id := cl.send(&AddRequest{
		DN: "uid=alice,ou=people,dc=example,dc=test",
		Attributes: []Attribute{
			StringAttribute("objectClass", "top", "person"),
			StringAttribute("uid", "alice"),
			StringAttribute("sn", "Adams"),
			StringAttribute("userPassword", password),
		},
	})
	m := cl.recv()
	if m.ID != id {
		t.Fatalf("response id = %d, want %d", m.ID, id)
	}
	resp, ok := m.Op.(*AddResponse)
	if !ok {
		t.Fatalf("op = %T, want AddResponse", m.Op)
	}
	return resp.Result
}

// setAlicePassword replaces userPassword over the wire as DM.
func setAlicePassword(t *testing.T, cl *ldapTestClient, password string) Result {
	t.Helper()
	id := cl.send(&ModifyRequest{
		DN: "uid=alice,ou=people,dc=example,dc=test",
		Changes: []ModifyChange{{
			Op:   ModifyReplace,
			Attr: Attribute{Name: "userPassword", Values: [][]byte{[]byte(password)}},
		}},
	})
	m := cl.recv()
	if m.ID != id {
		t.Fatalf("response id = %d, want %d", m.ID, id)
	}
	resp, ok := m.Op.(*ModifyResponse)
	if !ok {
		t.Fatalf("op = %T, want ModifyResponse", m.Op)
	}
	return resp.Result
}

func readAlice(t *testing.T, s *Server) *Entry {
	t.Helper()
	dn, err := config.ParseDN("uid=alice,ou=people,dc=example,dc=test")
	if err != nil {
		t.Fatalf("parse dn: %v", err)
	}
	var e *Entry
	if err := s.opts.Store.View(context.Background(), func(tx ReadTx) error {
		got, err := tx.Entry(context.Background(), dn)
		if err != nil {
			return err
		}
		e = got
		return nil
	}); err != nil {
		t.Fatalf("read alice: %v", err)
	}
	return e
}

func TestPolicySeedAddHashesAndBinds(t *testing.T) {
	t.Parallel()
	clock := newTestNow()
	opts := policyOptions(t, clock, nil)
	s, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	bindDM(t, cl)
	if res := addAlice(t, cl, "alice-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("add: %v", res)
	}

	entry := readAlice(t, s)
	vals := entry.Values("userPassword")
	if len(vals) != 1 {
		t.Fatalf("userPassword values = %d, want 1", len(vals))
	}
	if !strings.HasPrefix(string(vals[0]), "{PBKDF2-SHA256}") {
		t.Fatalf("stored userPassword lacks PBKDF2 prefix: %q", vals[0])
	}
	if strings.Contains(string(vals[0]), "alice-fixture-password") {
		t.Fatal("stored userPassword echoes plaintext")
	}
	changed := entry.Values("pwdChangedTime")
	if len(changed) != 1 || string(changed[0]) != "20260815120000Z" {
		t.Fatalf("pwdChangedTime = %v, want the fake clock's stamp", changed)
	}

	// The acceptance bind: plaintext against the stored hash.
	if res := bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "alice-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("bind with plaintext against hash = %v", res)
	}
	if res := bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "wrong"); res.Code != ResultInvalidCredentials {
		t.Fatalf("wrong bind = %v, want invalidCredentials", res)
	}
}

func TestPolicyMinLengthEnforcedOnWrite(t *testing.T) {
	t.Parallel()
	clock := newTestNow()
	opts := policyOptions(t, clock, func(p *PasswordPolicy) { p.MinLength = 12 })
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	bindDM(t, cl)

	if res := addAlice(t, cl, "short"); res.Code != ResultConstraintViolation {
		t.Fatalf("short add = %v, want constraintViolation (D18)", res)
	}
	if res := addAlice(t, cl, "long-enough-password"); res.Code != ResultSuccess {
		t.Fatalf("add = %v", res)
	}
	if res := setAlicePassword(t, cl, "tiny"); res.Code != ResultConstraintViolation {
		t.Fatalf("short modify = %v, want constraintViolation", res)
	}
	// The rejected change must not have landed: the old password still binds.
	if res := bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "long-enough-password"); res.Code != ResultSuccess {
		t.Fatalf("bind after rejected modify = %v", res)
	}
}

func TestPolicyHistoryRejectsReuse(t *testing.T) {
	t.Parallel()
	clock := newTestNow()
	opts := policyOptions(t, clock, func(p *PasswordPolicy) { p.HistoryCount = 4 })
	s, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	bindDM(t, cl)
	if res := addAlice(t, cl, "pw-one-aaaa"); res.Code != ResultSuccess {
		t.Fatalf("add: %v", res)
	}

	// Rotate A -> B as DM: allowed (and would also be allowed as self).
	if res := setAlicePassword(t, cl, "pw-two-bbbb"); res.Code != ResultSuccess {
		t.Fatalf("rotate A->B = %v", res)
	}
	entry := readAlice(t, s)
	if got := len(entry.Values("passwordHistory")); got != 1 {
		t.Fatalf("passwordHistory = %d values, want 1", got)
	}

	// History rejection is a non-DM (self) check: DM BypassACI skips it.
	if res := bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "pw-two-bbbb"); res.Code != ResultSuccess {
		t.Fatalf("alice bind B: %v", res)
	}
	// Reuse of A (now history) fails; the rejection aborts the commit, so B
	// still binds afterwards.
	if res := setAlicePassword(t, cl, "pw-one-aaaa"); res.Code != ResultConstraintViolation {
		t.Fatalf("reuse A = %v, want constraintViolation (D18)", res)
	}
	// Re-setting the current password is rejected with 19 (389 CAND-11).
	if res := setAlicePassword(t, cl, "pw-two-bbbb"); res.Code != ResultConstraintViolation {
		t.Fatalf("re-set current = %v, want constraintViolation (D20)", res)
	}
	if res := bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "pw-two-bbbb"); res.Code != ResultSuccess {
		t.Fatalf("bind B after rejections = %v", res)
	}
	if res := bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "pw-one-aaaa"); res.Code != ResultInvalidCredentials {
		t.Fatalf("bind A after rotation = %v, want invalidCredentials", res)
	}

	// A failed bind reset the connection to anonymous (RFC 4511 4.2.1).
	// Rotations that prove history eviction must run as self, not DM.
	if res := bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "pw-two-bbbb"); res.Code != ResultSuccess {
		t.Fatalf("re-bind alice: %v", res)
	}
	// History trims to HistoryCount: rotate through C,D,E,F and A drops off.
	for _, pw := range []string{"pw-c", "pw-d", "pw-e", "pw-f"} {
		if res := setAlicePassword(t, cl, pw); res.Code != ResultSuccess {
			t.Fatalf("rotate to %q = %v", pw, res)
		}
	}
	entry = readAlice(t, s)
	if got := len(entry.Values("passwordHistory")); got != 4 {
		t.Fatalf("passwordHistory = %d values, want trimmed to 4", got)
	}
	if res := setAlicePassword(t, cl, "pw-one-aaaa"); res.Code != ResultSuccess {
		t.Fatalf("reuse A after eviction = %v, want success (trimmed)", res)
	}
}

// TestPolicyDMBypassesHistory proves Directory Manager can re-apply a
// secret that is already in history (D29 / CAND-27). Minimum length still
// applies to DM writes (constraintViolation).
func TestPolicyDMBypassesHistory(t *testing.T) {
	t.Parallel()
	clock := newTestNow()
	opts := policyOptions(t, clock, func(p *PasswordPolicy) {
		p.HistoryCount = 4
		p.MinLength = 8
	})
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	bindDM(t, cl)
	if res := addAlice(t, cl, "pw-one-aaaa"); res.Code != ResultSuccess {
		t.Fatalf("add: %v", res)
	}
	if res := setAlicePassword(t, cl, "pw-two-bbbb"); res.Code != ResultSuccess {
		t.Fatalf("rotate A->B = %v", res)
	}
	// DM replace of an in-history password must succeed (seed merge).
	if res := setAlicePassword(t, cl, "pw-one-aaaa"); res.Code != ResultSuccess {
		t.Fatalf("DM in-history reset = %v, want success (D29)", res)
	}
	if res := bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "pw-one-aaaa"); res.Code != ResultSuccess {
		t.Fatalf("bind after DM history bypass = %v", res)
	}
	bindDM(t, cl)
	// DM re-set of the current password also succeeds (current is history).
	if res := setAlicePassword(t, cl, "pw-one-aaaa"); res.Code != ResultSuccess {
		t.Fatalf("DM current re-set = %v, want success", res)
	}
	// DM still cannot set a too-short password.
	if res := setAlicePassword(t, cl, "tiny"); res.Code != ResultConstraintViolation {
		t.Fatalf("DM too-short = %v, want constraintViolation", res)
	}
}

// TestPasswordEngineHistorySubject is the engine-level D29 matrix: DM
// BypassACI skips history; runtime, self, and zero Subject do not.
func TestPasswordEngineHistorySubject(t *testing.T) {
	t.Parallel()
	clock := newTestNow()
	hasher := fastHasher(t, "")
	eng, err := newPasswordEngine(PasswordPolicy{
		HistoryCount: 4,
		Hasher:       hasher,
		Now:          clock.Now,
	}, testLogger())
	if err != nil {
		t.Fatalf("newPasswordEngine: %v", err)
	}
	current, err := hasher.Hash([]byte("pw-current-aa"))
	if err != nil {
		t.Fatalf("hash current: %v", err)
	}
	old, err := hasher.Hash([]byte("pw-old-bbbbbb"))
	if err != nil {
		t.Fatalf("hash old: %v", err)
	}
	const aliceDN = "uid=alice,ou=people,dc=example,dc=test"
	alice := mustParseDN(t, aliceDN)
	runtime := mustParseDN(t, "uid=rt,ou=people,dc=example,dc=test")
	before := NewEntry(aliceDN,
		StringAttribute("objectClass", "top", "person"),
		Attribute{Name: attrUserPassword, Values: [][]byte{current}},
		Attribute{Name: attrPasswordHistory, Values: [][]byte{old}},
	)
	afterInHistory := NewEntry(aliceDN,
		StringAttribute("objectClass", "top", "person"),
		Attribute{Name: attrUserPassword, Values: [][]byte{[]byte("pw-old-bbbbbb")}},
		Attribute{Name: attrPasswordHistory, Values: [][]byte{old}},
	)
	afterCurrent := NewEntry(aliceDN,
		StringAttribute("objectClass", "top", "person"),
		Attribute{Name: attrUserPassword, Values: [][]byte{[]byte("pw-current-aa")}},
		Attribute{Name: attrPasswordHistory, Values: [][]byte{old}},
	)

	cases := []struct {
		name    string
		subj    Subject
		after   *Entry
		wantErr error
	}{
		{"dm in-history", Subject{DN: mustParseDN(t, "cn=Directory Manager"), BypassACI: true}, afterInHistory, nil},
		{"dm current re-set", Subject{DN: mustParseDN(t, "cn=Directory Manager"), BypassACI: true}, afterCurrent, nil},
		{"self in-history", Subject{DN: alice}, afterInHistory, errPasswordInHistory},
		{"self current re-set", Subject{DN: alice}, afterCurrent, errPasswordInHistory},
		{"runtime in-history", Subject{DN: runtime}, afterInHistory, errPasswordInHistory},
		{"zero subject in-history", Subject{}, afterInHistory, errPasswordInHistory},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := NewFakeStore()
			ctx := context.Background()
			if err := store.Update(ctx, func(tx UpdateTx) error {
				seed := cloneEntry(before)
				if err := tx.Add(ctx, seed); err != nil {
					return err
				}
				// AfterWrite re-reads the post-write entry.
				live := cloneEntry(tc.after)
				if err := tx.Replace(ctx, live); err != nil {
					return err
				}
				return eng.AfterWrite(ctx, tx, WriteEvent{
					Op:      WriteModify,
					Before:  cloneEntry(before),
					After:   cloneEntry(tc.after),
					Subject: tc.subj,
				})
			}); !errors.Is(err, tc.wantErr) {
				t.Fatalf("AfterWrite = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestWriteEventThreadsSubject proves handleAdd/handleModify copy the bind
// identity onto WriteEvent so the password plugin can see BypassACI.
func TestWriteEventThreadsSubject(t *testing.T) {
	t.Parallel()
	recorder := &FakePlugin{PluginName: "recorder"}
	clock := newTestNow()
	opts := policyOptions(t, clock, nil)
	opts.Plugins = []Plugin{recorder}
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	bindDM(t, cl)
	if res := addAlice(t, cl, "alice-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("add: %v", res)
	}
	evs := recorder.Events()
	if len(evs) == 0 {
		t.Fatal("plugin saw no events")
	}
	if !evs[0].Subject.BypassACI {
		t.Fatalf("add subject = %+v, want BypassACI (DM)", evs[0].Subject)
	}

	if res := bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "alice-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("alice bind: %v", res)
	}
	if res := setAlicePassword(t, cl, "alice-new-password"); res.Code != ResultSuccess {
		t.Fatalf("self set: %v", res)
	}
	evs = recorder.Events()
	last := evs[len(evs)-1]
	if last.Op != WriteModify || last.Subject.BypassACI || last.Subject.DN.String() != "uid=alice,ou=people,dc=example,dc=test" {
		t.Fatalf("modify subject = %+v, want alice without BypassACI", last.Subject)
	}
}

func TestPolicyLockoutWithFakeClock(t *testing.T) {
	t.Parallel()
	clock := newTestNow()
	opts := policyOptions(t, clock, func(p *PasswordPolicy) {
		p.MaxFailures = 3
		p.LockoutDuration = 10 * time.Minute
	})
	s, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	bindDM(t, cl)
	if res := addAlice(t, cl, "alice-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("add: %v", res)
	}
	const alice = "uid=alice,ou=people,dc=example,dc=test"

	// Two failures: still no lock.
	for i := 0; i < 2; i++ {
		if res := bindResult(t, cl, alice, "wrong"); res.Code != ResultInvalidCredentials {
			t.Fatalf("failure %d = %v, want invalidCredentials", i+1, res)
		}
	}
	if entry := readAlice(t, s); len(entry.Values("pwdAccountLockedTime")) != 0 {
		t.Fatal("pwdAccountLockedTime set before threshold")
	}
	if res := bindResult(t, cl, alice, "alice-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("bind before threshold = %v", res)
	}

	// Three consecutive failures lock the account and stamp the attribute.
	for i := 0; i < 3; i++ {
		bindResult(t, cl, alice, "wrong")
	}
	entry := readAlice(t, s)
	locked := entry.Values("pwdAccountLockedTime")
	if len(locked) != 1 || string(locked[0]) != "20260815120000Z" {
		t.Fatalf("pwdAccountLockedTime = %v, want the fake clock's stamp", locked)
	}

	// While locked, even the correct password fails (49; Delta candidate
	// pending the T-147 oracle — see password.go VerifyBind).
	if res := bindResult(t, cl, alice, "alice-fixture-password"); res.Code != ResultInvalidCredentials {
		t.Fatalf("bind while locked = %v, want invalidCredentials", res)
	}
	// Just before the window ends: still locked.
	clock.Advance(10*time.Minute - time.Second)
	if res := bindResult(t, cl, alice, "alice-fixture-password"); res.Code != ResultInvalidCredentials {
		t.Fatalf("bind before lockout expiry = %v", res)
	}
	// After the window: the bind succeeds and the attribute clears.
	clock.Advance(2 * time.Second)
	if res := bindResult(t, cl, alice, "alice-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("bind after lockout expiry = %v", res)
	}
	if entry := readAlice(t, s); len(entry.Values("pwdAccountLockedTime")) != 0 {
		t.Fatalf("pwdAccountLockedTime not cleared after successful bind: %v", entry.Values("pwdAccountLockedTime"))
	}
	// The counter reset on success: one more failure must not re-lock.
	bindResult(t, cl, alice, "wrong")
	if res := bindResult(t, cl, alice, "alice-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("bind after one post-unlock failure = %v", res)
	}
}

func TestPolicyMaxAgeWithFakeClock(t *testing.T) {
	t.Parallel()
	clock := newTestNow()
	opts := policyOptions(t, clock, func(p *PasswordPolicy) { p.MaxAge = time.Hour })
	s, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	bindDM(t, cl)
	if res := addAlice(t, cl, "alice-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("add: %v", res)
	}
	const alice = "uid=alice,ou=people,dc=example,dc=test"
	if res := bindResult(t, cl, alice, "alice-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("fresh bind = %v", res)
	}
	// Past maxAge the same password stops working.
	clock.Advance(time.Hour + time.Second)
	if res := bindResult(t, cl, alice, "alice-fixture-password"); res.Code != ResultInvalidCredentials {
		t.Fatalf("expired bind = %v, want invalidCredentials", res)
	}
	if entry := readAlice(t, s); len(entry.Values("userPassword")) == 0 {
		t.Fatal("expired password lost userPassword values")
	}
	// The failed binds reset the connection to anonymous; re-bind DM.
	bindDM(t, cl)
	// An administrative reset re-stamps pwdChangedTime and restores access.
	if res := setAlicePassword(t, cl, "alice-new-password"); res.Code != ResultSuccess {
		t.Fatalf("reset = %v", res)
	}
	if res := bindResult(t, cl, alice, "alice-new-password"); res.Code != ResultSuccess {
		t.Fatalf("bind after reset = %v", res)
	}
}

// TestPolicyPermanentLockout covers the 389 lockoutDuration=0 semantics:
// the account stays locked until the attribute is removed.
func TestPolicyPermanentLockout(t *testing.T) {
	t.Parallel()
	clock := newTestNow()
	opts := policyOptions(t, clock, func(p *PasswordPolicy) { p.MaxFailures = 1 })
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	bindDM(t, cl)
	if res := addAlice(t, cl, "alice-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("add: %v", res)
	}
	const alice = "uid=alice,ou=people,dc=example,dc=test"
	bindResult(t, cl, alice, "wrong")
	clock.Advance(24 * time.Hour)
	if res := bindResult(t, cl, alice, "alice-fixture-password"); res.Code != ResultInvalidCredentials {
		t.Fatalf("permanent lock lifted by time alone: %v", res)
	}
}

// TestPolicyNoPolicyKeepsPlaintext proves the nil-policy seam preserves the
// T-126 behavior for bindOptions-style seeds.
func TestPolicyNoPolicyKeepsPlaintext(t *testing.T) {
	t.Parallel()
	opts := bindOptions(t)
	if opts.PasswordPolicy != nil {
		t.Fatal("bindOptions unexpectedly sets a policy")
	}
	s, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.passwords != nil {
		t.Fatal("engine built without a configured policy")
	}
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	if res := bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "alice-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("plaintext bind = %v", res)
	}
}

// TestPolicyPasswordsNeverLogged drives add/bind/failure/lockout with a
// capturing logger and asserts passwords and hash blobs stay out of logs.
func TestPolicyPasswordsNeverLogged(t *testing.T) {
	t.Parallel()
	clock := newTestNow()
	var buf bytes.Buffer
	var logMu sync.Mutex
	logger := slog.New(slog.NewTextHandler(&lockedWriter{mu: &logMu, w: &buf}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	opts := policyOptions(t, clock, func(p *PasswordPolicy) {
		p.MaxFailures = 2
		p.LockoutDuration = time.Minute
	})
	opts.Logger = logger
	const password = "policy-redaction-fixture-password"
	s, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	bindDM(t, cl)
	if res := addAlice(t, cl, password); res.Code != ResultSuccess {
		t.Fatalf("add: %v", res)
	}
	const alice = "uid=alice,ou=people,dc=example,dc=test"
	bindResult(t, cl, alice, "wrong-one")
	bindResult(t, cl, alice, "wrong-two") // locks the account
	bindResult(t, cl, alice, password)    // rejected while locked
	clock.Advance(2 * time.Minute)
	if res := bindResult(t, cl, alice, password); res.Code != ResultSuccess {
		t.Fatalf("bind after unlock = %v", res)
	}

	logMu.Lock()
	out := buf.String()
	logMu.Unlock()
	for _, forbidden := range []string{password, "wrong-one", "wrong-two", "PRIVATE KEY"} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("log contains secret %q:\n%s", forbidden, out)
		}
	}
	// The stored hash blob must not appear either.
	entry := readAlice(t, s)
	for _, v := range entry.Values("userPassword") {
		if strings.Contains(out, string(v)) {
			t.Fatalf("log contains the stored hash blob:\n%s", out)
		}
	}
}

func TestPasswordPolicyValidation(t *testing.T) {
	t.Parallel()
	base := func() *PasswordPolicy { return &PasswordPolicy{} }
	cases := []struct {
		name   string
		policy *PasswordPolicy
		ok     bool
	}{
		{"empty is valid", base(), true},
		{"negative minLength", func() *PasswordPolicy { p := base(); p.MinLength = -1; return p }(), false},
		{"negative historyCount", func() *PasswordPolicy { p := base(); p.HistoryCount = -1; return p }(), false},
		{"negative maxAge", func() *PasswordPolicy { p := base(); p.MaxAge = -time.Second; return p }(), false},
		{"negative maxFailures", func() *PasswordPolicy { p := base(); p.MaxFailures = -1; return p }(), false},
		{"negative lockoutDuration", func() *PasswordPolicy {
			p := base()
			p.MaxFailures = 3
			p.LockoutDuration = -time.Second
			return p
		}(), false},
		{"unknown scheme", func() *PasswordPolicy { p := base(); p.StorageScheme = "CRYPT-MD5"; return p }(), false},
		{"alias scheme", func() *PasswordPolicy { p := base(); p.StorageScheme = "PBKDF2_SHA256"; return p }(), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := testOptions()
			opts.PasswordPolicy = tc.policy
			_, err := New(opts)
			if tc.ok && err != nil {
				t.Fatalf("New: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatal("New accepted an invalid policy")
			}
		})
	}
}
