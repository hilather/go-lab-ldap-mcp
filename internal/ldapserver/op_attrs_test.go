package ldapserver

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeClock is a settable time source for Options.Clock so operational
// attribute stamps are deterministic (T-137).
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (f *fakeClock) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeClock) set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = t
}

var opAttrsEpoch = time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)

// opAttrsOptions returns the contract-schema wire fixture (suffix, people,
// groups) with cleartext binds, a DM identity, a fake clock at
// opAttrsEpoch, and deterministic entryUUIDs. It additionally seeds a
// bindable user (carol), a pre-locked user (frank), and an ou=devices
// container for the marker-schema test. The seeds bypass the write path,
// so they carry no T-137 stamps.
func opAttrsOptions(t *testing.T, mutate func(*Options)) (Options, *fakeClock) {
	t.Helper()
	clock := &fakeClock{t: opAttrsEpoch}
	uuids := 0
	opts := schemaWireOptions(t, func(o *Options) {
		o.AllowCleartextBind = true
		o.DirectoryManager = dmIdentity("dm-fixture-password")
		o.Clock = clock.now
		o.NewUUID = func() string {
			uuids++
			return fmt.Sprintf("uuid-%08d", uuids)
		}
		ctx := context.Background()
		if err := o.Store.Update(ctx, func(tx UpdateTx) error {
			for _, e := range []*Entry{
				NewEntry("uid=carol,ou=people,dc=example,dc=test",
					StringAttribute("objectClass", "top", "person"),
					StringAttribute("uid", "carol"),
					StringAttribute("cn", "Carol Clark"),
					StringAttribute("sn", "Clark"),
					StringAttribute("userPassword", "carol-fixture-password")),
				NewEntry("uid=frank,ou=people,dc=example,dc=test",
					StringAttribute("objectClass", "top", "person"),
					StringAttribute("uid", "frank"),
					StringAttribute("cn", "Frank Fox"),
					StringAttribute("sn", "Fox"),
					StringAttribute("userPassword", "frank-fixture-password"),
					StringAttribute("nsAccountLock", "TRUE")),
				NewEntry("ou=devices,dc=example,dc=test",
					StringAttribute("objectClass", "top", "organizationalUnit"),
					StringAttribute("ou", "devices")),
			} {
				if err := tx.Add(ctx, e); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if mutate != nil {
			mutate(o)
		}
	})
	return opts, clock
}

// TestGeneralizedTime pins the RFC 4517 wire form: UTC, second granularity.
func TestGeneralizedTime(t *testing.T) {
	t.Parallel()
	if got := generalizedTime(opAttrsEpoch); got != "20260815120000Z" {
		t.Fatalf("generalizedTime = %q, want 20260815120000Z", got)
	}
	loc := time.FixedZone("UTC+2", 2*3600)
	local := time.Date(2026, 8, 15, 14, 0, 0, 0, loc)
	if got := generalizedTime(local); got != "20260815120000Z" {
		t.Fatalf("generalizedTime must normalize to UTC, got %q", got)
	}
}

// TestRandomUUID pins the RFC 4122 version 4 shape: 8-4-4-4-12 hex, version
// nibble 4, variant nibble in 8..b.
func TestRandomUUID(t *testing.T) {
	t.Parallel()
	a, b := randomUUID(), randomUUID()
	if a == b {
		t.Fatalf("two UUIDs collided: %q", a)
	}
	if len(a) != 36 || a[8] != '-' || a[13] != '-' || a[18] != '-' || a[23] != '-' {
		t.Fatalf("uuid shape = %q", a)
	}
	if a[14] != '4' {
		t.Fatalf("version nibble = %c, want 4", a[14])
	}
	if !strings.ContainsRune("89ab", rune(a[19])) {
		t.Fatalf("variant nibble = %c, want 8..b", a[19])
	}
}

// TestAccountLocked pins the nsAccountLock parse: caseIgnoreMatch with
// surrounding whitespace tolerated, anything else unlocked.
func TestAccountLocked(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		entry *Entry
		want  bool
	}{
		{name: "absent", entry: NewEntry("uid=x", StringAttribute("objectClass", "top")), want: false},
		{name: "true", entry: NewEntry("uid=x", StringAttribute("nsAccountLock", "true")), want: true},
		{name: "TRUE", entry: NewEntry("uid=x", StringAttribute("nsAccountLock", "TRUE")), want: true},
		{name: "padded", entry: NewEntry("uid=x", StringAttribute("nsAccountLock", " true ")), want: true},
		{name: "false", entry: NewEntry("uid=x", StringAttribute("nsAccountLock", "false")), want: false},
		{name: "yes", entry: NewEntry("uid=x", StringAttribute("nsAccountLock", "yes")), want: false},
		{name: "empty", entry: NewEntry("uid=x", StringAttribute("nsAccountLock", "")), want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := accountLocked(tc.entry); got != tc.want {
				t.Fatalf("accountLocked = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestOpAttrsAddStamps: Add stamps entryUUID, createTimestamp,
// modifyTimestamp, creatorsName, and modifiersName from the injected clock,
// UUID generator, and bound subject. The stamps are operational: a "+"
// selection returns them while a default selection does not.
func TestOpAttrsAddStamps(t *testing.T) {
	t.Parallel()
	opts, _ := opAttrsOptions(t, nil)
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	if res := bindResult(t, cl, "cn=Directory Manager", "dm-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("dm bind = %v", res)
	}
	dn := "uid=dave,ou=people,dc=example,dc=test"
	res := roundTrip(t, cl, &AddRequest{DN: dn, Attributes: []Attribute{
		StringAttribute("objectClass", "top", "person"),
		StringAttribute("uid", "dave"),
		StringAttribute("cn", "Dave Doe"),
		StringAttribute("sn", "Doe"),
	}})
	if res.Code != ResultSuccess {
		t.Fatalf("add = %v", res)
	}

	stamp := generalizedTime(opAttrsEpoch)
	for attr, want := range map[string]string{
		"entryUUID":       "uuid-00000001",
		"createTimestamp": stamp,
		"modifyTimestamp": stamp,
		"creatorsName":    "cn=Directory Manager",
		"modifiersName":   "cn=Directory Manager",
	} {
		if got := searchAttrValues(t, cl, dn, attr); !slices.Equal(got, []string{want}) {
			t.Fatalf("%s = %v, want %q", attr, got, want)
		}
	}

	// "+" returns all operational attributes in one search.
	entries, done := search(t, cl, &SearchRequest{
		BaseDN: dn, Scope: ScopeBaseObject,
		Filter: &FilterPresent{Attr: "objectClass"}, Attributes: []string{"+"},
	})
	if done.Result.Code != ResultSuccess || len(entries) != 1 {
		t.Fatalf("+ search = %v, %d entries", done.Result, len(entries))
	}
	if got := dseAttr(entries[0], "entryUUID"); !slices.Equal(got, []string{"uuid-00000001"}) {
		t.Fatalf("+ entryUUID = %v", got)
	}

	// A default selection must not leak the operational stamps.
	entries, _ = search(t, cl, &SearchRequest{
		BaseDN: dn, Scope: ScopeBaseObject,
		Filter: &FilterPresent{Attr: "objectClass"},
	})
	for _, a := range entries[0].Attributes {
		switch strings.ToLower(a.Name) {
		case "entryuuid", "createtimestamp", "modifytimestamp", "creatorsname", "modifiersname":
			t.Fatalf("default selection leaked operational %s", a.Name)
		}
	}
}

// TestOpAttrsAnonymousStamp: without a bind the writer identity is the
// empty DN (permissive test ACI only). Delta candidate: 389 records the
// anonymous identity differently; recorded for the T-147 oracle.
func TestOpAttrsAnonymousStamp(t *testing.T) {
	t.Parallel()
	opts, _ := opAttrsOptions(t, nil)
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	dn := "uid=erin,ou=people,dc=example,dc=test"
	res := roundTrip(t, cl, &AddRequest{DN: dn, Attributes: []Attribute{
		StringAttribute("objectClass", "top", "person"),
		StringAttribute("uid", "erin"),
		StringAttribute("cn", "Erin Earp"),
		StringAttribute("sn", "Earp"),
	}})
	if res.Code != ResultSuccess {
		t.Fatalf("anonymous add = %v", res)
	}
	if got := searchAttrValues(t, cl, dn, "creatorsName"); !slices.Equal(got, []string{""}) {
		t.Fatalf("creatorsName = %v, want empty DN", got)
	}
}

// TestOpAttrsModifyAndRenameBump: Modify and ModifyDN bump modifyTimestamp
// and modifiersName while createTimestamp, creatorsName, and entryUUID stay
// frozen.
func TestOpAttrsModifyAndRenameBump(t *testing.T) {
	t.Parallel()
	opts, clock := opAttrsOptions(t, nil)
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	if res := bindResult(t, cl, "cn=Directory Manager", "dm-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("dm bind = %v", res)
	}
	dn := "uid=dave,ou=people,dc=example,dc=test"
	res := roundTrip(t, cl, &AddRequest{DN: dn, Attributes: []Attribute{
		StringAttribute("objectClass", "top", "person"),
		StringAttribute("uid", "dave"),
		StringAttribute("cn", "Dave Doe"),
		StringAttribute("sn", "Doe"),
	}})
	if res.Code != ResultSuccess {
		t.Fatalf("add = %v", res)
	}

	later := opAttrsEpoch.Add(2 * time.Hour)
	clock.set(later)
	res = roundTrip(t, cl, &ModifyRequest{DN: dn, Changes: []ModifyChange{
		{Op: ModifyAdd, Attr: StringAttribute("description", "touched")},
	}})
	if res.Code != ResultSuccess {
		t.Fatalf("modify = %v", res)
	}
	if got := searchAttrValues(t, cl, dn, "modifyTimestamp"); !slices.Equal(got, []string{generalizedTime(later)}) {
		t.Fatalf("modifyTimestamp = %v, want %s", got, generalizedTime(later))
	}
	if got := searchAttrValues(t, cl, dn, "createTimestamp"); !slices.Equal(got, []string{generalizedTime(opAttrsEpoch)}) {
		t.Fatalf("createTimestamp moved = %v", got)
	}
	if got := searchAttrValues(t, cl, dn, "modifiersName"); !slices.Equal(got, []string{"cn=Directory Manager"}) {
		t.Fatalf("modifiersName = %v", got)
	}

	renamed := opAttrsEpoch.Add(3 * time.Hour)
	clock.set(renamed)
	res = roundTrip(t, cl, &ModifyDNRequest{DN: dn, NewRDN: "uid=david", DeleteOldRDN: true})
	if res.Code != ResultSuccess {
		t.Fatalf("rename = %v", res)
	}
	newDN := "uid=david,ou=people,dc=example,dc=test"
	if got := searchAttrValues(t, cl, newDN, "modifyTimestamp"); !slices.Equal(got, []string{generalizedTime(renamed)}) {
		t.Fatalf("modifyTimestamp after rename = %v, want %s", got, generalizedTime(renamed))
	}
	if got := searchAttrValues(t, cl, newDN, "entryUUID"); !slices.Equal(got, []string{"uuid-00000001"}) {
		t.Fatalf("entryUUID moved = %v", got)
	}
}

// TestOpAttrsClientGate: schema-declared operational attributes are
// rejected on client Add and Modify with constraintViolation (19); the
// user attribute nsAccountLock stays writable. 389's exact code for the
// rejection is a recorded Delta candidate.
func TestOpAttrsClientGate(t *testing.T) {
	t.Parallel()
	opts, _ := opAttrsOptions(t, nil)
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	dn := "uid=gwen,ou=people,dc=example,dc=test"
	base := []Attribute{
		StringAttribute("objectClass", "top", "person"),
		StringAttribute("uid", "gwen"),
		StringAttribute("cn", "Gwen Gray"),
		StringAttribute("sn", "Gray"),
	}

	for _, attr := range []string{"entryUUID", "createTimestamp", "modifyTimestamp", "creatorsName", "modifiersName", "memberOf"} {
		blocked := roundTrip(t, cl, &AddRequest{DN: dn, Attributes: append(slices.Clone(base), StringAttribute(attr, "x"))})
		if blocked.Code != ResultConstraintViolation {
			t.Fatalf("add with %s = %v, want constraintViolation", attr, blocked.Code)
		}
		if !strings.Contains(blocked.DiagnosticMessage, attr) {
			t.Fatalf("diagnostic %q does not name %s", blocked.DiagnosticMessage, attr)
		}
	}

	// nsAccountLock is a user attribute: it must pass the gate (disable is
	// a client write of nsAccountLock: true).
	ok := roundTrip(t, cl, &AddRequest{DN: dn, Attributes: append(slices.Clone(base), StringAttribute("nsAccountLock", "false"))})
	if ok.Code != ResultSuccess {
		t.Fatalf("add with nsAccountLock = %v", ok)
	}

	for _, ch := range []ModifyChange{
		{Op: ModifyAdd, Attr: StringAttribute("modifyTimestamp", "20260101000000Z")},
		{Op: ModifyDelete, Attr: StringAttribute("creatorsName", "")},
		{Op: ModifyReplace, Attr: StringAttribute("entryUUID", "forged")},
		{Op: ModifyAdd, Attr: StringAttribute("memberOf", "cn=admins,ou=groups,dc=example,dc=test")},
	} {
		if res := roundTrip(t, cl, &ModifyRequest{DN: dn, Changes: []ModifyChange{ch}}); res.Code != ResultConstraintViolation {
			t.Fatalf("modify %s = %v, want constraintViolation", ch.Attr.Name, res.Code)
		}
	}
	// The forged values must not have landed.
	if got := searchAttrValues(t, cl, dn, "entryUUID"); !slices.Equal(got, []string{"uuid-00000001"}) {
		t.Fatalf("entryUUID after rejected modify = %v", got)
	}
}

// TestOpAttrsLockedAccountBind: nsAccountLock: true fails the bind with
// unwillingToPerform (53) regardless of password correctness, while the
// entry stays searchable; removing the value re-enables the account.
func TestOpAttrsLockedAccountBind(t *testing.T) {
	t.Parallel()
	opts, _ := opAttrsOptions(t, nil)
	_, addr := serveTestServerFrom(t, opts, nil)

	carol := "uid=carol,ou=people,dc=example,dc=test"
	frank := "uid=frank,ou=people,dc=example,dc=test"

	// Unlocked user binds; unknown user still gets 49 (the lock gate never
	// leaks into the no-such-user path).
	cl := dialTestClient(t, addr)
	if res := bindResult(t, cl, carol, "carol-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("carol bind = %v", res)
	}
	if res := bindResult(t, cl, "uid=nobody,ou=people,dc=example,dc=test", "x"); res.Code != ResultInvalidCredentials {
		t.Fatalf("unknown bind = %v, want invalidCredentials", res)
	}

	// Seeded-locked frank: 53 with the right password and with a wrong one
	// (lock is checked before the password — 389-observed).
	if res := bindResult(t, cl, frank, "frank-fixture-password"); res.Code != ResultUnwillingToPerform {
		t.Fatalf("frank bind = %v, want unwillingToPerform", res)
	}
	if res := bindResult(t, cl, frank, "wrong"); res.Code != ResultUnwillingToPerform {
		t.Fatalf("frank bad-password bind = %v, want unwillingToPerform", res)
	}

	// The locked entry stays searchable, and a bind-test client can read
	// both account-state attributes (pwdAccountLockedTime is absent until
	// the T-134 policy stamps it).
	entries, done := search(t, cl, &SearchRequest{
		BaseDN: frank, Scope: ScopeBaseObject,
		Filter:     &FilterPresent{Attr: "objectClass"},
		Attributes: []string{"nsAccountLock", "pwdAccountLockedTime"},
	})
	if done.Result.Code != ResultSuccess || len(entries) != 1 {
		t.Fatalf("locked entry search = %v, %d entries", done.Result, len(entries))
	}
	if got := dseAttr(entries[0], "nsAccountLock"); !slices.Equal(got, []string{"TRUE"}) {
		t.Fatalf("nsAccountLock = %v, want TRUE", got)
	}
	if got := dseAttr(entries[0], "pwdAccountLockedTime"); len(got) != 0 {
		t.Fatalf("pwdAccountLockedTime = %v, want unset", got)
	}

	// DM flips carol's lock on (a client write), bind fails 53; delete the
	// value and the bind succeeds again.
	if res := bindResult(t, cl, "cn=Directory Manager", "dm-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("dm bind = %v", res)
	}
	if res := roundTrip(t, cl, &ModifyRequest{DN: carol, Changes: []ModifyChange{
		{Op: ModifyReplace, Attr: StringAttribute("nsAccountLock", "true")},
	}}); res.Code != ResultSuccess {
		t.Fatalf("lock carol = %v", res)
	}
	if res := bindResult(t, cl, carol, "carol-fixture-password"); res.Code != ResultUnwillingToPerform {
		t.Fatalf("locked carol bind = %v, want unwillingToPerform", res)
	}
	if res := bindResult(t, cl, "cn=Directory Manager", "dm-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("dm rebind = %v", res)
	}
	if res := roundTrip(t, cl, &ModifyRequest{DN: carol, Changes: []ModifyChange{
		{Op: ModifyDelete, Attr: StringAttribute("nsAccountLock", "true")},
	}}); res.Code != ResultSuccess {
		t.Fatalf("unlock carol = %v", res)
	}
	if res := bindResult(t, cl, carol, "carol-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("unlocked carol bind = %v", res)
	}
}

// TestOpAttrsDeviceMarker: the device marker object class with a JSON
// description add round-trips (ADR-0009 decision 21, parity contract C5).
func TestOpAttrsDeviceMarker(t *testing.T) {
	t.Parallel()
	opts, _ := opAttrsOptions(t, nil)
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	dn := "cn=printer-7,ou=devices,dc=example,dc=test"
	desc := `{"lab":"net","kind":"printer","managed":true}`
	res := roundTrip(t, cl, &AddRequest{DN: dn, Attributes: []Attribute{
		StringAttribute("objectClass", "top", "device"),
		StringAttribute("cn", "printer-7"),
		StringAttribute("description", desc),
	}})
	if res.Code != ResultSuccess {
		t.Fatalf("device marker add = %v", res)
	}
	if got := searchAttrValues(t, cl, dn, "description"); !slices.Equal(got, []string{desc}) {
		t.Fatalf("description = %v, want JSON round-trip", got)
	}
}
