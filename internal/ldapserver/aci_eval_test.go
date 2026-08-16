package ldapserver

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// The T-036 runtime allow/deny matrix, evaluated by the real T-139 engine
// over the four compiler-emitted runtime ACIs (the C8 golden fixture) with
// a FakeStore-backed tree. Positive and negative cases mirror the 389
// probes in internal/directory/ds389/verify.go (VerifyRuntime).

const (
	aciEvalSuffix  = "dc=example,dc=test"
	aciEvalPeople  = "ou=people,dc=example,dc=test"
	aciEvalGroups  = "ou=groups,dc=example,dc=test"
	aciEvalRuntime = "uid=labldap-runtime,ou=people,dc=example,dc=test"
	aciEvalAlice   = "uid=alice,ou=people,dc=example,dc=test"
	aciEvalBob     = "uid=bob,ou=people,dc=example,dc=test"
	aciEvalAdmins  = "cn=admins,ou=groups,dc=example,dc=test"
	aciEvalMarker  = "cn=labldap-baseline,dc=example,dc=test"
)

// runtimeACITexts loads the golden runtime ACI set (C8) shared with the
// T-138 parser test.
func runtimeACITexts(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "config", "testdata", "runtime-acis.txt"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("runtime-acis.txt has %d lines, want 4", len(lines))
	}
	var texts []string
	for _, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			t.Fatalf("golden line has %d fields: %q", len(fields), line)
		}
		texts = append(texts, fields[2])
	}
	return texts
}

func newRuntimeEngine(t *testing.T, extra ...string) ACIEngine {
	t.Helper()
	eng, err := NewACIEngine(append(runtimeACITexts(t), extra...), testLogger())
	if err != nil {
		t.Fatalf("NewACIEngine: %v", err)
	}
	return eng
}

// seedACITree returns a FakeStore with the suffix, containers, runtime
// account, two users (alice in cn=admins, bob not), and the baseline
// marker. The marker and suffix carry a synthetic userPassword so read
// denial is observable, and admins carries uniqueMember for the
// member/uniqueMember duality case.
func seedACITree(t *testing.T) *FakeStore {
	t.Helper()
	store := NewFakeStore()
	ctx := context.Background()
	err := store.Update(ctx, func(tx UpdateTx) error {
		for _, e := range []*Entry{
			NewEntry(aciEvalSuffix,
				StringAttribute("objectClass", "top", "domain"),
				StringAttribute("userPassword", "suffix-fixture-secret")),
			NewEntry(aciEvalPeople,
				StringAttribute("objectClass", "top", "organizationalUnit"),
				StringAttribute("ou", "people")),
			NewEntry(aciEvalGroups,
				StringAttribute("objectClass", "top", "organizationalUnit"),
				StringAttribute("ou", "groups")),
			NewEntry(aciEvalRuntime,
				StringAttribute("objectClass", "top", "person"),
				StringAttribute("uid", "labldap-runtime"),
				StringAttribute("cn", "LabLDAP Runtime"),
				StringAttribute("sn", "Runtime"),
				StringAttribute("userPassword", "runtime-fixture-secret")),
			NewEntry(aciEvalAlice,
				StringAttribute("objectClass", "top", "person"),
				StringAttribute("uid", "alice"),
				StringAttribute("cn", "Alice Adams"),
				StringAttribute("sn", "Adams"),
				StringAttribute("userPassword", "alice-fixture-secret")),
			NewEntry(aciEvalBob,
				StringAttribute("objectClass", "top", "person"),
				StringAttribute("uid", "bob"),
				StringAttribute("cn", "Bob Brown"),
				StringAttribute("sn", "Brown")),
			NewEntry(aciEvalAdmins,
				StringAttribute("objectClass", "top", "groupOfNames"),
				StringAttribute("cn", "admins"),
				StringAttribute("member", aciEvalAlice)),
			NewEntry(aciEvalMarker,
				StringAttribute("objectClass", "top", "device"),
				StringAttribute("cn", "labldap-baseline"),
				StringAttribute("serialNumber", "0"),
				StringAttribute("userPassword", "marker-fixture-secret")),
		} {
			if err := tx.Add(ctx, e); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func aciSubject(t *testing.T, dn string) Subject {
	t.Helper()
	if dn == "" {
		return Subject{Anonymous: true}
	}
	return Subject{DN: mustDNA(t, dn)}
}

// aciCheck runs one check inside a store View, the way dispatch does.
func aciCheck(t *testing.T, eng ACIEngine, store *FakeStore, subj Subject, target, attr string, perm Permission) bool {
	t.Helper()
	var (
		ok  bool
		err error
	)
	vErr := store.View(context.Background(), func(tx ReadTx) error {
		ok, err = eng.Allowed(context.Background(), tx, ACICheck{
			Subject:   subj,
			Target:    mustDNA(t, target),
			Attribute: attr,
			Perm:      perm,
		})
		return nil
	})
	if vErr != nil {
		t.Fatalf("view: %v", vErr)
	}
	if err != nil {
		t.Fatalf("Allowed(%s %s %s): %v", perm, target, attr, err)
	}
	return ok
}

func TestACIEngineRuntimeMatrix(t *testing.T) {
	t.Parallel()
	store := seedACITree(t)
	eng := newRuntimeEngine(t)
	rt := aciSubject(t, aciEvalRuntime)
	alice := aciSubject(t, aciEvalAlice)
	anon := aciSubject(t, "")

	cases := []struct {
		name   string
		subj   Subject
		target string
		attr   string
		perm   Permission
		want   bool
	}{
		// Runtime reads people/groups (T-036 allow arm).
		{"runtime search suffix subtree entry", rt, aciEvalSuffix, "", PermSearch, true},
		{"runtime search people entry", rt, aciEvalAlice, "", PermSearch, true},
		{"runtime read people attr", rt, aciEvalAlice, "cn", PermRead, true},
		{"runtime read groups attr", rt, aciEvalAdmins, "cn", PermRead, true},
		{"runtime compare people attr", rt, aciEvalAlice, "uid", PermCompare, true},
		// Runtime cannot read userPassword where only suffix-read applies
		// (targetattr!="userPassword"); the password ACI is write-only.
		{"runtime read userPassword on suffix", rt, aciEvalSuffix, "userPassword", PermRead, false},
		{"runtime read userPassword on marker", rt, aciEvalMarker, "userPassword", PermRead, false},
		{"runtime compare userPassword on suffix", rt, aciEvalSuffix, "userPassword", PermCompare, false},
		// 389-consistent corollary (verify.go: people-write still grants
		// read of non-aci attributes under ou=people, so the T-036 probe
		// checks userPassword denial only at suffix/marker scope).
		{"runtime read userPassword on people entry", rt, aciEvalAlice, "userPassword", PermRead, true},
		// Runtime writes people/groups except aci (targetattr!="aci").
		{"runtime add person", rt, "uid=probe," + aciEvalPeople, "", PermAdd, true},
		{"runtime delete person", rt, aciEvalAlice, "", PermDelete, true},
		{"runtime write person attr", rt, aciEvalAlice, "description", PermWrite, true},
		{"runtime add group", rt, "cn=probe," + aciEvalGroups, "", PermAdd, true},
		{"runtime write group attr", rt, aciEvalAdmins, "description", PermWrite, true},
		{"runtime write aci on person", rt, aciEvalAlice, "aci", PermWrite, false},
		{"runtime write aci on people container", rt, aciEvalPeople, "aci", PermWrite, false},
		{"runtime write aci on groups container", rt, aciEvalGroups, "aci", PermWrite, false},
		// Runtime writes userPassword on people (runtime-password grant).
		{"runtime write userPassword on person", rt, aciEvalAlice, "userPassword", PermWrite, true},
		// Entry-level writes outside people/groups: suffix-read grants no
		// write, so the marker at suffix root is read-only for runtime.
		{"runtime write marker description", rt, aciEvalMarker, "description", PermWrite, false},
		{"runtime add directly under suffix", rt, "cn=probe," + aciEvalSuffix, "", PermAdd, false},
		// Engine-admin tree: cn=config is outside every ACI target
		// (absent on native is Delta D2; the check still denies).
		{"runtime write cn=config", rt, "cn=config", "nsslapd-listenhost", PermWrite, false},
		{"runtime entry write cn=config", rt, "cn=config", "", PermWrite, false},
		// Outside the managed suffix nothing applies (the op layer answers
		// noSuchObject before or after this deny; both are T-036 passes).
		{"runtime add outside suffix", rt, "cn=probe,dc=unmanaged", "", PermAdd, false},
		// Other identities gain nothing from the runtime-pinned set.
		{"alice read people attr", alice, aciEvalAlice, "cn", PermRead, false},
		{"alice write people attr", alice, aciEvalAlice, "description", PermWrite, false},
		{"anonymous read suffix", anon, aciEvalSuffix, "cn", PermRead, false},
		{"anonymous search suffix", anon, aciEvalSuffix, "", PermSearch, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := aciCheck(t, eng, store, tc.subj, tc.target, tc.attr, tc.perm); got != tc.want {
				t.Errorf("Allowed(%s %q attr=%q) = %v, want %v", tc.perm, tc.target, tc.attr, got, tc.want)
			}
		})
	}
}

// The runtime matrix holds for any subject DN casing, because userdn and
// target-scope comparison are fold-correct.
func TestACIEngineCaseFoldedMatching(t *testing.T) {
	t.Parallel()
	store := seedACITree(t)
	eng := newRuntimeEngine(t)
	rt := Subject{DN: mustDNA(t, "UID=LabLDAP-Runtime,OU=People,dc=example,dc=test")}
	if !aciCheck(t, eng, store, rt, aciEvalAlice, "cn", PermRead) {
		t.Error("folded runtime DN must still match userdn")
	}
	if !aciCheck(t, eng, store, rt, "UID=ALICE,ou=people,DC=EXAMPLE,DC=TEST", "cn", PermRead) {
		t.Error("folded target DN must stay in the people-write scope")
	}
}

// An operator groupdn ACL allows a member and denies a non-member
// (T-036/T-139 acceptance), resolving member and uniqueMember through the
// same store snapshot.
func TestACIEngineGroupDN(t *testing.T) {
	t.Parallel()
	store := seedACITree(t)
	grant := `(target="ldap:///dc=example,dc=test")(targetattr="*")` +
		`(version 3.0; acl "labldap:admins-read"; allow (read,search,compare) groupdn="ldap:///cn=admins,ou=groups,dc=example,dc=test";)`
	eng := newRuntimeEngine(t, grant)

	if !aciCheck(t, eng, store, aciSubject(t, aciEvalAlice), aciEvalSuffix, "cn", PermRead) {
		t.Error("group member alice must be allowed")
	}
	if aciCheck(t, eng, store, aciSubject(t, aciEvalBob), aciEvalSuffix, "cn", PermRead) {
		t.Error("non-member bob must be denied")
	}
	if aciCheck(t, eng, store, aciSubject(t, ""), aciEvalSuffix, "cn", PermRead) {
		t.Error("anonymous must never match groupdn")
	}

	// uniqueMember participates in the same membership test.
	uniqueGrant := `(target="ldap:///dc=example,dc=test")` +
		`(version 3.0; acl "labldap:unique-read"; allow (read) groupdn="ldap:///cn=unixadmins,ou=groups,dc=example,dc=test";)`
	ctx := context.Background()
	if err := store.Update(ctx, func(tx UpdateTx) error {
		return tx.Add(ctx, NewEntry("cn=unixadmins,ou=groups,dc=example,dc=test",
			StringAttribute("objectClass", "top", "groupOfUniqueNames"),
			StringAttribute("cn", "unixadmins"),
			StringAttribute("uniqueMember", "uid=bob,ou=people,dc=example,dc=test")))
	}); err != nil {
		t.Fatalf("add uniqueMember group: %v", err)
	}
	eng2 := newRuntimeEngine(t, uniqueGrant)
	if !aciCheck(t, eng2, store, aciSubject(t, aciEvalBob), aciEvalSuffix, "cn", PermRead) {
		t.Error("uniqueMember bob must be allowed")
	}
	if aciCheck(t, eng2, store, aciSubject(t, aciEvalAlice), aciEvalSuffix, "cn", PermRead) {
		t.Error("non-uniqueMember alice must be denied")
	}
}

// BypassACI (the Directory Manager property, ADR-0009 decision 13) allows
// without evaluation — even with an empty ACI set or a matching deny rule.
func TestACIEngineBypassACI(t *testing.T) {
	t.Parallel()
	store := seedACITree(t)
	dm := Subject{DN: mustDNA(t, "cn=Directory Manager"), BypassACI: true}

	empty, err := NewACIEngine(nil, testLogger())
	if err != nil {
		t.Fatalf("NewACIEngine(empty): %v", err)
	}
	if !aciCheck(t, empty, store, dm, "cn=config", "userPassword", PermWrite) {
		t.Error("DM must be allowed with an empty ACI set")
	}
	if aciCheck(t, empty, store, aciSubject(t, aciEvalRuntime), aciEvalSuffix, "cn", PermRead) {
		t.Error("empty ACI set must deny non-DM subjects (fail closed)")
	}

	denyAll := `(target="ldap:///dc=example,dc=test")(targetattr="*")` +
		`(version 3.0; acl "labldap:deny-all"; deny (read,search,compare,add,delete,write) userdn="ldap:///anyone";)`
	eng := newRuntimeEngine(t, denyAll)
	if !aciCheck(t, eng, store, dm, aciEvalAlice, "userPassword", PermWrite) {
		t.Error("DM must bypass even a matching deny rule")
	}
	if aciCheck(t, eng, store, aciSubject(t, aciEvalRuntime), aciEvalAlice, "cn", PermRead) {
		t.Error("deny (…) anyone must override the runtime allows (deny-wins)")
	}
}

// Deny-wins (C8): an applicable deny beats every applicable allow.
func TestACIEngineDenyWins(t *testing.T) {
	t.Parallel()
	store := seedACITree(t)
	// The compiler emits deny rules only through rawACI; this pair mirrors
	// the adjudicated parser fixture: everyone may write description, but
	// a user may not write their own.
	allow := `(target="ldap:///ou=people,dc=example,dc=test")(targetattr="description")` +
		`(version 3.0; acl "labldap:all-desc"; allow (write) userdn="ldap:///all";)`
	deny := `(target="ldap:///ou=people,dc=example,dc=test")(targetattr="description")` +
		`(version 3.0; acl "labldap:deny-self-desc"; deny (write) userdn="ldap:///self";)`
	eng, err := NewACIEngine([]string{allow, deny}, testLogger())
	if err != nil {
		t.Fatalf("NewACIEngine: %v", err)
	}
	if !aciCheck(t, eng, store, aciSubject(t, aciEvalAlice), aciEvalBob, "description", PermWrite) {
		t.Error("alice writing bob's description must be allowed by the all rule")
	}
	if aciCheck(t, eng, store, aciSubject(t, aciEvalAlice), aciEvalAlice, "description", PermWrite) {
		t.Error("alice writing her own description must hit the self deny (deny-wins)")
	}
	// Deny order independence: the same set reversed must decide the same.
	engRev, err := NewACIEngine([]string{deny, allow}, testLogger())
	if err != nil {
		t.Fatalf("NewACIEngine reversed: %v", err)
	}
	if aciCheck(t, engRev, store, aciSubject(t, aciEvalAlice), aciEvalAlice, "description", PermWrite) {
		t.Error("deny-wins must not depend on ACI order")
	}
}

// userdn keyword forms: anyone matches pre-bind, all requires an
// authenticated identity, self requires the bound DN to equal the target.
func TestACIEngineSubjectKeywords(t *testing.T) {
	t.Parallel()
	store := seedACITree(t)
	anyone := `(target="ldap:///dc=example,dc=test")(targetattr="cn")` +
		`(version 3.0; acl "labldap:world"; allow (read) userdn="ldap:///anyone";)`
	all := `(target="ldap:///dc=example,dc=test")(targetattr="sn")` +
		`(version 3.0; acl "labldap:auth"; allow (read) userdn="ldap:///all";)`
	self := `(target="ldap:///ou=people,dc=example,dc=test")(targetattr="userPassword")` +
		`(version 3.0; acl "labldap:self-pw"; allow (write) userdn="ldap:///self";)`
	eng, err := NewACIEngine([]string{anyone, all, self}, testLogger())
	if err != nil {
		t.Fatalf("NewACIEngine: %v", err)
	}
	anon := aciSubject(t, "")
	alice := aciSubject(t, aciEvalAlice)

	if !aciCheck(t, eng, store, anon, aciEvalSuffix, "cn", PermRead) {
		t.Error("anyone must match the anonymous subject")
	}
	if aciCheck(t, eng, store, anon, aciEvalSuffix, "sn", PermRead) {
		t.Error("all must not match the anonymous subject")
	}
	if !aciCheck(t, eng, store, alice, aciEvalSuffix, "sn", PermRead) {
		t.Error("all must match an authenticated subject")
	}
	if !aciCheck(t, eng, store, alice, aciEvalAlice, "userPassword", PermWrite) {
		t.Error("self must match when bound DN equals the target")
	}
	if aciCheck(t, eng, store, alice, aciEvalBob, "userPassword", PermWrite) {
		t.Error("self must not match another entry")
	}

	// The pre-bind connection state is the zero Subject (Anonymous unset,
	// zero DN): it must behave as anonymous for every keyword.
	var zero Subject
	if aciCheck(t, eng, store, zero, aciEvalSuffix, "sn", PermRead) {
		t.Error("all must not match the zero (pre-bind) subject")
	}
	if !aciCheck(t, eng, store, zero, aciEvalSuffix, "cn", PermRead) {
		t.Error("anyone must match the zero (pre-bind) subject")
	}
	if aciCheck(t, eng, store, zero, aciEvalAlice, "userPassword", PermWrite) {
		t.Error("self must not match the zero (pre-bind) subject")
	}
}

// Fail-closed on ambiguous state (C8): a missing group, a non-group
// target, and an out-of-grammar subject kind all deny rather than grant.
func TestACIEngineFailClosed(t *testing.T) {
	t.Parallel()
	store := seedACITree(t)

	missingGroup := `(target="ldap:///dc=example,dc=test")(targetattr="*")` +
		`(version 3.0; acl "labldap:ghost"; allow (read,search) groupdn="ldap:///cn=ghost,ou=groups,dc=example,dc=test";)`
	nonGroup := `(target="ldap:///dc=example,dc=test")(targetattr="*")` +
		`(version 3.0; acl "labldap:notagroup"; allow (read,search) groupdn="ldap:///uid=alice,ou=people,dc=example,dc=test";)`
	eng := newRuntimeEngine(t, missingGroup, nonGroup)
	// alice: only the groupdn rules could grant her anything.
	if aciCheck(t, eng, store, aciSubject(t, aciEvalAlice), aciEvalSuffix, "cn", PermRead) {
		t.Error("missing group entry must fail closed")
	}
	if aciCheck(t, eng, store, aciSubject(t, aciEvalAlice), aciEvalBob, "cn", PermRead) {
		t.Error("groupdn pointing at a non-group entry must fail closed")
	}

	// A hand-built ACI with an unknown subject kind denies.
	bad := &aciEngine{
		acis: []*ParsedACI{{
			ID:          "labldap:hand-built",
			TargetDN:    mustDNA(t, aciEvalSuffix),
			Permissions: []Permission{PermRead},
			Subject:     ACISubjectA{Kind: ACISubjectKindA(99)},
		}},
		logger: testLogger(),
	}
	var allowed bool
	err := store.View(context.Background(), func(tx ReadTx) error {
		var err error
		allowed, err = bad.Allowed(context.Background(), tx, ACICheck{
			Subject: aciSubject(t, aciEvalAlice),
			Target:  mustDNA(t, aciEvalSuffix),
			Perm:    PermRead,
		})
		return err
	})
	if err != nil {
		t.Fatalf("Allowed: %v", err)
	}
	if allowed {
		t.Error("unknown subject kind must fail closed")
	}

	// A store error inside groupdn resolution surfaces as an error (the
	// dispatch seam denies and logs it).
	eng2 := newRuntimeEngine(t, `(target="ldap:///dc=example,dc=test")(targetattr="*")`+
		`(version 3.0; acl "labldap:err"; allow (read) groupdn="ldap:///cn=admins,ou=groups,dc=example,dc=test";)`)
	ok, err := eng2.Allowed(context.Background(), errReadTx{}, ACICheck{
		Subject: aciSubject(t, aciEvalAlice),
		Target:  mustDNA(t, aciEvalSuffix),
		Perm:    PermRead,
	})
	if err == nil {
		t.Fatal("store error must surface")
	}
	if ok {
		t.Error("store error must deny")
	}
}

// errReadTx fails every read: the groupdn lookup cannot succeed.
type errReadTx struct{}

func (errReadTx) Entry(context.Context, config.DN) (*Entry, error) {
	return nil, errors.New("ldapserver test: read failure")
}

func (errReadTx) Children(context.Context, config.DN) ([]*Entry, error) {
	return nil, errors.New("ldapserver test: read failure")
}

func (errReadTx) Subtree(context.Context, config.DN) ([]*Entry, error) {
	return nil, errors.New("ldapserver test: read failure")
}

// NewACIEngine never serves a partial policy: one malformed text rejects
// the set (fail closed at construction).
func TestNewACIEngineRejectsBadText(t *testing.T) {
	t.Parallel()
	texts := append(runtimeACITexts(t), `(version 3.0; acl "x"; allow (read) userdn="ldap:///anyone";)`)
	if _, err := NewACIEngine(texts, testLogger()); !errors.Is(err, ErrACIParseA) {
		t.Fatalf("NewACIEngine with target-less text = %v, want ErrACIParseA", err)
	}
	if _, err := NewACIEngine([]string{"garbage"}, testLogger()); !errors.Is(err, ErrACIParseA) {
		t.Fatalf("NewACIEngine(garbage) = %v, want ErrACIParseA", err)
	}
}

// New builds the real engine from ACITexts when no ACI is injected, and
// rejects unparseable policy at startup (fail closed). FakeACI stays the
// injected path for tests.
func TestNewServerBuildsACIFromTexts(t *testing.T) {
	t.Parallel()
	opts := testOptions()
	opts.ACI = nil
	opts.ACITexts = runtimeACITexts(t)
	s, err := New(opts)
	if err != nil {
		t.Fatalf("New with ACITexts: %v", err)
	}
	if s.opts.ACI == nil {
		t.Fatal("New must install the parsed engine")
	}

	bad := testOptions()
	bad.ACI = nil
	bad.ACITexts = []string{"not an aci"}
	if _, err := New(bad); err == nil {
		t.Fatal("New must reject unparseable ACITexts")
	}
}

// The T-036 runtime probes over the wire: the server evaluates the real
// engine from ACITexts against the FakeStore tree, as the runtime
// identity. Mirrors VerifyRuntime in internal/directory/ds389/verify.go.
func TestACIEngineRuntimeMatrixWire(t *testing.T) {
	t.Parallel()
	store := seedACITree(t)
	opts := testOptions()
	opts.Codec = NewBERCodec(BERCodecOptions{})
	opts.Schema = searchSchema()
	opts.Store = store
	opts.ACI = nil
	opts.ACITexts = runtimeACITexts(t)
	opts.AllowCleartextBind = true
	_, addr := serveTestServerFrom(t, opts, nil)

	cl := dialTestClient(t, addr)
	if res := bindResult(t, cl, aciEvalRuntime, "runtime-fixture-secret"); res.Code != ResultSuccess {
		t.Fatalf("runtime bind = %v", res)
	}

	// Allowed: subtree search of the managed suffix. userPassword is
	// projected out wherever suffix-read is the only covering ACI (suffix
	// root, marker). Under ou=people the people-write grant (targetattr!=
	// "aci") covers userPassword — 389-consistent per the verify.go probe
	// comment — so people entries return it.
	entries, done := search(t, cl, &SearchRequest{
		BaseDN: aciEvalSuffix, Scope: ScopeWholeSubtree,
		Filter: &FilterPresent{Attr: "objectClass"},
	})
	if done.Result.Code != ResultSuccess {
		t.Fatalf("suffix subtree search = %v", done.Result)
	}
	var sawAlice, alicePW bool
	for _, e := range entries {
		hasPW := false
		for _, a := range e.Attributes {
			if strings.EqualFold(a.Name, "userPassword") {
				hasPW = true
			}
		}
		switch e.DN {
		case aciEvalSuffix, aciEvalMarker:
			if hasPW {
				t.Fatalf("userPassword leaked on %s (only suffix-read covers it)", e.DN)
			}
		case aciEvalAlice:
			sawAlice = true
			alicePW = hasPW
		}
	}
	if !sawAlice {
		t.Fatal("runtime subtree search must see people entries")
	}
	if !alicePW {
		t.Fatal("people-write (targetattr!=\"aci\") must grant userPassword read under ou=people")
	}

	// Denied reads never error: the entry returns without the attribute.
	base, done := search(t, cl, &SearchRequest{
		BaseDN: aciEvalSuffix, Scope: ScopeBaseObject,
		Filter: &FilterPresent{Attr: "objectClass"}, Attributes: []string{"userPassword"},
	})
	if done.Result.Code != ResultSuccess || len(base) != 1 {
		t.Fatalf("suffix base search = %v, %d entries", done.Result, len(base))
	}
	if got := base[0].Attributes; len(got) != 0 {
		t.Fatalf("suffix base userPassword projection = %v, want no attributes", got)
	}

	// Denied: engine-admin tree (cn=config absent is Delta D2; the ACI
	// check fires before existence so the answer is 50, not 32).
	res := roundTrip(t, cl, &ModifyRequest{
		DN:      "cn=config",
		Changes: []ModifyChange{{Op: ModifyReplace, Attr: Attribute{Name: "nsslapd-listenhost", Values: [][]byte{[]byte("127.0.0.1")}}}},
	})
	if res.Code != ResultInsufficientAccessRights {
		t.Fatalf("runtime modify cn=config = %v, want insufficientAccessRights", res)
	}

	// Denied: marker at suffix root is outside the write grants.
	res = roundTrip(t, cl, &ModifyRequest{
		DN:      aciEvalMarker,
		Changes: []ModifyChange{{Op: ModifyReplace, Attr: Attribute{Name: "description", Values: [][]byte{[]byte("probe")}}}},
	})
	if res.Code != ResultInsufficientAccessRights {
		t.Fatalf("runtime modify marker = %v, want insufficientAccessRights", res)
	}

	// Denied: aci attribute writes on every write grant (targetattr!="aci").
	for _, dn := range []string{aciEvalPeople, aciEvalGroups, aciEvalAlice} {
		res = roundTrip(t, cl, &ModifyRequest{
			DN:      dn,
			Changes: []ModifyChange{{Op: ModifyAdd, Attr: Attribute{Name: "aci", Values: [][]byte{[]byte(`(targetattr="description")(version 3.0; acl "labldap:probe-widen"; allow (write) userdn="ldap:///anyone";)`)}}}},
		})
		if res.Code != ResultInsufficientAccessRights {
			t.Fatalf("runtime aci add on %s = %v, want insufficientAccessRights", dn, res)
		}
	}

	// Allowed: create/modify/password/delete of a person, and group CUD.
	probeUser := "uid=labldap-probe-user," + aciEvalPeople
	res = roundTrip(t, cl, &AddRequest{
		DN: probeUser,
		Attributes: []Attribute{
			StringAttribute("objectClass", "top", "person"),
			StringAttribute("uid", "labldap-probe-user"),
			StringAttribute("cn", "Probe"),
			StringAttribute("sn", "Probe"),
			StringAttribute("userPassword", "probe-fixture-secret"),
		},
	})
	if res.Code != ResultSuccess {
		t.Fatalf("runtime add probe user = %v", res)
	}
	res = roundTrip(t, cl, &ModifyRequest{
		DN:      probeUser,
		Changes: []ModifyChange{{Op: ModifyReplace, Attr: Attribute{Name: "description", Values: [][]byte{[]byte("probe")}}}},
	})
	if res.Code != ResultSuccess {
		t.Fatalf("runtime modify probe user = %v", res)
	}
	res = roundTrip(t, cl, &ModifyRequest{
		DN:      probeUser,
		Changes: []ModifyChange{{Op: ModifyReplace, Attr: Attribute{Name: "userPassword", Values: [][]byte{[]byte("probe-fixture-secret-2")}}}},
	})
	if res.Code != ResultSuccess {
		t.Fatalf("runtime password replace = %v", res)
	}
	probeGroup := "cn=labldap-probe-group," + aciEvalGroups
	res = roundTrip(t, cl, &AddRequest{
		DN: probeGroup,
		Attributes: []Attribute{
			StringAttribute("objectClass", "top", "groupOfNames"),
			StringAttribute("cn", "labldap-probe-group"),
			StringAttribute("member", probeUser),
		},
	})
	if res.Code != ResultSuccess {
		t.Fatalf("runtime add probe group = %v", res)
	}
	if res = roundTrip(t, cl, &DeleteRequest{DN: probeGroup}); res.Code != ResultSuccess {
		t.Fatalf("runtime delete probe group = %v", res)
	}
	if res = roundTrip(t, cl, &DeleteRequest{DN: probeUser}); res.Code != ResultSuccess {
		t.Fatalf("runtime delete probe user = %v", res)
	}

	// Denied: outside the managed suffix (noSuchObject per the op layer,
	// which T-036 accepts for this probe).
	res = roundTrip(t, cl, &AddRequest{
		DN:         "cn=labldap-probe,dc=unmanaged",
		Attributes: []Attribute{StringAttribute("objectClass", "top", "device"), StringAttribute("cn", "labldap-probe")},
	})
	if res.Code != ResultNoSuchObject {
		t.Fatalf("runtime add outside suffix = %v, want noSuchObject", res)
	}

	// An anonymous connection sees nothing under the runtime-pinned set:
	// denied searches look like empty results, never like existence.
	anon := dialTestClient(t, addr)
	entries, done = search(t, anon, &SearchRequest{
		BaseDN: aciEvalSuffix, Scope: ScopeWholeSubtree,
		Filter: &FilterPresent{Attr: "objectClass"},
	})
	if done.Result.Code != ResultSuccess || len(entries) != 0 {
		t.Fatalf("anonymous subtree = %v with %d entries, want success with none", done.Result, len(entries))
	}
}

// groupdn resolution is bounded: repeated groupdn clauses cost one group
// read per Allowed call, and membership verdicts are not cached across
// calls (a membership change between two checks takes effect immediately).
func TestACIEngineGroupCachePerCall(t *testing.T) {
	t.Parallel()
	store := seedACITree(t)
	grant := func(id string) string {
		return fmt.Sprintf(`(target="ldap:///dc=example,dc=test")(targetattr="cn")`+
			`(version 3.0; acl %q; allow (read) groupdn="ldap:///cn=admins,ou=groups,dc=example,dc=test";)`, id)
	}
	eng := newRuntimeEngine(t, grant("labldap:g1"), grant("labldap:g2"), grant("labldap:g3"))

	reads := 0
	var allowed bool
	err := store.View(context.Background(), func(tx ReadTx) error {
		var err error
		allowed, err = eng.Allowed(context.Background(), countingTx{ReadTx: tx, reads: &reads}, ACICheck{
			Subject:   aciSubject(t, aciEvalAlice),
			Target:    mustDNA(t, aciEvalSuffix),
			Attribute: "cn",
			Perm:      PermRead,
		})
		return err
	})
	if err != nil {
		t.Fatalf("Allowed: %v", err)
	}
	if !allowed {
		t.Fatal("member alice must be allowed")
	}
	if reads != 1 {
		t.Fatalf("group entry reads = %d, want exactly 1 per Allowed call", reads)
	}

	// No cross-call caching: remove alice's membership and re-check.
	ctx := context.Background()
	if err := store.Update(ctx, func(tx UpdateTx) error {
		g, err := tx.Entry(ctx, mustDNA(t, aciEvalAdmins))
		if err != nil {
			return err
		}
		setAttr(g, "member", []byte("uid=carol,ou=people,dc=example,dc=test"))
		return tx.Replace(ctx, g)
	}); err != nil {
		t.Fatalf("rewrite membership: %v", err)
	}
	if aciCheck(t, eng, store, aciSubject(t, aciEvalAlice), aciEvalSuffix, "cn", PermRead) {
		t.Fatal("membership change between calls must take effect (no stale cache)")
	}
}

// countingTx counts Entry reads through the transaction.
type countingTx struct {
	ReadTx
	reads *int
}

func (c countingTx) Entry(ctx context.Context, dn config.DN) (*Entry, error) {
	*c.reads++
	return c.ReadTx.Entry(ctx, dn)
}
