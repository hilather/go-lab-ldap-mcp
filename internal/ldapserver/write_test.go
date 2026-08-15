package ldapserver

import (
	"context"
	"errors"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// writeOptions starts from the seeded search tree with an allow-all ACI so
// the success paths exercise the store and plugin wiring; denial tests swap
// the ACI decide function.
func writeOptions(t *testing.T, mutate func(*Options)) Options {
	t.Helper()
	return searchOptions(t, mutate)
}

// roundTrip sends one write op and returns its result.
func roundTrip(t *testing.T, cl *ldapTestClient, op Operation) Result {
	t.Helper()
	id := cl.send(op)
	m := cl.recv()
	if m.ID != id {
		t.Fatalf("response id = %d, want %d", m.ID, id)
	}
	switch r := m.Op.(type) {
	case *AddResponse:
		return r.Result
	case *ModifyResponse:
		return r.Result
	case *DeleteResponse:
		return r.Result
	case *ModifyDNResponse:
		return r.Result
	case *CompareResponse:
		return r.Result
	default:
		t.Fatalf("unexpected op %T", m.Op)
		return Result{}
	}
}

// fetchEntry reads one entry straight from the store for assertions.
func fetchEntry(t *testing.T, opts Options, dn string) (*Entry, error) {
	t.Helper()
	parsed, err := config.ParseDN(dn)
	if err != nil {
		t.Fatalf("parse dn: %v", err)
	}
	var out *Entry
	err = opts.Store.View(context.Background(), func(tx ReadTx) error {
		e, err := tx.Entry(context.Background(), parsed)
		if err != nil {
			return err
		}
		out = e
		return nil
	})
	return out, err
}

func TestAddAndReadBack(t *testing.T) {
	t.Parallel()
	opts := writeOptions(t, nil)
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)

	res := roundTrip(t, cl, &AddRequest{
		DN: "uid=carol,ou=people,dc=example,dc=test",
		Attributes: []Attribute{
			StringAttribute("objectClass", "top", "person"),
			StringAttribute("uid", "carol"),
			StringAttribute("cn", "Carol"),
			StringAttribute("sn", "Clark"),
		},
	})
	if res.Code != ResultSuccess {
		t.Fatalf("add = %v", res)
	}
	e, err := fetchEntry(t, opts, "uid=carol,ou=people,dc=example,dc=test")
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got := e.Values("sn"); len(got) != 1 || string(got[0]) != "Clark" {
		t.Fatalf("sn = %q", got)
	}
}

func TestAddErrors(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, writeOptions(t, nil), nil)
	cl := dialTestClient(t, addr)

	// Duplicate DN.
	res := roundTrip(t, cl, &AddRequest{
		DN:         "uid=alice,ou=people,dc=example,dc=test",
		Attributes: []Attribute{StringAttribute("objectClass", "top")},
	})
	if res.Code != ResultEntryAlreadyExists {
		t.Fatalf("duplicate add = %v, want entryAlreadyExists", res)
	}
	// Missing parent.
	res = roundTrip(t, cl, &AddRequest{
		DN:         "uid=x,ou=nowhere,dc=example,dc=test",
		Attributes: []Attribute{StringAttribute("objectClass", "top")},
	})
	if res.Code != ResultNoSuchObject {
		t.Fatalf("orphan add = %v, want noSuchObject", res)
	}
	// Malformed DN.
	res = roundTrip(t, cl, &AddRequest{
		DN:         "not a dn",
		Attributes: []Attribute{StringAttribute("objectClass", "top")},
	})
	if res.Code != ResultInvalidDNSyntax {
		t.Fatalf("bad-dn add = %v, want invalidDNSyntax", res)
	}
	// Outside the managed suffix.
	res = roundTrip(t, cl, &AddRequest{
		DN:         "dc=other,dc=test",
		Attributes: []Attribute{StringAttribute("objectClass", "top")},
	})
	if res.Code != ResultNoSuchObject {
		t.Fatalf("out-of-suffix add = %v, want noSuchObject", res)
	}
}

func TestAddDeniedByACI(t *testing.T) {
	t.Parallel()
	// Deny everything: the result must be insufficientAccessRights even
	// though the DN is free (C8: no existence leak through the code path).
	_, addr := serveTestServerFrom(t, writeOptions(t, func(o *Options) {
		o.ACI = &FakeACI{}
	}), nil)
	cl := dialTestClient(t, addr)
	res := roundTrip(t, cl, &AddRequest{
		DN:         "uid=dave,ou=people,dc=example,dc=test",
		Attributes: []Attribute{StringAttribute("objectClass", "top")},
	})
	if res.Code != ResultInsufficientAccessRights {
		t.Fatalf("denied add = %v, want insufficientAccessRights", res)
	}
}

func TestAddSchemaGate(t *testing.T) {
	t.Parallel()
	// Once the registry knows object classes, unknown ones are rejected
	// (T-132 stub: the interface is called; FakeSchema permits when empty).
	_, addr := serveTestServerFrom(t, writeOptions(t, func(o *Options) {
		o.Schema = NewFakeSchema([]ObjectClassDef{{OID: "2.5.6.6", Name: "person"}}, nil)
	}), nil)
	cl := dialTestClient(t, addr)
	res := roundTrip(t, cl, &AddRequest{
		DN: "uid=eve,ou=people,dc=example,dc=test",
		Attributes: []Attribute{
			StringAttribute("objectClass", "top", "notARealClass"),
		},
	})
	if res.Code != ResultObjectClassViolation {
		t.Fatalf("unknown oc add = %v, want objectClassViolation", res)
	}
	res = roundTrip(t, cl, &AddRequest{
		DN: "uid=eve,ou=people,dc=example,dc=test",
		Attributes: []Attribute{
			StringAttribute("objectClass", "top", "person"),
		},
	})
	// "top" is not registered either, so this still fails.
	if res.Code != ResultObjectClassViolation {
		t.Fatalf("partial oc add = %v, want objectClassViolation", res)
	}
}

func TestModifySemantics(t *testing.T) {
	t.Parallel()
	opts := writeOptions(t, nil)
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	dn := "uid=alice,ou=people,dc=example,dc=test"

	// Add a new attribute.
	res := roundTrip(t, cl, &ModifyRequest{DN: dn, Changes: []ModifyChange{
		{Op: ModifyAdd, Attr: StringAttribute("description", "one", "two")},
	}})
	if res.Code != ResultSuccess {
		t.Fatalf("add attr = %v", res)
	}
	// Adding an existing value fails attributeOrValueExists (RFC 4511 4.6).
	res = roundTrip(t, cl, &ModifyRequest{DN: dn, Changes: []ModifyChange{
		{Op: ModifyAdd, Attr: StringAttribute("description", "one")},
	}})
	if res.Code != ResultAttributeOrValueExists {
		t.Fatalf("dup value add = %v, want attributeOrValueExists", res)
	}
	// Delete one value, then a missing value fails noSuchAttribute.
	res = roundTrip(t, cl, &ModifyRequest{DN: dn, Changes: []ModifyChange{
		{Op: ModifyDelete, Attr: StringAttribute("description", "one")},
	}})
	if res.Code != ResultSuccess {
		t.Fatalf("delete value = %v", res)
	}
	res = roundTrip(t, cl, &ModifyRequest{DN: dn, Changes: []ModifyChange{
		{Op: ModifyDelete, Attr: StringAttribute("description", "one")},
	}})
	if res.Code != ResultNoSuchAttribute {
		t.Fatalf("delete missing value = %v, want noSuchAttribute", res)
	}
	// Delete of a missing attribute fails noSuchAttribute.
	res = roundTrip(t, cl, &ModifyRequest{DN: dn, Changes: []ModifyChange{
		{Op: ModifyDelete, Attr: Attribute{Name: "title"}},
	}})
	if res.Code != ResultNoSuchAttribute {
		t.Fatalf("delete missing attr = %v, want noSuchAttribute", res)
	}
	// Replace creates an absent attribute and replaces existing values.
	res = roundTrip(t, cl, &ModifyRequest{DN: dn, Changes: []ModifyChange{
		{Op: ModifyReplace, Attr: StringAttribute("sn", "Addams")},
		{Op: ModifyReplace, Attr: StringAttribute("title", "engineer")},
	}})
	if res.Code != ResultSuccess {
		t.Fatalf("replace = %v", res)
	}
	e, err := fetchEntry(t, opts, dn)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got := e.Values("sn"); len(got) != 1 || string(got[0]) != "Addams" {
		t.Fatalf("sn = %q, want [Addams]", got)
	}
	if got := e.Values("title"); len(got) != 1 || string(got[0]) != "engineer" {
		t.Fatalf("title = %q, want [engineer]", got)
	}
	// Replace with no values deletes the attribute.
	res = roundTrip(t, cl, &ModifyRequest{DN: dn, Changes: []ModifyChange{
		{Op: ModifyReplace, Attr: Attribute{Name: "title"}},
	}})
	if res.Code != ResultSuccess {
		t.Fatalf("replace-empty = %v", res)
	}
	e, _ = fetchEntry(t, opts, dn)
	if got := e.Values("title"); len(got) != 0 {
		t.Fatalf("title after replace-empty = %q, want gone", got)
	}
	// Modify of a missing entry.
	res = roundTrip(t, cl, &ModifyRequest{DN: "uid=ghost,ou=people,dc=example,dc=test", Changes: []ModifyChange{
		{Op: ModifyReplace, Attr: StringAttribute("sn", "x")},
	}})
	if res.Code != ResultNoSuchObject {
		t.Fatalf("missing modify = %v, want noSuchObject", res)
	}
}

func TestModifyDeniedByACI(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, writeOptions(t, func(o *Options) {
		o.ACI = &FakeACI{} // deny all
	}), nil)
	cl := dialTestClient(t, addr)
	res := roundTrip(t, cl, &ModifyRequest{DN: "uid=alice,ou=people,dc=example,dc=test", Changes: []ModifyChange{
		{Op: ModifyReplace, Attr: StringAttribute("sn", "x")},
	}})
	if res.Code != ResultInsufficientAccessRights {
		t.Fatalf("denied modify = %v, want insufficientAccessRights", res)
	}
}

func TestDelete(t *testing.T) {
	t.Parallel()
	opts := writeOptions(t, nil)
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)

	// Non-leaf delete fails notAllowedOnNonLeaf.
	res := roundTrip(t, cl, &DeleteRequest{DN: "ou=people,dc=example,dc=test"})
	if res.Code != ResultNotAllowedOnNonLeaf {
		t.Fatalf("non-leaf delete = %v, want notAllowedOnNonLeaf", res)
	}
	// Missing entry.
	res = roundTrip(t, cl, &DeleteRequest{DN: "uid=ghost,ou=people,dc=example,dc=test"})
	if res.Code != ResultNoSuchObject {
		t.Fatalf("missing delete = %v, want noSuchObject", res)
	}
	// Leaf delete succeeds and the entry is gone.
	res = roundTrip(t, cl, &DeleteRequest{DN: "uid=bob,ou=people,dc=example,dc=test"})
	if res.Code != ResultSuccess {
		t.Fatalf("delete = %v", res)
	}
	if _, err := fetchEntry(t, opts, "uid=bob,ou=people,dc=example,dc=test"); err == nil {
		t.Fatal("deleted entry still readable")
	}
}

func TestDeleteDeniedByACI(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, writeOptions(t, func(o *Options) {
		o.ACI = &FakeACI{} // deny all
	}), nil)
	cl := dialTestClient(t, addr)
	// Denied even though the entry exists: no existence leak (C8).
	res := roundTrip(t, cl, &DeleteRequest{DN: "uid=alice,ou=people,dc=example,dc=test"})
	if res.Code != ResultInsufficientAccessRights {
		t.Fatalf("denied delete = %v, want insufficientAccessRights", res)
	}
}

func TestCompare(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, writeOptions(t, nil), nil)
	cl := dialTestClient(t, addr)
	dn := "uid=alice,ou=people,dc=example,dc=test"

	res := roundTrip(t, cl, &CompareRequest{DN: dn, Attr: "sn", Value: []byte("Adams")})
	if res.Code != ResultCompareTrue {
		t.Fatalf("compare true = %v", res)
	}
	res = roundTrip(t, cl, &CompareRequest{DN: dn, Attr: "sn", Value: []byte("Other")})
	if res.Code != ResultCompareFalse {
		t.Fatalf("compare false = %v", res)
	}
	// caseIgnoreMatch folds on compare.
	res = roundTrip(t, cl, &CompareRequest{DN: dn, Attr: "sn", Value: []byte("adams")})
	if res.Code != ResultCompareTrue {
		t.Fatalf("compare fold = %v", res)
	}
	// Missing attribute compares false, missing entry is noSuchObject.
	res = roundTrip(t, cl, &CompareRequest{DN: dn, Attr: "title", Value: []byte("x")})
	if res.Code != ResultCompareFalse {
		t.Fatalf("compare missing attr = %v", res)
	}
	res = roundTrip(t, cl, &CompareRequest{DN: "uid=ghost,ou=people,dc=example,dc=test", Attr: "sn", Value: []byte("x")})
	if res.Code != ResultNoSuchObject {
		t.Fatalf("compare missing entry = %v, want noSuchObject", res)
	}
}

func TestCompareDeniedByACI(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, writeOptions(t, func(o *Options) {
		o.ACI = &FakeACI{} // deny all
	}), nil)
	cl := dialTestClient(t, addr)
	res := roundTrip(t, cl, &CompareRequest{DN: "uid=alice,ou=people,dc=example,dc=test", Attr: "sn", Value: []byte("Adams")})
	if res.Code != ResultInsufficientAccessRights {
		t.Fatalf("denied compare = %v, want insufficientAccessRights", res)
	}
}

func TestModifyDN(t *testing.T) {
	t.Parallel()
	opts := writeOptions(t, nil)
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)

	// Rename within the same parent, keeping the old RDN value.
	res := roundTrip(t, cl, &ModifyDNRequest{
		DN:           "uid=bob,ou=people,dc=example,dc=test",
		NewRDN:       "uid=robert",
		DeleteOldRDN: true,
	})
	if res.Code != ResultSuccess {
		t.Fatalf("moddn = %v", res)
	}
	if _, err := fetchEntry(t, opts, "uid=bob,ou=people,dc=example,dc=test"); err == nil {
		t.Fatal("old DN still present after rename")
	}
	e, err := fetchEntry(t, opts, "uid=robert,ou=people,dc=example,dc=test")
	if err != nil {
		t.Fatalf("read renamed: %v", err)
	}
	if got := e.Values("uid"); len(got) != 1 || string(got[0]) != "robert" {
		t.Fatalf("uid after deleteoldrdn rename = %q, want [robert]", got)
	}

	// Rename with deleteoldrdn=false keeps both values.
	res = roundTrip(t, cl, &ModifyDNRequest{
		DN:           "uid=robert,ou=people,dc=example,dc=test",
		NewRDN:       "uid=rob",
		DeleteOldRDN: false,
	})
	if res.Code != ResultSuccess {
		t.Fatalf("moddn keep-old = %v", res)
	}
	e, _ = fetchEntry(t, opts, "uid=rob,ou=people,dc=example,dc=test")
	if got := e.Values("uid"); len(got) != 2 {
		t.Fatalf("uid after keep-old rename = %q, want both values", got)
	}

	// Subtree move: rename a container and its child follows atomically.
	res = roundTrip(t, cl, &ModifyDNRequest{
		DN:     "ou=groups,dc=example,dc=test",
		NewRDN: "ou=teams",
	})
	if res.Code != ResultSuccess {
		t.Fatalf("subtree moddn = %v", res)
	}
	if _, err := fetchEntry(t, opts, "cn=admins,ou=teams,dc=example,dc=test"); err != nil {
		t.Fatalf("child did not follow subtree rename: %v", err)
	}

	// Move under a different parent via newSuperior.
	res = roundTrip(t, cl, &ModifyDNRequest{
		DN:          "uid=alice,ou=people,dc=example,dc=test",
		NewRDN:      "uid=alice",
		NewSuperior: "ou=teams,dc=example,dc=test",
	})
	if res.Code != ResultSuccess {
		t.Fatalf("move moddn = %v", res)
	}
	if _, err := fetchEntry(t, opts, "uid=alice,ou=teams,dc=example,dc=test"); err != nil {
		t.Fatalf("moved entry not found: %v", err)
	}

	// Rename onto an existing DN fails entryAlreadyExists.
	res = roundTrip(t, cl, &ModifyDNRequest{
		DN:     "uid=rob,ou=people,dc=example,dc=test",
		NewRDN: "cn=admins",
	})
	// cn=admins no longer exists under ou=people after the subtree move;
	// it now lives under ou=teams, so target is free — expect success.
	if res.Code != ResultSuccess {
		t.Fatalf("rename to free DN = %v", res)
	}
	res = roundTrip(t, cl, &ModifyDNRequest{
		DN:     "ou=teams,dc=example,dc=test",
		NewRDN: "ou=people",
	})
	if res.Code != ResultEntryAlreadyExists {
		t.Fatalf("rename onto existing = %v, want entryAlreadyExists", res)
	}

	// Missing source.
	res = roundTrip(t, cl, &ModifyDNRequest{DN: "uid=ghost,dc=example,dc=test", NewRDN: "uid=x"})
	if res.Code != ResultNoSuchObject {
		t.Fatalf("missing moddn = %v, want noSuchObject", res)
	}
	// Out-of-suffix target refused.
	res = roundTrip(t, cl, &ModifyDNRequest{
		DN:          "uid=alice,ou=teams,dc=example,dc=test",
		NewRDN:      "uid=alice",
		NewSuperior: "dc=other,dc=test",
	})
	if res.Code != ResultUnwillingToPerform {
		t.Fatalf("out-of-suffix moddn = %v, want unwillingToPerform", res)
	}
}

func TestModifyDNDeniedByACI(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, writeOptions(t, func(o *Options) {
		o.ACI = &FakeACI{} // deny all
	}), nil)
	cl := dialTestClient(t, addr)
	res := roundTrip(t, cl, &ModifyDNRequest{
		DN:     "uid=alice,ou=people,dc=example,dc=test",
		NewRDN: "uid=alicia",
	})
	if res.Code != ResultInsufficientAccessRights {
		t.Fatalf("denied moddn = %v, want insufficientAccessRights", res)
	}
}

// TestPluginRunsInCommit proves AfterWrite observes the write inside the
// same Update, and that a plugin error aborts the whole commit (C7).
func TestPluginRunsInCommit(t *testing.T) {
	t.Parallel()
	plugin := &FakePlugin{PluginName: "recorder"}
	opts := writeOptions(t, func(o *Options) { o.Plugins = []Plugin{plugin} })
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)

	res := roundTrip(t, cl, &AddRequest{
		DN:         "uid=frank,ou=people,dc=example,dc=test",
		Attributes: []Attribute{StringAttribute("objectClass", "top", "person")},
	})
	if res.Code != ResultSuccess {
		t.Fatalf("add = %v", res)
	}
	evs := plugin.Events()
	if len(evs) != 1 || evs[0].Op != WriteAdd || evs[0].After == nil {
		t.Fatalf("plugin events = %+v", evs)
	}
	if evs[0].After.DN != "uid=frank,ou=people,dc=example,dc=test" {
		t.Fatalf("plugin saw DN %q", evs[0].After.DN)
	}

	// A failing plugin rolls the write back: the entry must not exist.
	bad := &FakePlugin{PluginName: "veto", Err: errTestVeto}
	opts2 := writeOptions(t, func(o *Options) { o.Plugins = []Plugin{bad} })
	_, addr2 := serveTestServerFrom(t, opts2, nil)
	cl2 := dialTestClient(t, addr2)
	res = roundTrip(t, cl2, &AddRequest{
		DN:         "uid=gone,ou=people,dc=example,dc=test",
		Attributes: []Attribute{StringAttribute("objectClass", "top")},
	})
	if res.Code != ResultUnwillingToPerform {
		t.Fatalf("vetoed add = %v, want unwillingToPerform", res)
	}
	if _, err := fetchEntry(t, opts2, "uid=gone,ou=people,dc=example,dc=test"); err == nil {
		t.Fatal("vetoed add committed")
	}
}

var errTestVeto = errors.New("test veto")

// TestWriteOpsOverTCPEndToEnd drives the full wire path once: bind, then
// add, modify, compare, rename, delete — the T-128 protocol-level chain.
func TestWriteOpsOverTCPEndToEnd(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, writeOptions(t, func(o *Options) {
		o.AllowCleartextBind = true
		ctx := context.Background()
		if err := o.Store.Update(ctx, func(tx UpdateTx) error {
			dn, _ := config.ParseDN("uid=alice,ou=people,dc=example,dc=test")
			e, err := tx.Entry(ctx, dn)
			if err != nil {
				return err
			}
			e.Attributes = append(e.Attributes, StringAttribute("userPassword", "alice-fixture-password"))
			return tx.Replace(ctx, e)
		}); err != nil {
			t.Fatalf("seed password: %v", err)
		}
	}), nil)
	cl := dialTestClient(t, addr)

	if res := bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "alice-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("bind = %v", res)
	}
	steps := []struct {
		name string
		op   Operation
		want ResultCode
	}{
		{"add", &AddRequest{
			DN: "uid=zoe,ou=people,dc=example,dc=test",
			Attributes: []Attribute{
				StringAttribute("objectClass", "top", "person"),
				StringAttribute("uid", "zoe"),
				StringAttribute("cn", "Zoe"),
				StringAttribute("sn", "Zahn"),
			},
		}, ResultSuccess},
		{"modify", &ModifyRequest{DN: "uid=zoe,ou=people,dc=example,dc=test", Changes: []ModifyChange{
			{Op: ModifyReplace, Attr: StringAttribute("sn", "Young")},
		}}, ResultSuccess},
		{"compare", &CompareRequest{DN: "uid=zoe,ou=people,dc=example,dc=test", Attr: "sn", Value: []byte("Young")}, ResultCompareTrue},
		{"moddn", &ModifyDNRequest{DN: "uid=zoe,ou=people,dc=example,dc=test", NewRDN: "uid=zoey", DeleteOldRDN: true}, ResultSuccess},
		{"delete", &DeleteRequest{DN: "uid=zoey,ou=people,dc=example,dc=test"}, ResultSuccess},
	}
	for _, step := range steps {
		if res := roundTrip(t, cl, step.op); res.Code != step.want {
			t.Fatalf("%s = %v, want %v", step.name, res, step.want)
		}
	}
}
