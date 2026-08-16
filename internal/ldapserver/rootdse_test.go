package ldapserver

import (
	"context"
	"strings"
	"testing"
)

// schemaWireOptions serves the seeded tree with the real contract schema
// registry (T-132) so Add/Modify run the MUST/MAY gate.
func schemaWireOptions(t *testing.T, mutate func(*Options)) Options {
	t.Helper()
	std := mustStandardSchema(t)
	return writeOptions(t, func(o *Options) {
		o.Schema = std
		if mutate != nil {
			mutate(o)
		}
	})
}

// dseAttr returns one attribute's values from a search entry.
func dseAttr(e *SearchResultEntry, name string) []string {
	var out []string
	for _, a := range e.Attributes {
		if strings.EqualFold(a.Name, name) {
			for _, v := range a.Values {
				out = append(out, string(v))
			}
		}
	}
	return out
}

// TestRootDSESearch: base-object search on "" returns the C10 publication
// set with Delta D1 vendor identity (T-132 acceptance).
func TestRootDSESearch(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, schemaWireOptions(t, nil), nil)
	cl := dialTestClient(t, addr)

	entries, done := search(t, cl, &SearchRequest{
		BaseDN: "", Scope: ScopeBaseObject, Filter: &FilterPresent{Attr: "objectClass"},
	})
	if done.Result.Code != ResultSuccess {
		t.Fatalf("root dse search: %v", done.Result)
	}
	if len(entries) != 1 || entries[0].DN != "" {
		t.Fatalf("entries = %+v", entries)
	}
	e := entries[0]

	if got := dseAttr(e, "namingContexts"); len(got) != 1 || got[0] != "dc=example,dc=test" {
		t.Errorf("namingContexts = %v", got)
	}
	if got := dseAttr(e, "subschemaSubentry"); len(got) != 1 || got[0] != SubschemaDN {
		t.Errorf("subschemaSubentry = %v", got)
	}
	if got := dseAttr(e, "supportedLDAPVersion"); len(got) != 1 || got[0] != "3" {
		t.Errorf("supportedLDAPVersion = %v", got)
	}
	controls := dseAttr(e, "supportedControl")
	if len(controls) != 1 || controls[0] != OIDSimplePagedResults {
		t.Errorf("supportedControl = %v", controls)
	}
	for _, ctl := range controls {
		if ctl == OIDAssertion {
			t.Error("assertion control advertised before T-141 honors it (C9)")
		}
	}
	if got := dseAttr(e, "supportedExtension"); len(got) == 0 {
		t.Error("supportedExtension empty")
	}
	// D1: distinct native vendor identity, never the 389 strings.
	vendor := dseAttr(e, "vendorName")
	if len(vendor) != 1 || vendor[0] != VendorName || strings.Contains(vendor[0], "389") {
		t.Errorf("vendorName = %v", vendor)
	}
	version := dseAttr(e, "vendorVersion")
	if len(version) != 1 || version[0] == "" || strings.Contains(version[0], "389-Directory") {
		t.Errorf("vendorVersion = %v", version)
	}
}

// TestRootDSECapabilityShape: the Root DSE carries exactly the field set
// the control plane's capability inspect reads (ds389 Capabilities:
// vendorName, vendorVersion, supportedControl, supportedLDAPVersion,
// namingContexts, subschemaSubentry), so requiredOK's measurement gate is
// satisfiable against the native engine (T-132 acceptance).
func TestRootDSECapabilityShape(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, schemaWireOptions(t, nil), nil)
	cl := dialTestClient(t, addr)

	want := []string{
		"vendorName", "vendorVersion", "supportedControl",
		"supportedLDAPVersion", "namingContexts", "subschemaSubentry",
	}
	entries, done := search(t, cl, &SearchRequest{
		BaseDN: "", Scope: ScopeBaseObject,
		Filter:     &FilterPresent{Attr: "objectClass"},
		Attributes: want,
	})
	if done.Result.Code != ResultSuccess || len(entries) != 1 {
		t.Fatalf("search = %v, %d entries", done.Result, len(entries))
	}
	e := entries[0]
	if len(e.Attributes) != len(want) {
		t.Fatalf("returned attributes = %d, want %d", len(e.Attributes), len(want))
	}
	for _, name := range want {
		if got := dseAttr(e, name); len(got) == 0 || got[0] == "" {
			t.Errorf("%s missing or empty", name)
		}
	}
}

func TestRootDSEScopeFilterAndSelection(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, schemaWireOptions(t, nil), nil)
	cl := dialTestClient(t, addr)

	// Non-base scope on the empty DN: noSuchObject (389-observed shape).
	_, done := search(t, cl, &SearchRequest{
		BaseDN: "", Scope: ScopeWholeSubtree, Filter: &FilterPresent{Attr: "objectClass"},
	})
	if done.Result.Code != ResultNoSuchObject {
		t.Fatalf("subtree root dse = %v, want noSuchObject", done.Result)
	}

	// A filter that does not match yields success with zero entries.
	entries, done := search(t, cl, &SearchRequest{
		BaseDN: "", Scope: ScopeBaseObject,
		Filter: &FilterEquality{Attr: "vendorName", Value: []byte("No Such Vendor")},
	})
	if done.Result.Code != ResultSuccess || len(entries) != 0 {
		t.Fatalf("non-matching filter = %v, %d entries", done.Result, len(entries))
	}
	// An equality filter that does match returns the DSE.
	entries, done = search(t, cl, &SearchRequest{
		BaseDN: "", Scope: ScopeBaseObject,
		Filter: &FilterEquality{Attr: "vendorName", Value: []byte(VendorName)},
	})
	if done.Result.Code != ResultSuccess || len(entries) != 1 {
		t.Fatalf("matching filter = %v, %d entries", done.Result, len(entries))
	}

	// Explicit selection returns only the named attribute.
	entries, done = search(t, cl, &SearchRequest{
		BaseDN: "", Scope: ScopeBaseObject, Filter: &FilterPresent{Attr: "objectClass"},
		Attributes: []string{"namingContexts"},
	})
	if done.Result.Code != ResultSuccess || len(entries) != 1 {
		t.Fatalf("selection = %v", done.Result)
	}
	if len(entries[0].Attributes) != 1 || !strings.EqualFold(entries[0].Attributes[0].Name, "namingContexts") {
		t.Fatalf("selected attributes = %+v", entries[0].Attributes)
	}

	// "1.1" suppresses all attributes.
	entries, done = search(t, cl, &SearchRequest{
		BaseDN: "", Scope: ScopeBaseObject, Filter: &FilterPresent{Attr: "objectClass"},
		Attributes: []string{"1.1"},
	})
	if done.Result.Code != ResultSuccess || len(entries) != 1 || len(entries[0].Attributes) != 0 {
		t.Fatalf("1.1 selection = %v, %+v", done.Result, entries)
	}
}

// TestRootDSEIgnoresACI: the DSE and subschema stay readable when the ACI
// engine denies everything (389-observed; capability inspect runs
// pre-bind).
func TestRootDSEIgnoresACI(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, schemaWireOptions(t, func(o *Options) {
		o.ACI = &FakeACI{} // deny all
	}), nil)
	cl := dialTestClient(t, addr)

	entries, done := search(t, cl, &SearchRequest{
		BaseDN: "", Scope: ScopeBaseObject, Filter: &FilterPresent{Attr: "objectClass"},
	})
	if done.Result.Code != ResultSuccess || len(entries) != 1 {
		t.Fatalf("root dse under deny-all = %v, %d entries", done.Result, len(entries))
	}
	entries, done = search(t, cl, &SearchRequest{
		BaseDN: SubschemaDN, Scope: ScopeBaseObject, Filter: &FilterPresent{Attr: "objectClass"},
	})
	if done.Result.Code != ResultSuccess || len(entries) != 1 {
		t.Fatalf("subschema under deny-all = %v, %d entries", done.Result, len(entries))
	}
}

// TestSubschemaSearch: cn=subschema publishes the C5 classes and the
// 389-isms, and the cn=schema alias serves the 389-shaped capability
// read-back (ds389 schemaHasAccountLock searches cn=schema attributeTypes
// for nsaccountlock).
func TestSubschemaSearch(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, schemaWireOptions(t, nil), nil)
	cl := dialTestClient(t, addr)

	entries, done := search(t, cl, &SearchRequest{
		BaseDN: SubschemaDN, Scope: ScopeBaseObject,
		Filter:     &FilterPresent{Attr: "objectClass"},
		Attributes: []string{"attributeTypes", "objectClasses", "matchingRules"},
	})
	if done.Result.Code != ResultSuccess || len(entries) != 1 {
		t.Fatalf("subschema search = %v, %d entries", done.Result, len(entries))
	}
	e := entries[0]
	if e.DN != SubschemaDN {
		t.Errorf("dn = %q", e.DN)
	}
	lower := func(vals []string) string { return strings.ToLower(strings.Join(vals, "\n")) }
	ats := lower(dseAttr(e, "attributeTypes"))
	if !strings.Contains(ats, "nsaccountlock") {
		t.Error("attributeTypes lacks nsAccountLock (capability inspect reads this)")
	}
	ocs := lower(dseAttr(e, "objectClasses"))
	for _, want := range []string{"inetorgperson", "groupofnames", "nsmemberof"} {
		if !strings.Contains(ocs, want) {
			t.Errorf("objectClasses lacks %s", want)
		}
	}
	if mrs := dseAttr(e, "matchingRules"); len(mrs) == 0 {
		t.Error("matchingRules empty")
	}

	// 389-shaped alias.
	entries, done = search(t, cl, &SearchRequest{
		BaseDN: "cn=schema", Scope: ScopeBaseObject,
		Filter:     &FilterPresent{Attr: "objectClass"},
		Attributes: []string{"attributeTypes"},
	})
	if done.Result.Code != ResultSuccess || len(entries) != 1 || entries[0].DN != "cn=schema" {
		t.Fatalf("cn=schema alias = %v, %+v", done.Result, entries)
	}
	if ats := lower(dseAttr(entries[0], "attributeTypes")); !strings.Contains(ats, "nsaccountlock") {
		t.Error("cn=schema attributeTypes lacks nsAccountLock")
	}

	// One-level under the subschema subentry: no subordinates.
	entries, done = search(t, cl, &SearchRequest{
		BaseDN: SubschemaDN, Scope: ScopeSingleLevel, Filter: &FilterPresent{Attr: "objectClass"},
	})
	if done.Result.Code != ResultSuccess || len(entries) != 0 {
		t.Fatalf("subschema one-level = %v, %d entries", done.Result, len(entries))
	}

	// A non-matching filter filters the subentry out.
	entries, done = search(t, cl, &SearchRequest{
		BaseDN: SubschemaDN, Scope: ScopeBaseObject,
		Filter: &FilterEquality{Attr: "objectClass", Value: []byte("noSuchClass")},
	})
	if done.Result.Code != ResultSuccess || len(entries) != 0 {
		t.Fatalf("filtered subschema = %v, %d entries", done.Result, len(entries))
	}
}

// TestAddSchemaEnforcement wires the T-132 gate over the wire: a user
// without sn fails objectClassViolation (acceptance), and the 389-observed
// marker shape (device with out-of-MAY attributes) is accepted.
func TestAddSchemaEnforcement(t *testing.T) {
	t.Parallel()
	opts := schemaWireOptions(t, nil)
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)

	// Missing sn: objectClassViolation (T-132 acceptance).
	res := roundTrip(t, cl, &AddRequest{
		DN: "uid=nosn,ou=people,dc=example,dc=test",
		Attributes: []Attribute{
			StringAttribute("objectClass", "top", "person", "organizationalPerson", "inetOrgPerson"),
			StringAttribute("uid", "nosn"),
			StringAttribute("cn", "No Surname"),
		},
	})
	if res.Code != ResultObjectClassViolation {
		t.Fatalf("add without sn = %v, want objectClassViolation", res)
	}
	if !strings.Contains(res.DiagnosticMessage, "sn") {
		t.Fatalf("diagnostic should name the missing attribute: %q", res.DiagnosticMessage)
	}

	// Unknown objectClass: objectClassViolation.
	res = roundTrip(t, cl, &AddRequest{
		DN: "uid=bogus,ou=people,dc=example,dc=test",
		Attributes: []Attribute{
			StringAttribute("objectClass", "top", "bogusClass"),
			StringAttribute("cn", "Bogus"),
			StringAttribute("sn", "Bogus"),
		},
	})
	if res.Code != ResultObjectClassViolation {
		t.Fatalf("add unknown oc = %v, want objectClassViolation", res)
	}

	// groupOfNames without member: objectClassViolation (empty groups
	// forbidden, OD-018).
	res = roundTrip(t, cl, &AddRequest{
		DN: "cn=empty,ou=groups,dc=example,dc=test",
		Attributes: []Attribute{
			StringAttribute("objectClass", "top", "groupOfNames"),
			StringAttribute("cn", "empty"),
		},
	})
	if res.Code != ResultObjectClassViolation {
		t.Fatalf("add empty group = %v, want objectClassViolation", res)
	}

	// Valid user succeeds and is readable.
	res = roundTrip(t, cl, &AddRequest{
		DN: "uid=valid,ou=people,dc=example,dc=test",
		Attributes: []Attribute{
			StringAttribute("objectClass", "top", "person", "organizationalPerson", "inetOrgPerson"),
			StringAttribute("uid", "valid"),
			StringAttribute("cn", "Valid User"),
			StringAttribute("sn", "User"),
			StringAttribute("nsAccountLock", "true"),
		},
	})
	if res.Code != ResultSuccess {
		t.Fatalf("add valid user = %v", res)
	}
	if e, err := fetchEntry(t, opts, "uid=valid,ou=people,dc=example,dc=test"); err != nil || len(e.Values("nsAccountLock")) != 1 {
		t.Fatalf("read back = %v, %v", e, err)
	}

	// The 389-observed baseline marker shape succeeds: device carries
	// serialNumber/owner/destinationIndicator/description.
	res = roundTrip(t, cl, &AddRequest{
		DN: "cn=labldap-baseline,dc=example,dc=test",
		Attributes: []Attribute{
			StringAttribute("objectClass", "top", "device"),
			StringAttribute("cn", "labldap-baseline"),
			StringAttribute("serialNumber", "rev-1"),
			StringAttribute("owner", "v0.1.0"),
			StringAttribute("destinationIndicator", "rev-1"),
			StringAttribute("description", "{}"),
		},
	})
	if res.Code != ResultSuccess {
		t.Fatalf("add marker = %v, want success (389 marker parity)", res)
	}
}

// TestModifySchemaEnforcement: a modify leaving the entry without a MUST
// attribute, without objectClass, or with an unknown class fails
// objectClassViolation and rolls back; unrelated attribute edits pass.
func TestModifySchemaEnforcement(t *testing.T) {
	t.Parallel()
	opts := schemaWireOptions(t, nil)
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	dn := "uid=alice,ou=people,dc=example,dc=test" // seeded: top, person + cn + sn

	// Deleting sn (MUST on person) fails and rolls back.
	res := roundTrip(t, cl, &ModifyRequest{DN: dn, Changes: []ModifyChange{
		{Op: ModifyDelete, Attr: Attribute{Name: "sn"}},
	}})
	if res.Code != ResultObjectClassViolation {
		t.Fatalf("delete sn = %v, want objectClassViolation", res)
	}
	if e, err := fetchEntry(t, opts, dn); err != nil || len(e.Values("sn")) != 1 {
		t.Fatalf("sn after rollback = %v, %v", e, err)
	}

	// Replacing objectClass with an unknown class fails.
	res = roundTrip(t, cl, &ModifyRequest{DN: dn, Changes: []ModifyChange{
		{Op: ModifyReplace, Attr: StringAttribute("objectClass", "top", "bogusClass")},
	}})
	if res.Code != ResultObjectClassViolation {
		t.Fatalf("replace oc bogus = %v, want objectClassViolation", res)
	}

	// Deleting objectClass entirely fails.
	res = roundTrip(t, cl, &ModifyRequest{DN: dn, Changes: []ModifyChange{
		{Op: ModifyDelete, Attr: Attribute{Name: "objectClass"}},
	}})
	if res.Code != ResultObjectClassViolation {
		t.Fatalf("delete oc = %v, want objectClassViolation", res)
	}

	// An ordinary attribute edit passes the gate.
	res = roundTrip(t, cl, &ModifyRequest{DN: dn, Changes: []ModifyChange{
		{Op: ModifyAdd, Attr: StringAttribute("description", "schema-checked")},
	}})
	if res.Code != ResultSuccess {
		t.Fatalf("add description = %v", res)
	}

	// Upgrading alice to the full user chain keeps MUSTs satisfied.
	res = roundTrip(t, cl, &ModifyRequest{DN: dn, Changes: []ModifyChange{
		{Op: ModifyReplace, Attr: StringAttribute("objectClass", "top", "person", "organizationalPerson", "inetOrgPerson")},
	}})
	if res.Code != ResultSuccess {
		t.Fatalf("upgrade oc = %v", res)
	}
	if e, err := fetchEntry(t, opts, dn); err != nil || len(e.Values("objectClass")) != 4 {
		t.Fatalf("objectClass after upgrade = %v, %v", e, err)
	}
}

// TestSubschemaOutsideStore: the synthetic paths never touch the entry
// store, so they answer on an empty store too.
func TestSubschemaOutsideStore(t *testing.T) {
	t.Parallel()
	std := mustStandardSchema(t)
	opts := testOptions()
	opts.Codec = NewBERCodec(BERCodecOptions{})
	opts.Schema = std
	opts.ACI = &FakeACI{Decide: func(ctx context.Context, tx ReadTx, check ACICheck) (bool, error) {
		return true, nil
	}}
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)

	entries, done := search(t, cl, &SearchRequest{
		BaseDN: "", Scope: ScopeBaseObject, Filter: &FilterPresent{Attr: "objectClass"},
	})
	if done.Result.Code != ResultSuccess || len(entries) != 1 {
		t.Fatalf("root dse on empty store = %v", done.Result)
	}
	entries, done = search(t, cl, &SearchRequest{
		BaseDN: SubschemaDN, Scope: ScopeBaseObject, Filter: &FilterPresent{Attr: "objectClass"},
	})
	if done.Result.Code != ResultSuccess || len(entries) != 1 {
		t.Fatalf("subschema on empty store = %v", done.Result)
	}
}
