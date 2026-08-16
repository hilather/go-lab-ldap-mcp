package ldapserver

import (
	"errors"
	"strings"
	"testing"
)

func mustStandardSchema(t *testing.T) *Registry {
	t.Helper()
	s, err := StandardSchema()
	if err != nil {
		t.Fatalf("StandardSchema: %v", err)
	}
	return s
}

// TestStandardSchemaContents proves the contract object classes (C5) and
// the ADR-0009 389-isms are registered and resolvable by name and OID.
func TestStandardSchemaContents(t *testing.T) {
	t.Parallel()
	s := mustStandardSchema(t)

	for _, name := range []string{
		"top", "domain", "organizationalUnit", "person", "organizationalPerson",
		"inetOrgPerson", "groupOfNames", "groupOfUniqueNames",
		"nsmemberof", "device", "subschema",
	} {
		if _, ok := s.ObjectClass(name); !ok {
			t.Errorf("object class %s missing", name)
		}
		// Case-insensitive name resolution.
		if _, ok := s.ObjectClass(strings.ToUpper(name)); !ok {
			t.Errorf("object class %s not case-insensitive", name)
		}
	}
	// OID resolution.
	oc, ok := s.ObjectClass("2.16.840.1.113730.3.2.2")
	if !ok || oc.Name != "inetOrgPerson" {
		t.Errorf("oid lookup = %+v, %v", oc, ok)
	}
	if oc, ok := s.ObjectClass("nsmemberof"); !ok || oc.Kind != ObjectClassAuxiliary {
		t.Errorf("nsmemberof = %+v, %v (want AUXILIARY)", oc, ok)
	}
	if oc, ok := s.ObjectClass("top"); !ok || oc.Kind != ObjectClassAbstract {
		t.Errorf("top = %+v, %v (want ABSTRACT)", oc, ok)
	}

	for _, name := range []string{
		"objectClass", "cn", "sn", "ou", "dc", "uid", "description",
		"member", "uniqueMember", "memberOf", "userPassword",
		"nsAccountLock", "pwdAccountLockedTime", "aci",
		"createTimestamp", "modifyTimestamp", "modifiersName", "entryUUID",
		"namingContexts", "subschemaSubentry", "supportedControl",
		"supportedExtension", "supportedLDAPVersion", "vendorName", "vendorVersion",
		"attributeTypes", "objectClasses", "matchingRules",
	} {
		if _, ok := s.AttributeType(name); !ok {
			t.Errorf("attribute type %s missing", name)
		}
	}
	at, ok := s.AttributeType("2.16.840.1.113730.3.1.610")
	if !ok || at.Name != "nsAccountLock" || !at.SingleValue {
		t.Errorf("nsAccountLock by oid = %+v, %v", at, ok)
	}
	if at, ok := s.AttributeType("entryUUID"); !ok || !at.Operational {
		t.Errorf("entryUUID = %+v, %v (want operational)", at, ok)
	}
	if _, ok := s.ObjectClass("notARealClass"); ok {
		t.Error("unknown object class resolved")
	}
	if _, ok := s.AttributeType("notARealAttr"); ok {
		t.Error("unknown attribute type resolved")
	}
}

// TestStandardSchemaSelfConsistency: NewRegistry validation guarantees it,
// and this pins the invariant for future table edits.
func TestStandardSchemaSelfConsistency(t *testing.T) {
	t.Parallel()
	s := mustStandardSchema(t)
	for _, oc := range s.ObjectClasses() {
		for _, sup := range oc.Sup {
			if _, ok := s.ObjectClass(sup); !ok {
				t.Errorf("%s: SUP %s unresolved", oc.Name, sup)
			}
		}
		for _, attr := range append(append([]string(nil), oc.Must...), oc.May...) {
			if _, ok := s.AttributeType(attr); !ok {
				t.Errorf("%s: attribute %s unresolved", oc.Name, attr)
			}
		}
	}
}

func TestNewRegistryValidation(t *testing.T) {
	t.Parallel()
	cn := AttributeTypeDef{OID: "2.5.4.3", Name: "cn"}
	person := ObjectClassDef{OID: "2.5.6.6", Name: "person", Kind: ObjectClassStructural, Sup: []string{"top"}, Must: []string{"cn"}}
	top := ObjectClassDef{OID: "2.5.6.0", Name: "top", Kind: ObjectClassAbstract}

	if _, err := NewRegistry([]ObjectClassDef{top, person}, []AttributeTypeDef{cn}); err != nil {
		t.Fatalf("valid registry: %v", err)
	}
	// Duplicate name (case-insensitive).
	dup := ObjectClassDef{OID: "2.5.6.66", Name: "PERSON"}
	if _, err := NewRegistry([]ObjectClassDef{person, dup}, []AttributeTypeDef{cn}); err == nil {
		t.Fatal("duplicate object class name accepted")
	}
	// Unknown SUP.
	badSup := ObjectClassDef{OID: "2.5.6.7", Name: "organizationalPerson", Sup: []string{"ghost"}}
	if _, err := NewRegistry([]ObjectClassDef{top, badSup}, []AttributeTypeDef{cn}); err == nil {
		t.Fatal("unknown SUP accepted")
	}
	// Unknown MUST attribute.
	badMust := ObjectClassDef{OID: "2.5.6.8", Name: "x", Must: []string{"ghostAttr"}}
	if _, err := NewRegistry([]ObjectClassDef{top, badMust}, []AttributeTypeDef{cn}); err == nil {
		t.Fatal("unknown MUST attribute accepted")
	}
	// Missing name.
	if _, err := NewRegistry([]ObjectClassDef{{OID: "1.2.3"}}, nil); err == nil {
		t.Fatal("nameless object class accepted")
	}
}

// TestCheckEntrySchema pins the MUST/MAY enforcement semantics (T-132).
func TestCheckEntrySchema(t *testing.T) {
	t.Parallel()
	std := mustStandardSchema(t)

	user := func(attrs ...Attribute) *Entry {
		base := []Attribute{StringAttribute("objectClass", "top", "person", "organizationalPerson", "inetOrgPerson")}
		return NewEntry("uid=u,ou=people,dc=example,dc=test", append(base, attrs...)...)
	}

	cases := []struct {
		name    string
		schema  Schema
		entry   *Entry
		wantErr string // empty: valid; otherwise substring of the reason
	}{
		{
			name:   "valid inetOrgPerson user",
			schema: std,
			entry: user(
				StringAttribute("uid", "u"),
				StringAttribute("cn", "User One"),
				StringAttribute("sn", "One"),
			),
		},
		{
			name:   "missing sn fails (T-132 acceptance)",
			schema: std,
			entry: user(
				StringAttribute("uid", "u"),
				StringAttribute("cn", "User One"),
			),
			wantErr: `"sn"`,
		},
		{
			name:    "empty MUST value fails",
			schema:  std,
			entry:   NewEntry("cn=g,ou=groups,dc=example,dc=test", StringAttribute("objectClass", "top", "groupOfNames"), StringAttribute("cn", "g"), Attribute{Name: "member"}),
			wantErr: `"member"`,
		},
		{
			name:    "unknown object class fails",
			schema:  std,
			entry:   NewEntry("cn=x,dc=example,dc=test", StringAttribute("objectClass", "top", "bogusClass"), StringAttribute("cn", "x")),
			wantErr: "unknown object class",
		},
		{
			name:    "no objectClass fails",
			schema:  std,
			entry:   NewEntry("cn=x,dc=example,dc=test", StringAttribute("cn", "x")),
			wantErr: "no objectClass",
		},
		{
			name:   "groupOfUniqueNames with uniqueMember",
			schema: std,
			entry: NewEntry("cn=g,ou=groups,dc=example,dc=test",
				StringAttribute("objectClass", "top", "groupOfUniqueNames"),
				StringAttribute("cn", "g"),
				StringAttribute("uniqueMember", "uid=u,ou=people,dc=example,dc=test")),
		},
		{
			// OD-012: the baseline marker is device + description JSON.
			// destinationIndicator/owner extras are not required and
			// destinationIndicator is not in device MAY (D17).
			name:   "marker device with description JSON passes",
			schema: std,
			entry: NewEntry("cn=labldap-baseline,dc=example,dc=test",
				StringAttribute("objectClass", "top", "device"),
				StringAttribute("cn", "labldap-baseline"),
				StringAttribute("description", `{"serialNumber":"rev-1"}`)),
		},
		{
			name:   "marker extra destinationIndicator fails MAY",
			schema: std,
			entry: NewEntry("cn=labldap-baseline,dc=example,dc=test",
				StringAttribute("objectClass", "top", "device"),
				StringAttribute("cn", "labldap-baseline"),
				StringAttribute("destinationIndicator", "rev-1"),
				StringAttribute("description", "{}")),
			wantErr: `"destinationIndicator"`,
		},
		{
			name:   "unknown attribute fails",
			schema: std,
			entry: NewEntry("cn=unknownattr,dc=example,dc=test",
				StringAttribute("objectClass", "top", "device"),
				StringAttribute("cn", "unknownattr"),
				StringAttribute("xyzzyUndefinedAttr", "1")),
			wantErr: `"xyzzyUndefinedAttr"`,
		},
		{
			// Server-owned operational stamps ride on every stored
			// entry; they are not in device MAY and must still pass.
			name:   "operational attributes remain allowed",
			schema: std,
			entry: NewEntry("cn=labldap-baseline,dc=example,dc=test",
				StringAttribute("objectClass", "top", "device"),
				StringAttribute("cn", "labldap-baseline"),
				StringAttribute("description", "{}"),
				StringAttribute("entryUUID", "uuid-1"),
				StringAttribute("createTimestamp", "20260815120000Z"),
				StringAttribute("modifyTimestamp", "20260815120000Z")),
		},
		{
			name:    "empty registry permits everything (T-128 seam)",
			schema:  NewFakeSchema(nil, nil),
			entry:   NewEntry("cn=x,dc=example,dc=test", StringAttribute("objectClass", "bogusClass")),
			wantErr: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := checkEntrySchema(tc.schema, tc.entry)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("checkEntrySchema = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("checkEntrySchema = nil, want %q", tc.wantErr)
			}
			if !errors.Is(err, errSchemaViolation) {
				t.Fatalf("error %v does not unwrap to errSchemaViolation", err)
			}
			var sv *schemaViolation
			if !errors.As(err, &sv) || !strings.Contains(sv.reason, tc.wantErr) {
				t.Fatalf("reason = %q, want substring %s", err, tc.wantErr)
			}
		})
	}
}

// TestCheckEntrySchemaSUPChain: cn/sn are MUST on person and inherited by
// inetOrgPerson through the SUP chain.
func TestCheckEntrySchemaSUPChain(t *testing.T) {
	t.Parallel()
	std := mustStandardSchema(t)
	e := NewEntry("uid=u,ou=people,dc=example,dc=test",
		StringAttribute("objectClass", "inetOrgPerson"),
		StringAttribute("uid", "u"),
		StringAttribute("sn", "One"))
	if err := checkEntrySchema(std, e); err == nil || !strings.Contains(err.Error(), `"cn"`) {
		t.Fatalf("inherited MUST cn not enforced: %v", err)
	}
}

func TestFormatObjectClass(t *testing.T) {
	t.Parallel()
	oc := ObjectClassDef{
		OID: "2.5.6.6", Name: "person", Kind: ObjectClassStructural,
		Sup: []string{"top"}, Must: []string{"sn", "cn"}, May: []string{"userPassword", "description"},
	}
	want := "( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ description ) )"
	if got := formatObjectClass(oc); got != want {
		t.Fatalf("formatObjectClass =\n%s\nwant\n%s", got, want)
	}
	// Abstract class with a lone MUST and no SUP.
	top := ObjectClassDef{OID: "2.5.6.0", Name: "top", Kind: ObjectClassAbstract, Must: []string{"objectClass"}}
	wantTop := "( 2.5.6.0 NAME 'top' ABSTRACT MUST ( objectClass ) )"
	if got := formatObjectClass(top); got != wantTop {
		t.Fatalf("formatObjectClass(top) = %s, want %s", got, wantTop)
	}
}

func TestFormatAttributeType(t *testing.T) {
	t.Parallel()
	at := AttributeTypeDef{OID: "2.16.840.1.113730.3.1.610", Name: "nsAccountLock", Equality: "caseIgnoreMatch", Syntax: syntaxDirectoryString, SingleValue: true}
	want := "( 2.16.840.1.113730.3.1.610 NAME 'nsAccountLock' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )"
	if got := formatAttributeType(at); got != want {
		t.Fatalf("formatAttributeType =\n%s\nwant\n%s", got, want)
	}
	op := AttributeTypeDef{OID: "2.5.18.1", Name: "createTimestamp", Equality: "generalizedTimeMatch", Syntax: syntaxGeneralizedTime, SingleValue: true, Operational: true}
	got := formatAttributeType(op)
	if !strings.HasSuffix(got, "SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )") {
		t.Fatalf("operational form = %s", got)
	}
}

// TestSubschemaEntryContents: the subschema publishes what C10 requires
// clients to find, including the 389-isms.
func TestSubschemaEntryContents(t *testing.T) {
	t.Parallel()
	std := mustStandardSchema(t)
	e := subschemaEntry(std, SubschemaDN)
	if e.DN != SubschemaDN {
		t.Fatalf("dn = %q", e.DN)
	}
	join := func(vals [][]byte) string {
		var b strings.Builder
		for _, v := range vals {
			b.Write(v)
			b.WriteByte('\n')
		}
		return b.String()
	}
	ocs := join(e.Values("objectClasses"))
	for _, want := range []string{
		"NAME 'inetOrgPerson'", "NAME 'groupOfNames'", "NAME 'groupOfUniqueNames'",
		"NAME 'nsmemberof'", "NAME 'device'", "NAME 'person'",
	} {
		if !strings.Contains(ocs, want) {
			t.Errorf("objectClasses missing %s", want)
		}
	}
	ats := join(e.Values("attributeTypes"))
	for _, want := range []string{
		"NAME 'nsAccountLock'", "NAME 'memberOf'", "NAME 'member'",
		"2.16.840.1.113730.3.1.610", "NAME 'userPassword'", "NAME 'nsAccountLock' EQUALITY caseIgnoreMatch",
	} {
		if !strings.Contains(ats, want) {
			t.Errorf("attributeTypes missing %s", want)
		}
	}
	mrs := join(e.Values("matchingRules"))
	if !strings.Contains(mrs, "2.5.13.2") || !strings.Contains(mrs, "caseIgnoreMatch") {
		t.Errorf("matchingRules missing caseIgnoreMatch: %s", mrs)
	}
	// The 389-shaped alias echoes the requested DN.
	alias := subschemaEntry(std, "cn=schema")
	if alias.DN != "cn=schema" || string(alias.Values("cn")[0]) != "schema" {
		t.Errorf("alias dn/cn = %q %q", alias.DN, alias.Values("cn"))
	}
}
