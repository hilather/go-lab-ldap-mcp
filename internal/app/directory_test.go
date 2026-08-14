package app

import (
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

func TestSearchRedactsSecretsAndUnavailable(t *testing.T) {
	t.Parallel()
	q := New(Deps{
		Search: fakeSearch{page: directory.SearchPage{Entries: []directory.SearchEntry{{
			DN: "uid=alice,ou=people,dc=example,dc=test",
			Attributes: []directory.AttrKV{
				{Name: "cn", Value: "Alice"},
				{Name: "userPassword", Value: "unit-search-pass-12"},
			},
		}}}},
	}).Query
	page, err := q.Search(t.Context(), writer(), directory.SearchQuery{Filter: "(uid=alice)"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Entries) != 1 || len(page.Entries[0].Attributes) != 1 || page.Entries[0].Attributes[0].Name != "cn" {
		t.Fatalf("redaction: %+v", page.Entries)
	}

	down := New(Deps{Search: fakeSearch{err: directory.Error("connection", directory.FieldUnavailable, "directory unavailable")}}).Query
	_, err = down.Search(t.Context(), writer(), directory.SearchQuery{Filter: "(uid=a)"})
	if err == nil || !isUnavailable(err) {
		t.Fatalf("unavailable: %v", err)
	}
}

func TestGetEntryRedactsAndRequiresDN(t *testing.T) {
	t.Parallel()
	q := New(Deps{
		Search: fakeSearch{page: directory.SearchPage{Entries: []directory.SearchEntry{{
			DN: "uid=alice,ou=people,dc=example,dc=test",
			Attributes: []directory.AttrKV{
				{Name: "uid", Value: "alice"},
				{Name: "userPassword", Value: "unit-getentry-pass-12"},
			},
		}}}},
	}).Query
	got, err := q.GetEntry(t.Context(), reader(), "uid=alice,ou=people,dc=example,dc=test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.DN == "" || len(got.Attributes) != 1 || got.Attributes[0].Name != "uid" {
		t.Fatalf("redaction: %+v", got)
	}
	_, err = q.GetEntry(t.Context(), reader(), "  ", nil)
	if err == nil || apperr.CodeOf(err) != apperr.CodeConfiguration {
		t.Fatalf("empty dn: %v", err)
	}
	missing := New(Deps{Search: fakeSearch{page: directory.SearchPage{}}}).Query
	_, err = missing.GetEntry(t.Context(), reader(), "uid=missing,dc=example,dc=test", nil)
	if err == nil || apperr.CodeOf(err) != apperr.CodeDirectory {
		t.Fatalf("not found: %v", err)
	}
}

func TestBindTestPasswordScope(t *testing.T) {
	t.Parallel()
	q := New(Deps{Bind: fakeBind{res: directory.BindTestResult{Outcome: directory.BindOutcomeSuccess}}}).Query
	_, err := q.BindTest(t.Context(), reader(), "alice", observability.Secret("unit-bind-pass-12"), directory.TransportLDAPS)
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuth {
		t.Fatalf("password scope: %v", err)
	}
	res, err := q.BindTest(t.Context(), writer(), "alice", observability.Secret("unit-bind-pass-12"), directory.TransportLDAPS)
	if err != nil || res.Outcome != directory.BindOutcomeSuccess {
		t.Fatalf("ok: %+v %v", res, err)
	}
}

func TestSchemaRedactsSecretsAndLooksUpDetails(t *testing.T) {
	t.Parallel()
	q := New(Deps{Schema: fakeSchema{sch: directory.Schema{
		ObjectClasses: []directory.ObjectClass{{
			Name: "inetOrgPerson", OID: "2.16.840.1.113730.3.2.2",
			May: []string{"uid", "userPassword", "mail"},
		}},
		Attributes: []directory.AttributeType{
			{Name: "uid", OID: "0.9.2342.19200300.100.1.1"},
			{Name: "userPassword"},
			{Name: "nsslapd-rootpw"},
			{Name: "nsds5replicaCredentials"},
		},
	}}}).Query
	schemaP := Principal{Kind: KindToken, ID: "s", Scopes: directory.ScopeSet{"schema:read"}}
	sch, err := q.Schema(t.Context(), schemaP)
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range sch.Attributes {
		if secretSchemaAttr(at.Name) {
			t.Fatalf("secret schema attr leaked: %s", at.Name)
		}
	}
	if len(sch.Attributes) != 1 || sch.Attributes[0].Name != "uid" {
		t.Fatalf("schema attrs %+v", sch.Attributes)
	}
	oc, err := q.ObjectClass(t.Context(), schemaP, "INETORGPERSON")
	if err != nil || oc.Name != "inetOrgPerson" {
		t.Fatalf("object class %+v %v", oc, err)
	}
	for _, n := range oc.May {
		if secretSchemaAttr(n) {
			t.Fatalf("secret name in MAY: %s", n)
		}
	}
	at, err := q.AttributeType(t.Context(), schemaP, "uid")
	if err != nil || at.Name != "uid" {
		t.Fatalf("attribute %+v %v", at, err)
	}
	if _, err := q.AttributeType(t.Context(), schemaP, "userPassword"); err == nil || fieldCode(err) != directory.FieldNotFound {
		t.Fatalf("secret attribute detail: %v", err)
	}
	if _, err := q.ObjectClass(t.Context(), reader(), "inetOrgPerson"); err == nil || apperr.CodeOf(err) != apperr.CodeAuth {
		t.Fatalf("schema:read required: %v", err)
	}
}

func TestSchemaAndCapabilitiesScopes(t *testing.T) {
	t.Parallel()
	q := New(Deps{
		Schema: fakeSchema{dse: directory.RootDSE{VendorName: "389 Project"}, sch: directory.Schema{}},
		Caps:   fakeCaps{caps: directory.Capabilities{EngineVendor: "389 Project", Controls: []string{directory.ControlAssertionOID}, RequiredOK: true}},
	}).Query
	if _, err := q.RootDSE(t.Context(), reader()); err == nil {
		t.Fatal("schema:read required")
	}
	schemaP := Principal{Kind: KindToken, ID: "s", Scopes: directory.ScopeSet{"schema:read"}}
	dse, err := q.RootDSE(t.Context(), schemaP)
	if err != nil || dse.VendorName == "" {
		t.Fatalf("rootdse: %+v %v", dse, err)
	}
	_, err = q.Capabilities(t.Context(), writer())
	if err != nil {
		t.Fatal(err)
	}
}

func TestBaselineSeparatesRevisions(t *testing.T) {
	t.Parallel()
	q := New(Deps{
		Marker: fakeMarker{m: directory.BaselineMarker{
			DN: "cn=labldap-baseline,dc=example,dc=test", AppliedRevision: "aaa", ExpectedRevision: "aaa",
		}},
		ExpectedRevision: "aaa",
		ControlRevision:  "bbb",
	}).Query
	b, err := q.Baseline(t.Context(), writer())
	if err != nil {
		t.Fatal(err)
	}
	if b.ExpectedRevision != "aaa" || b.AppliedRevision != "aaa" || b.ControlRevision != "bbb" || !b.Match {
		t.Fatalf("%+v", b)
	}
	mismatch := New(Deps{
		Marker:           fakeMarker{m: directory.BaselineMarker{AppliedRevision: "ccc"}},
		ExpectedRevision: "aaa",
		ControlRevision:  "bbb",
	}).Query
	got, err := mismatch.Baseline(t.Context(), writer())
	if err != nil || got.Match || got.AppliedRevision != "ccc" || got.ControlRevision != "bbb" {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestResetExportScopesIndependent(t *testing.T) {
	t.Parallel()
	p := writer()
	az := ScopeAuthorizer{}
	if az.Authorize(p, OpReset) == nil {
		t.Fatal("write must not imply lab:reset")
	}
	if az.Authorize(p, OpExport) == nil {
		t.Fatal("write must not imply lab:export")
	}
	if az.Authorize(p, OpUserPassword) != nil {
		t.Fatal("writer fixture includes password")
	}
}

func TestMarkerReadOnlyDoesNotWrite(t *testing.T) {
	t.Parallel()
	var _ directory.MarkerReader = fakeMarker{}
}
