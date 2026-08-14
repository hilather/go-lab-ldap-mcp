package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/api/generated"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

func TestRootDSEAndSchemaRequireSchemaRead(t *testing.T) {
	t.Parallel()
	s, _, _, _ := queryServer(t)
	h := s.Handler()

	for _, path := range []string{
		"/api/v1/rootdse",
		"/api/v1/schema",
		"/api/v1/schema/objectclasses/inetOrgPerson",
		"/api/v1/schema/attributes/uid",
	} {
		unauth := httptest.NewRequest(http.MethodGet, path, nil)
		ur := httptest.NewRecorder()
		h.ServeHTTP(ur, unauth)
		if ur.Code != http.StatusUnauthorized {
			t.Fatalf("%s unauth %d %s", path, ur.Code, ur.Body.String())
		}

		read := httptest.NewRequest(http.MethodGet, path, nil)
		read.Header.Set("Authorization", "Bearer "+readOnlyToken)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, read)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s directory:read %d %s", path, rr.Code, rr.Body.String())
		}

		write := httptest.NewRequest(http.MethodGet, path, nil)
		write.Header.Set("Authorization", "Bearer "+writeOnlyToken)
		wr := httptest.NewRecorder()
		h.ServeHTTP(wr, write)
		if wr.Code != http.StatusForbidden {
			t.Fatalf("%s directory:write %d %s", path, wr.Code, wr.Body.String())
		}
	}
}

func TestRootDSEAndSchemaBodies(t *testing.T) {
	t.Parallel()
	s, _, _, _ := queryServer(t)
	h := s.Handler()

	dseReq := httptest.NewRequest(http.MethodGet, "/api/v1/rootdse", nil)
	dseReq.Header.Set("Authorization", "Bearer "+schemaOnlyToken)
	dseRec := httptest.NewRecorder()
	h.ServeHTTP(dseRec, dseReq)
	if dseRec.Code != http.StatusOK {
		t.Fatalf("rootdse %d %s", dseRec.Code, dseRec.Body.String())
	}
	if dseRec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("rootdse cache")
	}
	var dse generated.RootDSE
	decodeOpenAPI(t, dseRec, &dse)
	if dse.VendorName == nil || *dse.VendorName != "389 Project" {
		t.Fatalf("rootdse %+v", dse)
	}
	if dse.NamingContexts == nil || len(*dse.NamingContexts) == 0 {
		t.Fatalf("namingContexts %+v", dse)
	}

	schReq := httptest.NewRequest(http.MethodGet, "/api/v1/schema", nil)
	schReq.Header.Set("Authorization", "Bearer "+schemaOnlyToken)
	schRec := httptest.NewRecorder()
	h.ServeHTTP(schRec, schReq)
	if schRec.Code != http.StatusOK {
		t.Fatalf("schema %d %s", schRec.Code, schRec.Body.String())
	}
	assertNoSecret(t, schRec.Body.String(), "nsslapd-rootpw", bindPass)
	var sch generated.Schema
	decodeOpenAPI(t, schRec, &sch)
	if len(sch.ObjectClasses) != 1 || sch.ObjectClasses[0].Name != "inetOrgPerson" {
		t.Fatalf("object classes %+v", sch.ObjectClasses)
	}
	if len(sch.Attributes) != 1 || sch.Attributes[0].Name != "uid" {
		t.Fatalf("attributes must omit secrets: %+v", sch.Attributes)
	}

	ocReq := httptest.NewRequest(http.MethodGet, "/api/v1/schema/objectclasses/INETORGPERSON", nil)
	ocReq.Header.Set("Authorization", "Bearer "+schemaOnlyToken)
	ocRec := httptest.NewRecorder()
	h.ServeHTTP(ocRec, ocReq)
	if ocRec.Code != http.StatusOK {
		t.Fatalf("object class %d %s", ocRec.Code, ocRec.Body.String())
	}
	var oc generated.ObjectClass
	decodeOpenAPI(t, ocRec, &oc)
	if oc.Name != "inetOrgPerson" || oc.Kind == nil || *oc.Kind != "structural" {
		t.Fatalf("object class %+v", oc)
	}

	atReq := httptest.NewRequest(http.MethodGet, "/api/v1/schema/attributes/uid", nil)
	atReq.Header.Set("Authorization", "Bearer "+schemaOnlyToken)
	atRec := httptest.NewRecorder()
	h.ServeHTTP(atRec, atReq)
	if atRec.Code != http.StatusOK {
		t.Fatalf("attribute %d %s", atRec.Code, atRec.Body.String())
	}
	var at generated.AttributeType
	decodeOpenAPI(t, atRec, &at)
	if at.Name != "uid" || at.SingleValue == nil || !*at.SingleValue {
		t.Fatalf("attribute %+v", at)
	}

	secret := httptest.NewRequest(http.MethodGet, "/api/v1/schema/attributes/userPassword", nil)
	secret.Header.Set("Authorization", "Bearer "+schemaOnlyToken)
	secRec := httptest.NewRecorder()
	h.ServeHTTP(secRec, secret)
	if secRec.Code != http.StatusNotFound {
		t.Fatalf("secret attribute detail %d %s", secRec.Code, secRec.Body.String())
	}
	assertProblem(t, secRec, "directory")

	missing := httptest.NewRequest(http.MethodGet, "/api/v1/schema/objectclasses/no-such-class", nil)
	missing.Header.Set("Authorization", "Bearer "+schemaOnlyToken)
	mr := httptest.NewRecorder()
	h.ServeHTTP(mr, missing)
	if mr.Code != http.StatusNotFound {
		t.Fatalf("missing class %d %s", mr.Code, mr.Body.String())
	}
}

func TestSchemaUnavailableWithoutService(t *testing.T) {
	t.Parallel()
	reg, err := auth.NewRegistry([]auth.Token{{
		ID:     "schema",
		Scopes: []string{auth.ScopeSchemaRead},
		Secret: observability.Secret(schemaOnlyToken),
	}})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{Registry: reg})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/schema", nil)
	req.Header.Set("Authorization", "Bearer "+schemaOnlyToken)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	assertProblem(t, rec, "directory")
}
