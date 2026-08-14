package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/api/generated"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

func TestGroupCRUDAndEmptyCreate(t *testing.T) {
	t.Parallel()
	s, users, _ := directoryServer(t)
	h := s.Handler()
	users.mu.Lock()
	users.put(directory.User{ID: "alice", UID: "alice"})
	users.mu.Unlock()

	empty := httptest.NewRequest(http.MethodPost, "/api/v1/groups", strings.NewReader(`{"id":"staff","members":[]}`))
	empty.Header.Set("Authorization", "Bearer "+testToken)
	empty.Header.Set("Content-Type", "application/json")
	er := httptest.NewRecorder()
	h.ServeHTTP(er, empty)
	if er.Code != http.StatusBadRequest {
		t.Fatalf("empty create %d %s", er.Code, er.Body.String())
	}
	assertProblem(t, er, "configuration")
	var problem generated.Problem
	decodeOpenAPI(t, er, &problem)
	if problem.Errors == nil || len(*problem.Errors) == 0 || (*problem.Errors)[0].Code != "empty_group" {
		t.Fatalf("empty_group field: %s", er.Body.String())
	}

	omit := httptest.NewRequest(http.MethodPost, "/api/v1/groups", strings.NewReader(`{"id":"staff"}`))
	omit.Header.Set("Authorization", "Bearer "+testToken)
	omit.Header.Set("Content-Type", "application/json")
	or := httptest.NewRecorder()
	h.ServeHTTP(or, omit)
	if or.Code != http.StatusBadRequest {
		t.Fatalf("omitted members %d %s", or.Code, or.Body.String())
	}

	create := httptest.NewRequest(http.MethodPost, "/api/v1/groups", strings.NewReader(`{"id":"staff","members":[{"kind":"user","id":"alice"}]}`))
	create.Header.Set("Authorization", "Bearer "+testToken)
	create.Header.Set("Content-Type", "application/json")
	cr := httptest.NewRecorder()
	h.ServeHTTP(cr, create)
	if cr.Code != http.StatusCreated {
		t.Fatalf("create %d %s", cr.Code, cr.Body.String())
	}
	if cr.Header().Get("Location") != "/api/v1/groups/staff" {
		t.Fatalf("location %q", cr.Header().Get("Location"))
	}
	if cr.Header().Get("ETag") == "" {
		t.Fatal("missing etag")
	}
	var created generated.Group
	decodeOpenAPI(t, cr, &created)
	if created.Id != "staff" || created.Revision == "" || len(created.Members) != 1 {
		t.Fatalf("created %+v", created)
	}

	get := httptest.NewRequest(http.MethodGet, "/api/v1/groups/staff", nil)
	get.Header.Set("Authorization", "Bearer "+readOnlyToken)
	gr := httptest.NewRecorder()
	h.ServeHTTP(gr, get)
	if gr.Code != http.StatusOK {
		t.Fatalf("get %d %s", gr.Code, gr.Body.String())
	}
	if gr.Header().Get("ETag") != cr.Header().Get("ETag") {
		t.Fatalf("get etag %q", gr.Header().Get("ETag"))
	}

	patch := httptest.NewRequest(http.MethodPatch, "/api/v1/groups/staff", strings.NewReader(`{"id":"other"}`))
	patch.Header.Set("Authorization", "Bearer "+testToken)
	patch.Header.Set("Content-Type", "application/json")
	pr := httptest.NewRecorder()
	h.ServeHTTP(pr, patch)
	if pr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("patch groups must not exist: %d %s", pr.Code, pr.Body.String())
	}

	list := httptest.NewRequest(http.MethodGet, "/api/v1/groups", nil)
	list.Header.Set("Authorization", "Bearer "+readOnlyToken)
	lr := httptest.NewRecorder()
	h.ServeHTTP(lr, list)
	if lr.Code != http.StatusOK {
		t.Fatalf("list %d %s", lr.Code, lr.Body.String())
	}
	var page generated.GroupPage
	decodeOpenAPI(t, lr, &page)
	if len(page.Items) != 1 || page.Items[0].Id != "staff" {
		t.Fatalf("list %+v", page)
	}

	del := httptest.NewRequest(http.MethodDelete, "/api/v1/groups/staff", nil)
	del.Header.Set("Authorization", "Bearer "+testToken)
	del.Header.Set("If-Match", cr.Header().Get("ETag"))
	dr := httptest.NewRecorder()
	h.ServeHTTP(dr, del)
	if dr.Code != http.StatusNoContent {
		t.Fatalf("delete %d %s", dr.Code, dr.Body.String())
	}
}

func TestMembershipRevisionAndIdempotentCounts(t *testing.T) {
	t.Parallel()
	s, _, _ := directoryServer(t)
	h := s.Handler()

	create := httptest.NewRequest(http.MethodPost, "/api/v1/groups", strings.NewReader(`{"id":"ops","members":[{"kind":"user","id":"alice"}]}`))
	create.Header.Set("Authorization", "Bearer "+testToken)
	create.Header.Set("Content-Type", "application/json")
	cr := httptest.NewRecorder()
	h.ServeHTTP(cr, create)
	if cr.Code != http.StatusCreated {
		t.Fatalf("create %d %s", cr.Code, cr.Body.String())
	}
	etag := cr.Header().Get("ETag")

	noMatch := httptest.NewRequest(http.MethodPost, "/api/v1/groups/ops/members", strings.NewReader(`{"members":[{"kind":"user","id":"bob"}]}`))
	noMatch.Header.Set("Authorization", "Bearer "+testToken)
	noMatch.Header.Set("Content-Type", "application/json")
	nm := httptest.NewRecorder()
	h.ServeHTTP(nm, noMatch)
	if nm.Code != http.StatusPreconditionFailed {
		t.Fatalf("members without if-match %d %s", nm.Code, nm.Body.String())
	}

	addAlice := httptest.NewRequest(http.MethodPost, "/api/v1/groups/ops/members", strings.NewReader(`{"members":[{"kind":"user","id":"alice"}]}`))
	addAlice.Header.Set("Authorization", "Bearer "+testToken)
	addAlice.Header.Set("Content-Type", "application/json")
	addAlice.Header.Set("If-Match", etag)
	ar := httptest.NewRecorder()
	h.ServeHTTP(ar, addAlice)
	if ar.Code != http.StatusOK {
		t.Fatalf("idempotent add %d %s", ar.Code, ar.Body.String())
	}
	var addSum generated.MembershipSummary
	decodeOpenAPI(t, ar, &addSum)
	if len(addSum.Added) != 0 || len(addSum.Unchanged) != 1 || len(addSum.Removed) != 0 {
		t.Fatalf("idempotent add counts %+v", addSum)
	}
	if addSum.Added == nil || addSum.Removed == nil || addSum.Unchanged == nil || addSum.Rejected == nil {
		t.Fatalf("nil membership slices %+v", addSum)
	}

	addBob := httptest.NewRequest(http.MethodPost, "/api/v1/groups/ops/members", strings.NewReader(`{"members":[{"kind":"user","id":"bob"}]}`))
	addBob.Header.Set("Authorization", "Bearer "+testToken)
	addBob.Header.Set("Content-Type", "application/json")
	addBob.Header.Set("If-Match", ar.Header().Get("ETag"))
	br := httptest.NewRecorder()
	h.ServeHTTP(br, addBob)
	if br.Code != http.StatusOK {
		t.Fatalf("add bob %d %s", br.Code, br.Body.String())
	}
	var bobSum generated.MembershipSummary
	decodeOpenAPI(t, br, &bobSum)
	if len(bobSum.Added) != 1 || bobSum.Added[0].Id != "bob" {
		t.Fatalf("add bob %+v", bobSum)
	}

	rmBob := httptest.NewRequest(http.MethodDelete, "/api/v1/groups/ops/members", strings.NewReader(`{"members":[{"kind":"user","id":"bob"}]}`))
	rmBob.Header.Set("Authorization", "Bearer "+testToken)
	rmBob.Header.Set("Content-Type", "application/json")
	rmBob.Header.Set("If-Match", br.Header().Get("ETag"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, rmBob)
	if rr.Code != http.StatusOK {
		t.Fatalf("remove bob %d %s", rr.Code, rr.Body.String())
	}
	var rmSum generated.MembershipSummary
	decodeOpenAPI(t, rr, &rmSum)
	if len(rmSum.Removed) != 1 || len(rmSum.Unchanged) != 0 {
		t.Fatalf("remove %+v", rmSum)
	}

	rmAgain := httptest.NewRequest(http.MethodDelete, "/api/v1/groups/ops/members", strings.NewReader(`{"members":[{"kind":"user","id":"bob"}]}`))
	rmAgain.Header.Set("Authorization", "Bearer "+testToken)
	rmAgain.Header.Set("Content-Type", "application/json")
	rmAgain.Header.Set("If-Match", rr.Header().Get("ETag"))
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, rmAgain)
	if rr2.Code != http.StatusOK {
		t.Fatalf("idempotent remove %d %s", rr2.Code, rr2.Body.String())
	}
	var rm2 generated.MembershipSummary
	decodeOpenAPI(t, rr2, &rm2)
	if len(rm2.Removed) != 0 || len(rm2.Unchanged) != 1 {
		t.Fatalf("idempotent remove counts %+v", rm2)
	}

	replace := httptest.NewRequest(http.MethodPut, "/api/v1/groups/ops/members", strings.NewReader(`{"members":[{"kind":"user","id":"alice"},{"kind":"user","id":"cara"}]}`))
	replace.Header.Set("Authorization", "Bearer "+testToken)
	replace.Header.Set("Content-Type", "application/json")
	replace.Header.Set("If-Match", rr2.Header().Get("ETag"))
	rpr := httptest.NewRecorder()
	h.ServeHTTP(rpr, replace)
	if rpr.Code != http.StatusOK {
		t.Fatalf("replace %d %s", rpr.Code, rpr.Body.String())
	}
	var repl generated.MembershipSummary
	decodeOpenAPI(t, rpr, &repl)
	if len(repl.Added) != 1 || len(repl.Unchanged) != 1 || len(repl.Removed) != 0 {
		t.Fatalf("replace %+v", repl)
	}

	readWrite := httptest.NewRequest(http.MethodPost, "/api/v1/groups/ops/members", strings.NewReader(`{"members":[{"kind":"user","id":"dan"}]}`))
	readWrite.Header.Set("Authorization", "Bearer "+readOnlyToken)
	readWrite.Header.Set("Content-Type", "application/json")
	readWrite.Header.Set("If-Match", rpr.Header().Get("ETag"))
	rwr := httptest.NewRecorder()
	h.ServeHTTP(rwr, readWrite)
	if rwr.Code != http.StatusForbidden {
		t.Fatalf("read-only members %d %s", rwr.Code, rwr.Body.String())
	}
}

func TestGroupScopesAndUnavailable(t *testing.T) {
	t.Parallel()
	s, _, _ := directoryServer(t)
	h := s.Handler()

	unauth := httptest.NewRequest(http.MethodGet, "/api/v1/groups", nil)
	ur := httptest.NewRecorder()
	h.ServeHTTP(ur, unauth)
	if ur.Code != http.StatusUnauthorized {
		t.Fatalf("unauth %d", ur.Code)
	}

	writeList := httptest.NewRequest(http.MethodGet, "/api/v1/groups", nil)
	writeList.Header.Set("Authorization", "Bearer "+writeOnlyToken)
	wlr := httptest.NewRecorder()
	h.ServeHTTP(wlr, writeList)
	if wlr.Code != http.StatusForbidden {
		t.Fatalf("write-only list %d %s", wlr.Code, wlr.Body.String())
	}

	bare := testServer(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/groups", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	bare.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no groups service %d %s", rec.Code, rec.Body.String())
	}
}
