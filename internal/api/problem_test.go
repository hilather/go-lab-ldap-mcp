package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/api/generated"
	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/reset"
)

func TestStatusForErrorFamilies(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		err    error
		status int
	}{
		{name: "auth required", err: auth.AuthRequired(), status: http.StatusUnauthorized},
		{name: "missing scope", err: auth.Require(nil, auth.ScopeDirectoryRead), status: http.StatusForbidden},
		{name: "csrf", err: apperr.New(apperr.CodeAuth, "csrf check failed").WithField(apperr.Field{Path: "csrf", Code: "forbidden", Message: "csrf token is missing or invalid"}), status: http.StatusForbidden},
		{name: "json", err: apperr.New(apperr.CodeConfiguration, "invalid json").WithField(apperr.Field{Path: "body", Code: "invalid", Message: "malformed json"}), status: http.StatusBadRequest},
		{name: "cursor", err: apperr.New(apperr.CodeConfiguration, "cursor is invalid").WithField(apperr.Field{Path: "cursor", Code: "invalid", Message: "cursor is invalid"}), status: http.StatusBadRequest},
		{name: "missing if-match", err: missingIfMatch(), status: http.StatusPreconditionFailed},
		{name: "missing revision", err: apperr.New(apperr.CodeConfiguration, "revision is required").WithField(apperr.Field{Path: "revision", Code: "required", Message: "revision is required"}), status: http.StatusPreconditionFailed},
		{name: "invalid if-match", err: invalidIfMatch("If-Match must be a quoted revision"), status: http.StatusBadRequest},
		{name: "stale revision", err: directory.Error("revision", directory.FieldConflict, "directory entry revision does not match"), status: http.StatusPreconditionFailed},
		{name: "not found", err: directory.Error("entry", directory.FieldNotFound, "directory entry not found"), status: http.StatusNotFound},
		{name: "exists", err: directory.Error("entry", directory.FieldConflict, "directory entry already exists"), status: http.StatusConflict},
		{name: "constraint", err: directory.Error("entry", directory.FieldConstraint, "directory constraint violation"), status: http.StatusBadRequest},
		{name: "dir forbidden", err: directory.Error("authorization", directory.FieldForbidden, "directory operation not permitted"), status: http.StatusForbidden},
		{name: "unavailable", err: directory.Error("connection", directory.FieldUnavailable, "directory unavailable"), status: http.StatusServiceUnavailable},
		{name: "invalid credentials", err: directory.Error("bind", directory.FieldInvalidCredentials, "invalid credentials"), status: http.StatusBadRequest},
		{name: "dir default", err: directory.Error("entry", directory.FieldIncomplete, "create incomplete"), status: http.StatusBadGateway},
		{name: "reset blocked", err: func() error { g := reset.NewGate(); g.Set(reset.Resetting); return g.Allow(t.Context()) }(), status: http.StatusServiceUnavailable},
		{name: "reset conflict", err: apperr.New(apperr.CodeReset, "reset already running"), status: http.StatusConflict},
		{name: "export limit", err: apperr.New(apperr.CodeExport, "limit exceeded").WithField(apperr.Field{Path: "export.bytes", Code: "limit", Message: "too large"}), status: http.StatusBadRequest},
		{name: "export conflict", err: apperr.New(apperr.CodeExport, "export busy"), status: http.StatusConflict},
		{name: "export unavailable", err: apperr.New(apperr.CodeExport, "export unavailable").WithField(apperr.Field{Path: "export", Code: directory.FieldUnavailable, Message: "unavailable"}).Retry(), status: http.StatusServiceUnavailable},
		{name: "bootstrap", err: apperr.New(apperr.CodeBootstrap, "bootstrap failed"), status: http.StatusInternalServerError},
		{name: "unknown", err: apperr.New("other", "mystery"), status: http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.err == nil {
				if statusFor(tc.err) != http.StatusInternalServerError {
					t.Fatalf("nil err status = %d", statusFor(tc.err))
				}
				return
			}
			if got := statusFor(tc.err); got != tc.status {
				t.Fatalf("status = %d, want %d (%v)", got, tc.status, tc.err)
			}
		})
	}
}

func TestWriteProblemHasRequestIDAndType(t *testing.T) {
	t.Parallel()
	s := testServer(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "application/problem+json" &&
		!strings.HasPrefix(rec.Header().Get("Content-Type"), "application/problem+json") {
		t.Fatalf("content-type %q", rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache-control %q", rec.Header().Get("Cache-Control"))
	}
	id := rec.Header().Get(headerRequestID)
	if id == "" {
		t.Fatal("missing X-Request-ID")
	}
	var body generated.Problem
	dec := json.NewDecoder(strings.NewReader(rec.Body.String()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		t.Fatalf("openapi problem: %v body=%s", err, rec.Body.String())
	}
	if body.Type != problemTypePrefix+"auth" {
		t.Fatalf("type %q", body.Type)
	}
	if body.Status != http.StatusUnauthorized {
		t.Fatalf("body status %d", body.Status)
	}
	if body.Extensions == nil || body.Extensions.RequestId == nil || *body.Extensions.RequestId != id {
		t.Fatalf("extensions.requestId = %+v header=%s", body.Extensions, id)
	}
}

func TestWriteProblemUsesCallerRequestID(t *testing.T) {
	t.Parallel()
	s := testServer(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	req.Header.Set(headerRequestID, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Header().Get(headerRequestID) != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Fatalf("request id %q", rec.Header().Get(headerRequestID))
	}
	if !strings.Contains(rec.Body.String(), `"requestId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`) {
		t.Fatalf("body %s", rec.Body.String())
	}
}

func TestStaleAndMissingPreconditions(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodPatch, "/api/v1/version", nil)
	rec := httptest.NewRecorder()
	writeProblem(rec, req, missingIfMatch())
	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("missing = %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"path":"If-Match"`) || !strings.Contains(rec.Body.String(), `"code":"required"`) {
		t.Fatalf("missing body %s", rec.Body.String())
	}
	if rec.Header().Get(headerRequestID) == "" {
		t.Fatal("missing request id on precondition error")
	}

	rec = httptest.NewRecorder()
	writeProblem(rec, req, directory.Error("revision", directory.FieldConflict, "directory entry revision does not match"))
	if rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale = %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), problemTypePrefix+"directory") {
		t.Fatalf("stale type %s", rec.Body.String())
	}
}
