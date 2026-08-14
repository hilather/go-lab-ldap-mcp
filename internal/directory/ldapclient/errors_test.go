package ldapclient

import (
	"context"
	"errors"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

func TestMapErrorLDAPCategories(t *testing.T) {
	t.Parallel()
	cases := []struct {
		code  uint16
		field string
		retry bool
	}{
		{ldap.LDAPResultNoSuchObject, directory.FieldNotFound, false},
		{ldap.LDAPResultEntryAlreadyExists, directory.FieldConflict, false},
		{ldap.LDAPResultInvalidCredentials, directory.FieldInvalidCredentials, false},
		{ldap.LDAPResultConstraintViolation, directory.FieldConstraint, false},
		{ldap.LDAPResultInsufficientAccessRights, directory.FieldForbidden, false},
		{ldap.LDAPResultUnavailable, directory.FieldUnavailable, true},
		{ldap.ErrorNetwork, directory.FieldUnavailable, true},
	}
	for _, tc := range cases {
		err := MapError(&ldap.Error{ResultCode: tc.code, Err: errors.New("ldap")})
		apperr.Assert(t, err).Code(apperr.CodeDirectory).Retryable(tc.retry)
		if !hasField(err, tc.field) {
			t.Fatalf("code %d: missing field %s in %#v", tc.code, tc.field, err)
		}
	}
}

func TestMapErrorPreservesDirectory(t *testing.T) {
	t.Parallel()
	in := directory.Error("entry", directory.FieldNotFound, "directory entry not found")
	if MapError(in) != in {
		t.Fatal("mapped already-structured error")
	}
}

func TestMapErrorCanceled(t *testing.T) {
	t.Parallel()
	err := MapError(context.Canceled)
	apperr.Assert(t, err).Code(apperr.CodeDirectory).Retryable(false)
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func hasField(err error, code string) bool {
	var e *apperr.Error
	if !errors.As(err, &e) {
		return false
	}
	for _, f := range e.Fields() {
		if f.Code == code {
			return true
		}
	}
	return false
}
