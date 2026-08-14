package ldapclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

// MapError translates LDAP and transport failures into CodeDirectory.
// LDAP result categories are mapped here, not in app.
func MapError(err error) error {
	if err == nil {
		return nil
	}
	var de *apperr.Error
	if errors.As(err, &de) && de != nil && de.Code() == apperr.CodeDirectory {
		return err
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return apperr.New(apperr.CodeDirectory, "directory operation canceled").
			WithField(apperr.Field{Path: "connection", Code: directory.FieldUnavailable, Message: "directory operation canceled"}).
			Wrap(err)
	}
	if tlsVerifyFailed(err) {
		return directory.Error("tls", directory.FieldForbidden, "directory TLS verification failed").Wrap(err)
	}
	var le *ldap.Error
	if errors.As(err, &le) && le != nil {
		return mapLDAP(le)
	}
	if transientNet(err) {
		return directory.Error("connection", directory.FieldUnavailable, "directory unavailable").Wrap(err)
	}
	return directory.Error("connection", directory.FieldUnavailable, "directory unavailable").Wrap(err)
}

func mapLDAP(le *ldap.Error) error {
	switch le.ResultCode {
	case ldap.LDAPResultNoSuchObject, ldap.LDAPResultNoSuchAttribute:
		return directory.Error("entry", directory.FieldNotFound, "directory entry not found").Wrap(le)
	case ldap.LDAPResultEntryAlreadyExists, ldap.LDAPResultAttributeOrValueExists:
		return directory.Error("entry", directory.FieldConflict, "directory entry already exists").Wrap(le)
	case ldap.LDAPResultInvalidCredentials, ldap.LDAPResultInappropriateAuthentication:
		return directory.Error("bind", directory.FieldInvalidCredentials, "invalid credentials").Wrap(le)
	case ldap.LDAPResultConstraintViolation, ldap.LDAPResultObjectClassViolation,
		ldap.LDAPResultNamingViolation, ldap.LDAPResultNotAllowedOnNonLeaf,
		ldap.LDAPResultNotAllowedOnRDN, ldap.LDAPResultObjectClassModsProhibited,
		ldap.LDAPResultUndefinedAttributeType, ldap.LDAPResultInvalidAttributeSyntax,
		ldap.LDAPResultInvalidDNSyntax, ldap.LDAPResultSizeLimitExceeded,
		ldap.LDAPResultTimeLimitExceeded:
		return directory.Error("entry", directory.FieldConstraint, "directory constraint violation").Wrap(le)
	case ldap.LDAPResultInsufficientAccessRights, ldap.LDAPResultConfidentialityRequired,
		ldap.LDAPResultStrongAuthRequired, ldap.LDAPResultAuthMethodNotSupported,
		ldap.LDAPResultAuthorizationDenied:
		return directory.Error("authorization", directory.FieldForbidden, "directory operation not permitted").Wrap(le)
	case ldap.LDAPResultBusy, ldap.LDAPResultUnavailable, ldap.LDAPResultUnwillingToPerform,
		ldap.LDAPResultUnavailableCriticalExtension, ldap.LDAPResultOther,
		ldap.ErrorNetwork, ldap.LDAPResultConnectError, ldap.LDAPResultServerDown:
		return directory.Error("connection", directory.FieldUnavailable, "directory unavailable").Wrap(le)
	default:
		return directory.Error("connection", directory.FieldUnavailable, "directory unavailable").Wrap(le)
	}
}

func tlsVerifyFailed(err error) bool {
	if err == nil {
		return false
	}
	var ca *tls.CertificateVerificationError
	if errors.As(err, &ca) {
		return true
	}
	var unk x509.UnknownAuthorityError
	if errors.As(err, &unk) {
		return true
	}
	var hn x509.HostnameError
	if errors.As(err, &hn) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "certificate") &&
		(strings.Contains(msg, "unknown authority") ||
			strings.Contains(msg, "not valid for") ||
			strings.Contains(msg, "verification") ||
			strings.Contains(msg, "hostname"))
}

func transientNet(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne)
}

func isBroken(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var de *apperr.Error
	if errors.As(err, &de) && de != nil && de.Retryable() {
		return true
	}
	var le *ldap.Error
	if errors.As(err, &le) && le != nil {
		switch le.ResultCode {
		case ldap.ErrorNetwork, ldap.LDAPResultUnavailable, ldap.LDAPResultServerDown,
			ldap.LDAPResultConnectError, ldap.LDAPResultBusy, ldap.LDAPResultOther:
			return true
		}
	}
	return transientNet(err)
}
