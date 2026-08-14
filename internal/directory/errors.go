package directory

import "github.com/hilather/go-lab-ldap-mcp/internal/apperr"

// Field codes for apperr.CodeDirectory. ldapclient maps LDAP result categories here.
const (
	FieldNotFound           = "not_found"
	FieldConflict           = "conflict"
	FieldInvalidCredentials = "invalid_credentials"
	FieldConstraint         = "constraint"
	FieldUnavailable        = "unavailable"
	FieldForbidden          = "forbidden"
	// FieldIncomplete marks a create that left (or may have left) a
	// no-password account. Callers may compensate with delete. A
	// post-success read failure is not incomplete.
	FieldIncomplete = "incomplete"
)

// Error builds a CodeDirectory error with a single field code. unavailable is retryable.
func Error(path, fieldCode, public string) *apperr.Error {
	e := apperr.New(apperr.CodeDirectory, public).WithField(apperr.Field{
		Path:    path,
		Code:    fieldCode,
		Message: public,
	})
	if fieldCode == FieldUnavailable {
		e = e.Retry()
	}
	return e
}
