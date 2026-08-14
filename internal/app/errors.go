package app

import (
	"errors"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

func asError(err error, target **apperr.Error) bool {
	return errors.As(err, target)
}

func isConflict(err error) bool {
	return fieldCode(err) == directory.FieldConflict
}

func isUnavailable(err error) bool {
	var e *apperr.Error
	if !errors.As(err, &e) {
		return false
	}
	return e.Retryable() || fieldCode(err) == directory.FieldUnavailable
}
