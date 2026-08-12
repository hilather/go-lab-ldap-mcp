package config

import (
	"errors"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
)

func joinConfig(acc []*apperr.Error) error {
	if len(acc) == 0 {
		return nil
	}
	if len(acc) == 1 {
		return acc[0]
	}
	out := apperr.New(apperr.CodeConfiguration, "invalid configuration")
	for _, e := range acc {
		for _, f := range e.Fields() {
			out = out.WithField(f)
		}
	}
	return out
}

func asConfigErr(err error) *apperr.Error {
	var e *apperr.Error
	if errors.As(err, &e) {
		return e
	}
	return apperr.New(apperr.CodeConfiguration, "invalid configuration").Wrap(err)
}
