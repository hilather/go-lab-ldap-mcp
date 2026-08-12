package bootstrap

import "github.com/hilather/go-lab-ldap-mcp/internal/apperr"

func phaseErr(phase, code, public string) *apperr.Error {
	return apperr.New(apperr.CodeBootstrap, public).WithField(apperr.Field{
		Path:    "phase." + phase,
		Code:    code,
		Message: public,
	})
}

// PhaseError is the public constructor for ds389 and tests.
func PhaseError(phase, code, public string) *apperr.Error {
	return phaseErr(phase, code, public)
}
