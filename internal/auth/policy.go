package auth

import (
	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

// Policy is the application authorization checker. Transports may also
// consult it; services must still call Require.
type Policy struct{}

// Require reports missing_scope with the required scope name only.
func Require(scopes directory.ScopeSet, required string) error {
	if required == "" {
		return nil
	}
	if scopes.Has(required) {
		return nil
	}
	return apperr.New(apperr.CodeAuth, "missing required scope").WithField(apperr.Field{
		Path:    "scope",
		Code:    "forbidden",
		Message: required,
	})
}

func (Policy) Require(scopes directory.ScopeSet, required string) error {
	return Require(scopes, required)
}

// Case is one generated matrix row for T-057 / T-059.
type Case struct {
	Name     string
	Have     directory.ScopeSet
	Required string
	Allow    bool
}

// Matrix enumerates each registered scope as the required grant against
// empty, exact, write-only, and full-except-required sets.
func Matrix() []Case {
	all := Scopes()
	var out []Case
	for _, req := range all {
		except := directory.ScopeSet{}
		for _, s := range all {
			if s != req {
				except = append(except, s)
			}
		}
		out = append(out,
			Case{Name: "none/" + req, Have: nil, Required: req, Allow: false},
			Case{Name: "exact/" + req, Have: directory.ScopeSet{req}, Required: req, Allow: true},
			Case{Name: "write/" + req, Have: directory.ScopeSet{ScopeDirectoryWrite}, Required: req, Allow: req == ScopeDirectoryWrite},
			Case{Name: "except/" + req, Have: except, Required: req, Allow: false},
		)
	}
	return out
}
