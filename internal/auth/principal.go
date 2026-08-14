package auth

import (
	"context"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

const (
	KindToken   = "token"
	KindSession = "session"
)

// Principal is the non-secret actor after authentication.
type Principal struct {
	Kind   string
	ID     string
	Scopes directory.ScopeSet
}

type principalKey struct{}

func WithPrincipal(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

func PrincipalFrom(ctx context.Context) (Principal, bool) {
	if ctx == nil {
		return Principal{}, false
	}
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok
}
