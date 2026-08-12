package config

import (
	"context"
	"fmt"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config/v1alpha1"
)

var impliedByWrite = map[string]bool{
	v1alpha1.ScopeDirectoryPassword: true,
	v1alpha1.ScopeLabReset:          true,
	v1alpha1.ScopeLabExport:         true,
}

func knownScope(s string) bool {
	for _, k := range v1alpha1.Scopes() {
		if k == s {
			return true
		}
	}
	return false
}

func normalizeTokens(ctx context.Context, in *Input, resolver SecretResolver) ([]NormalizedToken, error) {
	var acc []*apperr.Error
	seenID := map[string]int{}
	digestOwner := map[string]string{}
	out := make([]NormalizedToken, 0, len(in.Tokens))
	for i, t := range in.Tokens {
		path := fmt.Sprintf("spec.tokens[%d]", i)
		if t.ID == "" {
			acc = append(acc, fieldErr(path+".id", "required", "token id is required"))
			continue
		}
		if prev, ok := seenID[t.ID]; ok {
			acc = append(acc, fieldErr(path+".id", "duplicate", fmt.Sprintf("duplicate token id (also spec.tokens[%d])", prev)))
			continue
		}
		seenID[t.ID] = i
		if t.Secret.File == "" {
			acc = append(acc, fieldErr(path+".secretFile", "required", "secretFile is required"))
			continue
		}
		var scopes []string
		seenScope := map[string]struct{}{}
		for _, s := range t.Scopes {
			if !knownScope(s) {
				acc = append(acc, fieldErr(path+".scopes", "unknown_scope", "unknown scope "+s))
				continue
			}
			if _, ok := seenScope[s]; ok {
				continue
			}
			seenScope[s] = struct{}{}
			scopes = append(scopes, s)
		}
		// directory:write must not silently grant password/reset/export — just store listed scopes.
		_ = impliedByWrite
		nt := NormalizedToken{ID: t.ID, Scopes: scopes}
		if resolver != nil {
			sec, err := resolver.Resolve(ctx, path+".secretFile", t.Secret.File)
			if err != nil {
				acc = append(acc, asConfigErr(err))
			} else {
				if other, ok := digestOwner[sec.Digest]; ok {
					acc = append(acc, fieldErr(path+".secretFile", "duplicate_value", "token value matches "+other))
				} else {
					digestOwner[sec.Digest] = path
				}
				nt.Secret = sec
			}
		}
		out = append(out, nt)
	}
	if err := joinConfig(acc); err != nil {
		return nil, err
	}
	return out, nil
}

func tokenHasOnlyListedScopes(t NormalizedToken) bool {
	hasWrite := false
	for _, s := range t.Scopes {
		if s == v1alpha1.ScopeDirectoryWrite {
			hasWrite = true
		}
	}
	if !hasWrite {
		return true
	}
	// write present does not imply others; others must be explicit
	return true
}
