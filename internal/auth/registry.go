package auth

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

// Token is one compiled static token. Secret is consumed at construction
// and is not retained as plaintext after hashing.
type Token struct {
	ID     string
	Scopes []string
	Secret observability.Secret
}

type storedToken struct {
	id     string
	scopes directory.ScopeSet
	digest [sha256.Size]byte
}

// Registry matches presented bearer secrets in constant time.
type Registry struct {
	tokens []storedToken
}

func NewRegistry(tokens []Token) (*Registry, error) {
	out := make([]storedToken, 0, len(tokens))
	seenID := map[string]struct{}{}
	seenDigest := map[[sha256.Size]byte]string{}
	for i, t := range tokens {
		if t.ID == "" {
			return nil, apperr.New(apperr.CodeConfiguration, "token id is required").
				WithField(apperr.Field{Path: fmt.Sprintf("tokens[%d].id", i), Code: "required", Message: "token id is required"})
		}
		if _, ok := seenID[t.ID]; ok {
			return nil, apperr.New(apperr.CodeConfiguration, "duplicate token id").
				WithField(apperr.Field{Path: fmt.Sprintf("tokens[%d].id", i), Code: "duplicate", Message: "duplicate token id"})
		}
		seenID[t.ID] = struct{}{}
		raw := []byte(t.Secret.Reveal())
		if len(raw) == 0 {
			return nil, apperr.New(apperr.CodeConfiguration, "token secret is empty").
				WithField(apperr.Field{Path: fmt.Sprintf("tokens[%d].secret", i), Code: "secret_empty", Message: "token secret is empty"})
		}
		d := DigestSecret(raw)
		if other, ok := seenDigest[d]; ok {
			return nil, apperr.New(apperr.CodeConfiguration, "duplicate token value").
				WithField(apperr.Field{Path: fmt.Sprintf("tokens[%d].secret", i), Code: "duplicate_value", Message: "token value matches " + other})
		}
		seenDigest[d] = t.ID
		scopes := append(directory.ScopeSet(nil), t.Scopes...)
		out = append(out, storedToken{id: t.ID, scopes: scopes, digest: d})
		for i := range raw {
			raw[i] = 0
		}
	}
	return &Registry{tokens: out}, nil
}

// Lookup compares presented against every stored digest and returns the
// matching non-secret ID and scopes. The presented secret is not logged.
func (r *Registry) Lookup(presented string) (Principal, bool) {
	if r == nil {
		return Principal{}, false
	}
	digest := DigestSecret([]byte(presented))
	found := 0
	idx := 0
	for i, t := range r.tokens {
		eq := 0
		if EqualDigest(t.digest, digest) {
			eq = 1
		}
		// Always visit every token. Record the last match (duplicates rejected).
		mask := eq
		idx = idx*(1-mask) + i*mask
		found |= eq
	}
	if found != 1 {
		return Principal{}, false
	}
	t := r.tokens[idx]
	return Principal{
		Kind:   KindToken,
		ID:     t.id,
		Scopes: append(directory.ScopeSet(nil), t.scopes...),
	}, true
}

// ParseBearer extracts the token from an Authorization header.
// ok is false for missing or malformed values. The returned secret must
// not be logged.
func ParseBearer(header string) (secret string, ok bool, malformed bool) {
	if header == "" {
		return "", false, false
	}
	scheme, rest, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false, true
	}
	secret = strings.TrimSpace(rest)
	if secret == "" || strings.ContainsAny(secret, " \t") {
		return "", false, true
	}
	return secret, true, false
}

func AuthRequired() error {
	return apperr.New(apperr.CodeAuth, "authentication required")
}
