package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

type SecretResolver interface {
	Resolve(ctx context.Context, owner, path string) (ResolvedSecret, error)
}

type ResolvedSecret struct {
	Owner  string
	Path   string
	Value  observability.Secret
	Digest string
}

type fileResolver struct{}

func FileSecretResolver() SecretResolver { return fileResolver{} }

func (fileResolver) Resolve(ctx context.Context, owner, path string) (ResolvedSecret, error) {
	_ = ctx
	if path == "" {
		return ResolvedSecret{}, apperr.New(apperr.CodeConfiguration, "secret file unreadable").
			WithField(apperr.Field{Path: owner, Code: "secret_unreadable", Message: "path is empty"})
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ResolvedSecret{}, apperr.New(apperr.CodeConfiguration, "secret file unreadable").
			WithField(apperr.Field{Path: owner, Code: "secret_unreadable", Message: "path " + path + " could not be read"})
	}
	norm := stripOneTrailingNewline(raw)
	if len(norm) == 0 {
		return ResolvedSecret{}, apperr.New(apperr.CodeConfiguration, "secret file empty").
			WithField(apperr.Field{Path: owner, Code: "secret_empty", Message: "path " + path + " is empty"})
	}
	sum := sha256.Sum256(norm)
	return ResolvedSecret{
		Owner:  owner,
		Path:   path,
		Value:  observability.Secret(string(norm)),
		Digest: hex.EncodeToString(sum[:]),
	}, nil
}

func stripOneTrailingNewline(b []byte) []byte {
	s := string(b)
	switch {
	case strings.HasSuffix(s, "\r\n"):
		return []byte(s[:len(s)-2])
	case strings.HasSuffix(s, "\n"):
		return []byte(s[:len(s)-1])
	default:
		return append([]byte(nil), b...)
	}
}
