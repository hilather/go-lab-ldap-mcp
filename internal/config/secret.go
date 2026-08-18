package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
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

// DirSecretResolver resolves relative secret paths against baseDir (the YAML
// file directory) first, then the process working directory.
func DirSecretResolver(baseDir string) SecretResolver {
	return dirResolver{base: baseDir, inner: fileResolver{}}
}

type dirResolver struct {
	base  string
	inner fileResolver
}

func (d dirResolver) Resolve(ctx context.Context, owner, path string) (ResolvedSecret, error) {
	if filepath.IsAbs(path) {
		return d.inner.Resolve(ctx, owner, path)
	}
	// Relative paths are scenario-relative. Prefer the YAML directory so a
	// same-named file in the process CWD cannot substitute the secret.
	if d.base != "" {
		joined := filepath.Join(d.base, path)
		if _, err := os.Stat(joined); err == nil {
			return d.inner.Resolve(ctx, owner, joined)
		}
	}
	return d.inner.Resolve(ctx, owner, path)
}

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

// MapResolver is a test/CLI helper that maps logical paths to secret bytes.
type MapResolver map[string]string

func (m MapResolver) Resolve(ctx context.Context, owner, path string) (ResolvedSecret, error) {
	_ = ctx
	v, ok := m[path]
	if !ok {
		return FileSecretResolver().Resolve(ctx, owner, path)
	}
	norm := stripOneTrailingNewline([]byte(v))
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
