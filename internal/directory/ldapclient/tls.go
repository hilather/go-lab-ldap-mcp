package ldapclient

import (
	"crypto/tls"
	"crypto/x509"
	"os"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

func tlsConfig(cfg Config) (*tls.Config, error) {
	tc := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: cfg.ServerName,
	}
	if cfg.InsecureSkipVerify && cfg.AllowCleartextBind {
		tc.InsecureSkipVerify = true
		return tc, nil
	}
	if cfg.CAFile == "" {
		return nil, directory.Error("tls", directory.FieldForbidden, "directory CA file is required")
	}
	pem, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, directory.Error("tls", directory.FieldForbidden, "directory CA file unreadable").Wrap(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, directory.Error("tls", directory.FieldForbidden, "directory CA file is not a PEM certificate")
	}
	tc.RootCAs = pool
	return tc, nil
}
