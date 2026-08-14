package ldapclient

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

// Config is the runtime LDAP client and pool settings.
type Config struct {
	// Address is host:port with no scheme. Ports follow compiled 3389/3636.
	Address string
	// Transport selects ldap, ldaps, or starttls. Empty defaults to ldaps.
	Transport  directory.Transport
	ServerName string
	CAFile     string
	// InsecureSkipVerify is honored only when AllowCleartextBind is true
	// (compiled insecure lab mode). Otherwise Connect fails closed.
	InsecureSkipVerify bool
	AllowCleartextBind bool

	DialTimeout time.Duration
	OpTimeout   time.Duration
	WaitTimeout time.Duration

	BindDN       string
	BindPassword observability.Secret

	PoolSize    int
	MaxIdle     time.Duration
	MaxLifetime time.Duration

	Metrics Metrics
	// Dial, if set, replaces the real network dial. Tests inject it.
	Dial DialFunc
}

// DialFunc opens one protected, optionally bound connection.
type DialFunc func(ctx context.Context, cfg Config) (*Conn, error)

func (c *Config) applyDefaults() {
	if c.Transport == "" {
		c.Transport = directory.TransportLDAPS
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = 5 * time.Second
	}
	if c.OpTimeout <= 0 {
		c.OpTimeout = 30 * time.Second
	}
	if c.WaitTimeout <= 0 {
		c.WaitTimeout = c.DialTimeout
	}
	if c.PoolSize <= 0 {
		c.PoolSize = 16
	}
	if c.ServerName == "" {
		c.ServerName = hostOf(c.Address)
	}
}

func (c Config) validate() error {
	switch c.Transport {
	case directory.TransportLDAP, directory.TransportLDAPS, directory.TransportStartTLS:
	default:
		return directory.Error("tls", directory.FieldConstraint, "unknown LDAP transport")
	}
	if c.Transport == directory.TransportLDAP && !c.AllowCleartextBind {
		return directory.Error("tls", directory.FieldForbidden, "cleartext LDAP bind is not allowed")
	}
	needTLS := c.Transport == directory.TransportLDAPS || c.Transport == directory.TransportStartTLS
	if needTLS && c.InsecureSkipVerify && !c.AllowCleartextBind {
		return directory.Error("tls", directory.FieldForbidden, "TLS verification cannot be skipped")
	}
	if needTLS && !c.InsecureSkipVerify && c.CAFile == "" {
		return directory.Error("tls", directory.FieldForbidden, "directory CA file is required")
	}
	if c.Address == "" {
		return directory.Error("connection", directory.FieldUnavailable, "LDAP address is empty")
	}
	return nil
}

func hostOf(addr string) string {
	addr = strings.TrimPrefix(strings.TrimPrefix(addr, "ldaps://"), "ldap://")
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
