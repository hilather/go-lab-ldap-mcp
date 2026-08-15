package ldapserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// Compose-published default ports for the native engine (ADR-0009 decision
// 4). Published host ports stay on loopback.
const (
	DefaultLDAPPort  = 3389
	DefaultLDAPSPort = 3636
)

// ErrNotImplemented marks entry points whose implementation lands in a later
// M9 task; the wrapping message names the task.
var ErrNotImplemented = errors.New("ldapserver: not implemented")

// Limits are the pre-auth and per-operation ceilings (ADR-0009 decision 10).
// cmd/labldapd fills them from compiled spec.limits; a zero field takes the
// DefaultLimits value.
type Limits struct {
	MaxPDUBytes       int
	MaxOutstandingOps int
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	SearchSizeLimit   int
	SearchTimeLimit   time.Duration
}

// DefaultLimits returns conservative ceilings applied when the scenario does
// not override them.
func DefaultLimits() Limits {
	return Limits{
		MaxPDUBytes:       1 << 20,
		MaxOutstandingOps: 8,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       5 * time.Minute,
		SearchSizeLimit:   500,
		SearchTimeLimit:   30 * time.Second,
	}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxPDUBytes <= 0 {
		l.MaxPDUBytes = d.MaxPDUBytes
	}
	if l.MaxOutstandingOps <= 0 {
		l.MaxOutstandingOps = d.MaxOutstandingOps
	}
	if l.ReadTimeout <= 0 {
		l.ReadTimeout = d.ReadTimeout
	}
	if l.WriteTimeout <= 0 {
		l.WriteTimeout = d.WriteTimeout
	}
	if l.IdleTimeout <= 0 {
		l.IdleTimeout = d.IdleTimeout
	}
	if l.SearchSizeLimit <= 0 {
		l.SearchSizeLimit = d.SearchSizeLimit
	}
	if l.SearchTimeLimit <= 0 {
		l.SearchTimeLimit = d.SearchTimeLimit
	}
	return l
}

// Identity is a privileged bind identity. VerifyPassword must compare in
// constant time; cmd/labldapd reads the underlying secret from a file and it
// must never appear on argv, in logs, or in an Options dump.
type Identity struct {
	DN             string
	VerifyPassword func(password []byte) bool
}

// Options configure a Server. All dependencies are injected; there are no
// package-level globals.
type Options struct {
	// Suffix is the managed naming context, for example "dc=example,dc=test".
	Suffix string
	// LDAPAddress is the cleartext/StartTLS listener ("host:port"); empty
	// disables it. An empty host defaults to loopback (ADR-0009 decision 4).
	LDAPAddress string
	// LDAPSAddress is the implicit-TLS listener; empty disables it.
	LDAPSAddress string
	// TLSConfig is required when LDAPSAddress is set or AllowStartTLS is on.
	TLSConfig *tls.Config
	// AllowStartTLS permits the StartTLS extended op on the LDAP listener.
	AllowStartTLS bool
	// AllowAnonymousBind permits anonymous binds. Default off (C3).
	AllowAnonymousBind bool
	// AllowCleartextBind permits simple bind without TLS. Default off; only
	// explicit insecure lab mode turns it on (C3).
	AllowCleartextBind bool
	Limits             Limits
	Codec              Codec
	Store              Store
	Schema             Schema
	ACI                ACIEngine
	Plugins            []Plugin
	// DirectoryManager is the bootstrap-root identity. An empty DN disables
	// it; no other identity may bypass ACI (ADR-0009 decision 13).
	DirectoryManager Identity
	Logger           *slog.Logger
}

// Server is the native directory engine. The constructor validates and
// normalizes Options; listener lifecycle lands in T-125.
type Server struct {
	opts   Options
	suffix config.DN
	dmDN   config.DN
	hasDM  bool
}

// New validates opts and returns a Server. Configuration problems are
// reported as apperr.CodeConfiguration field errors, never panics.
func New(opts Options) (*Server, error) {
	fieldErr := func(path, code, msg string) error {
		return apperr.New(apperr.CodeConfiguration, "ldapserver: invalid options").
			WithField(apperr.Field{Path: path, Code: code, Message: msg})
	}
	if opts.Codec == nil {
		return nil, fieldErr("codec", "required", "a BER codec is required")
	}
	if opts.Store == nil {
		return nil, fieldErr("store", "required", "an entry store is required")
	}
	if opts.Schema == nil {
		return nil, fieldErr("schema", "required", "a schema registry is required")
	}
	if opts.ACI == nil {
		return nil, fieldErr("aci", "required", "an ACI engine is required")
	}
	if opts.Logger == nil {
		return nil, fieldErr("logger", "required", "a slog logger is required")
	}
	suffix, err := config.ParseDN(opts.Suffix)
	if err != nil {
		return nil, fieldErr("suffix", "invalid_dn", "suffix is not a valid DN")
	}
	s := &Server{opts: opts, suffix: suffix}
	if opts.DirectoryManager.DN != "" {
		dm, err := config.ParseDN(opts.DirectoryManager.DN)
		if err != nil {
			return nil, fieldErr("directoryManager.dn", "invalid_dn", "directory manager DN is not a valid DN")
		}
		if opts.DirectoryManager.VerifyPassword == nil {
			return nil, fieldErr("directoryManager.verifyPassword", "required", "directory manager DN set without a password verifier")
		}
		s.dmDN, s.hasDM = dm, true
	}
	if (opts.LDAPSAddress != "" || opts.AllowStartTLS) && opts.TLSConfig == nil {
		return nil, fieldErr("tlsConfig", "required", "LDAPS or StartTLS requires a TLS config")
	}
	if s.opts.LDAPAddress, err = loopbackDefault(opts.LDAPAddress); err != nil {
		return nil, fieldErr("ldapAddress", "invalid_address", "LDAP listener address is invalid")
	}
	if s.opts.LDAPSAddress, err = loopbackDefault(opts.LDAPSAddress); err != nil {
		return nil, fieldErr("ldapsAddress", "invalid_address", "LDAPS listener address is invalid")
	}
	s.opts.Limits = opts.Limits.withDefaults()
	return s, nil
}

// loopbackDefault pins an empty listener host to loopback (ADR-0009 decision
// 4). An empty address stays empty (listener disabled).
func loopbackDefault(addr string) (string, error) {
	if addr == "" {
		return "", nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}
	if host == "" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port), nil
}

// Suffix returns the parsed managed naming context.
func (s *Server) Suffix() config.DN { return s.suffix }

// Limits returns the effective ceilings after defaults.
func (s *Server) Limits() Limits { return s.opts.Limits }

// Serve binds the configured listeners and serves until ctx is canceled.
// The listener lifecycle lands in T-125; calling it before then fails with
// ErrNotImplemented.
func (s *Server) Serve(ctx context.Context) error {
	return fmt.Errorf("ldapserver serve: %w (lands in T-125)", ErrNotImplemented)
}

// Close releases the store. Listener shutdown lands with Serve in T-125.
func (s *Server) Close() error {
	return s.opts.Store.Close()
}
