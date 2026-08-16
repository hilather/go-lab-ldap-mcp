package native

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ldapclient"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

// Engine implements the engine-plan read-back reconcilers for
// engine=native (ADR-0009 decisions 11-12). labldapd self-applies the
// compiled engine plan at start and publishes it as a stub cn=config
// entry; these reconcilers verify the running daemon's applied plan by
// reading that entry back over LDAP as Directory Manager. They never
// invoke dsconf and never mutate the engine plane: any mismatch fails
// closed with a phase error.
type Engine struct {
	// Address is the labldapd host:port the backend/policy/plugin
	// read-back reconcilers dial (their bootstrap requests carry no
	// coordinates; the TLS reconciler uses its per-request addresses).
	Address string
	// Transport selects ldap, ldaps, or starttls for the engine-level
	// probes. Empty defaults to ldaps (the ldapclient default).
	Transport directory.Transport
	// ServerName overrides the TLS server name; empty derives from Address.
	ServerName string
	// CAFile trusts the directory certificate for ldaps/starttls probes.
	CAFile string
	// Insecure is the compiled insecureLabMode: it permits cleartext
	// probe dials and skips certificate verification.
	Insecure    bool
	DialTimeout time.Duration
	// ProbeDial, if set, replaces the real LDAP dial. Tests inject fakes;
	// production wiring leaves it nil.
	ProbeDial ProbeDialFunc
}

// directoryManagerDN matches the daemon's configured root identity
// (ADR-0009 decision 13 default; cmd/labldapd owns the constant).
const directoryManagerDN = "cn=Directory Manager"

// The cn=config read-back contract. These attribute names and value
// formats mirror cmd/labldapd/enginestate.go exactly — the daemon
// publishes them and these reconcilers compare against them. Values are
// plain ASCII: integers base 10, durations as whole seconds, booleans
// "on"/"off", the storage scheme in canonical form (uppercase, dashes).
const (
	configEntryDN = "cn=config"
	engineName    = "native"

	attrEngine             = "labldapEngine"
	attrEngineSuffix       = "labldapEngineSuffix"
	attrPasswordScheme     = "labldapPasswordStorageScheme"
	attrPasswordMinLength  = "labldapPasswordMinLength"
	attrPasswordHistory    = "labldapPasswordHistoryCount"
	attrPasswordMaxAge     = "labldapPasswordMaxAgeSeconds"
	attrLockoutEnabled     = "labldapPasswordLockoutEnabled"
	attrLockoutMaxFailures = "labldapPasswordLockoutMaxFailures"
	attrLockoutDuration    = "labldapPasswordLockoutDurationSeconds"
	attrPlugins            = "labldapPlugins"
)

// ProbeConfig describes one read-back connection attempt.
type ProbeConfig struct {
	Address string
	// Mode is ldap, ldaps, or starttls.
	Mode        directory.Transport
	ServerName  string
	CAFile      string
	Insecure    bool
	DialTimeout time.Duration
}

// Probe is one read-back LDAP session. It is deliberately string-typed so
// this package never touches go-ldap values (import boundary).
type Probe interface {
	Bind(ctx context.Context, dn, password string) error
	Compare(ctx context.Context, dn, attribute, value string) (bool, error)
	Close() error
}

// ProbeDialFunc opens one probe connection.
type ProbeDialFunc func(ctx context.Context, cfg ProbeConfig) (Probe, error)

// engineProbeConfig renders the engine-level probe coordinates.
func (e Engine) engineProbeConfig() ProbeConfig {
	mode := e.Transport
	if mode == "" {
		mode = directory.TransportLDAPS
	}
	return ProbeConfig{
		Address:     e.Address,
		Mode:        mode,
		ServerName:  e.ServerName,
		CAFile:      e.CAFile,
		Insecure:    e.Insecure,
		DialTimeout: e.DialTimeout,
	}
}

func (e Engine) dialProbe(ctx context.Context, cfg ProbeConfig) (Probe, error) {
	d := e.ProbeDial
	if d == nil {
		d = defaultProbeDial
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 5 * time.Second
	}
	return d(ctx, cfg)
}

// dmProbe dials the engine address and binds as Directory Manager. The
// password is resolved from its file and never appears in errors or logs.
func (e Engine) dmProbe(ctx context.Context, phase, passwordFile string) (Probe, error) {
	if e.Address == "" {
		return nil, bootstrap.PhaseError(phase, "unavailable", "native engine address is not configured")
	}
	res, err := config.FileSecretResolver().Resolve(ctx, "directory-manager-password-file", passwordFile)
	if err != nil {
		return nil, bootstrap.PhaseError(phase, "secret_unreadable", "Directory Manager password file unreadable").Wrap(err)
	}
	pr, err := e.dialProbe(ctx, e.engineProbeConfig())
	if err != nil {
		return nil, bootstrap.PhaseError(phase, "unavailable", "labldapd is not reachable").Wrap(err)
	}
	if err := pr.Bind(ctx, directoryManagerDN, res.Value.Reveal()); err != nil {
		_ = pr.Close()
		return nil, bootstrap.PhaseError(phase, "bind_failed", "Directory Manager bind failed").Wrap(err)
	}
	return pr, nil
}

// compareState fails closed unless cn=config carries exactly want for
// attr. want is engine-plane metadata (never secret), so naming it in the
// mismatch message is safe and keeps failures actionable.
func compareState(ctx context.Context, pr Probe, phase, code, attr, want string) error {
	ok, err := pr.Compare(ctx, configEntryDN, attr, want)
	if err != nil {
		return bootstrap.PhaseError(phase, code, "applied engine state is not readable at cn=config").Wrap(err)
	}
	if !ok {
		return bootstrap.PhaseError(phase, code,
			fmt.Sprintf("applied engine plan mismatch at %s: daemon does not carry the planned value %q", attr, want))
	}
	return nil
}

// canonicalScheme normalizes a storage-scheme spelling exactly as the
// daemon does (uppercase, dashes, empty defaults to PBKDF2-SHA256).
func canonicalScheme(s string) string {
	s = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), "_", "-"))
	if s == "" {
		return "PBKDF2-SHA256"
	}
	return s
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// defaultProbeDial opens a real LDAP session through ldapclient.
// AllowCleartextBind is always set client-side: the probes exist to
// verify server-side policy, which includes attempting weak dials the
// server must refuse.
func defaultProbeDial(ctx context.Context, cfg ProbeConfig) (Probe, error) {
	conn, err := ldapclient.Connect(ctx, ldapclient.Config{
		Address:            cfg.Address,
		Transport:          cfg.Mode,
		ServerName:         cfg.ServerName,
		CAFile:             cfg.CAFile,
		InsecureSkipVerify: cfg.Insecure,
		AllowCleartextBind: true,
		DialTimeout:        cfg.DialTimeout,
	})
	if err != nil {
		return nil, err
	}
	return &ldapProbe{conn: conn}, nil
}

type ldapProbe struct {
	conn *ldapclient.Conn
}

func (p *ldapProbe) Bind(ctx context.Context, dn, password string) error {
	return p.conn.Bind(ctx, dn, observability.Secret(password))
}

func (p *ldapProbe) Compare(ctx context.Context, dn, attribute, value string) (bool, error) {
	ok, err := p.conn.Raw().Compare(dn, attribute, value)
	if err != nil {
		return false, ldapclient.MapError(err)
	}
	return ok, nil
}

func (p *ldapProbe) Close() error { return p.conn.Close() }
