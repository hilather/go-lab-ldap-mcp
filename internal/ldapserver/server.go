package ldapserver

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
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
	// MaxConnections bounds simultaneously open client connections. A
	// connection arriving at the ceiling receives a busy notice of
	// disconnection and is closed (ADR-0009 decision 10).
	MaxConnections int
	// MaxAuthAttempts is the pre-auth budget of failed bind attempts after
	// which the server closes the connection with a notice of
	// disconnection (ADR-0009 decision 10).
	MaxAuthAttempts int
	// ShutdownTimeout bounds graceful connection drain after Serve's context
	// is canceled; remaining connections are force-closed when it expires.
	ShutdownTimeout time.Duration
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
		MaxConnections:    256,
		MaxAuthAttempts:   5,
		ShutdownTimeout:   10 * time.Second,
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
	if l.MaxConnections <= 0 {
		l.MaxConnections = d.MaxConnections
	}
	if l.MaxAuthAttempts <= 0 {
		l.MaxAuthAttempts = d.MaxAuthAttempts
	}
	if l.ShutdownTimeout <= 0 {
		l.ShutdownTimeout = d.ShutdownTimeout
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
	// AllowAnonymousBind permits anonymous binds. Default off (C3). When
	// off, unauthenticated directory operations (search including Root DSE
	// and subschema, compare, writes, and extended ops other than StartTLS)
	// are also refused with inappropriateAuthentication (48), matching
	// pinned 389 (KD-6 / D21 / D24).
	AllowAnonymousBind bool
	// AllowCleartextBind permits simple bind without TLS. Default off; only
	// explicit insecure lab mode turns it on (C3).
	AllowCleartextBind bool
	// PasswordPolicy enables the T-134 policy engine: scheme-aware hash
	// verification on binds, bind-failure lockout with
	// pwdAccountLockedTime, and — as an automatically registered Plugin —
	// hash-on-write, minimum length, history, and pwdChangedTime on the
	// write path. Nil preserves the T-126 constant-time plaintext compare
	// with no policy state. The engine plugin is appended last so it
	// observes other plugins' in-transaction changes.
	PasswordPolicy *PasswordPolicy
	Limits         Limits
	// Clock supplies the current time for server-maintained operational
	// attributes (createTimestamp, modifyTimestamp, T-137). Nil uses
	// time.Now; tests inject a fake clock.
	Clock func() time.Time
	// NewUUID supplies entryUUID values on Add (T-137). Nil generates a
	// random RFC 4122 version 4 UUID.
	NewUUID func() string
	Codec   Codec
	Store   Store
	Schema  Schema
	// ACI is the access-control engine (T-139); tests inject FakeACI. When
	// nil, New builds the evaluating engine from ACITexts.
	ACI ACIEngine
	// ACITexts holds the compiled ACI set — the four runtime ACIs plus any
	// operator ACLs (parity contract C8) — as compiler-emitted ACI text. It
	// is consulted only when ACI is nil; a parse failure is a configuration
	// error because a partial access policy must never be served.
	ACITexts []string
	Plugins  []Plugin
	// Metrics receives bounded-cardinality observations (op name + result
	// code, connection open/close). Nil disables metrics. DNs and attribute
	// values never cross this seam.
	Metrics Metrics
	// DirectoryManager is the bootstrap-root identity. An empty DN disables
	// it; no other identity may bypass ACI (ADR-0009 decision 13).
	DirectoryManager Identity
	Logger           *slog.Logger
}

// Server is the native directory engine. The constructor validates and
// normalizes Options; Serve binds the listeners (T-125).
type Server struct {
	opts   Options
	suffix config.DN
	dmDN   config.DN
	hasDM  bool

	// passwords is the T-134 policy engine, consulted by the bind path
	// through the passwordGate seam; nil without Options.PasswordPolicy.
	passwords *passwordEngine

	// pageKey is the HMAC key signing Simple Paged Results cookies
	// (T-140, ctrl_paged.go): 32 random bytes generated in New, held only
	// in memory, never persisted, configured, or logged. Cookies are
	// therefore valid only against the server instance that issued them.
	pageKey []byte

	// ldapAddr and ldapsAddr hold the bound net.Addr once Serve has
	// opened the listeners (atomic.Value of net.Addr).
	ldapAddr  atomic.Value
	ldapsAddr atomic.Value

	connsMu sync.Mutex
	conns   map[*conn]struct{}
	connWG  sync.WaitGroup
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
		if len(opts.ACITexts) == 0 {
			return nil, fieldErr("aci", "required", "an ACI engine is required")
		}
		eng, err := NewACIEngine(opts.ACITexts, opts.Logger)
		if err != nil {
			return nil, fieldErr("aciTexts", "invalid_aci", "ACI text failed to parse: "+err.Error())
		}
		opts.ACI = eng
	}
	if opts.Logger == nil {
		return nil, fieldErr("logger", "required", "a slog logger is required")
	}
	suffix, err := config.ParseDN(opts.Suffix)
	if err != nil {
		return nil, fieldErr("suffix", "invalid_dn", "suffix is not a valid DN")
	}
	pageKey := make([]byte, 32)
	if _, err := rand.Read(pageKey); err != nil {
		return nil, fmt.Errorf("ldapserver: paged results cookie key: %w", err)
	}
	s := &Server{opts: opts, suffix: suffix, pageKey: pageKey, conns: map[*conn]struct{}{}}
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
	if opts.TLSConfig != nil {
		// Clone so the caller's config is never mutated, and raise the
		// protocol floor to TLS 1.2 (security posture: harden, never
		// loosen).
		s.opts.TLSConfig = serverTLSConfig(opts.TLSConfig)
	}
	if s.opts.LDAPAddress, err = loopbackDefault(opts.LDAPAddress); err != nil {
		return nil, fieldErr("ldapAddress", "invalid_address", "LDAP listener address is invalid")
	}
	if s.opts.LDAPSAddress, err = loopbackDefault(opts.LDAPSAddress); err != nil {
		return nil, fieldErr("ldapsAddress", "invalid_address", "LDAPS listener address is invalid")
	}
	if opts.PasswordPolicy != nil {
		eng, err := newPasswordEngine(*opts.PasswordPolicy, opts.Logger)
		if err != nil {
			return nil, err
		}
		s.passwords = eng
		s.opts.Plugins = append(s.opts.Plugins, eng)
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

// LDAPAddr returns the bound LDAP listener address once Serve has opened
// the listener; nil before that.
func (s *Server) LDAPAddr() net.Addr {
	if v, ok := s.ldapAddr.Load().(net.Addr); ok {
		return v
	}
	return nil
}

// LDAPSAddr returns the bound LDAPS listener address once Serve has opened
// the listener; nil before that.
func (s *Server) LDAPSAddr() net.Addr {
	if v, ok := s.ldapsAddr.Load().(net.Addr); ok {
		return v
	}
	return nil
}

// Serve binds the configured listeners and serves until ctx is canceled
// (T-125). On cancellation it stops accepting, waits up to
// Limits.ShutdownTimeout for connections to drain, then force-closes the
// rest and returns nil. Listener setup failures return a wrapped error.
func (s *Server) Serve(ctx context.Context) error {
	if s.opts.LDAPAddress == "" && s.opts.LDAPSAddress == "" {
		return apperr.New(apperr.CodeConfiguration, "ldapserver: at least one listener address is required")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type binding struct {
		listener net.Listener
		tls      bool
	}
	var bindings []binding
	var lc net.ListenConfig
	if s.opts.LDAPAddress != "" {
		l, err := lc.Listen(ctx, "tcp", s.opts.LDAPAddress)
		if err != nil {
			return fmt.Errorf("ldapserver: listen LDAP: %w", err)
		}
		bindings = append(bindings, binding{listener: l})
		s.ldapAddr.Store(l.Addr())
		s.opts.Logger.LogAttrs(ctx, slog.LevelInfo, "ldap listener bound",
			slog.String("address", l.Addr().String()))
	}
	if s.opts.LDAPSAddress != "" {
		l, err := lc.Listen(ctx, "tcp", s.opts.LDAPSAddress)
		if err != nil {
			for _, b := range bindings {
				_ = b.listener.Close()
			}
			return fmt.Errorf("ldapserver: listen LDAPS: %w", err)
		}
		bindings = append(bindings, binding{listener: tls.NewListener(l, s.opts.TLSConfig), tls: true})
		s.ldapsAddr.Store(l.Addr())
		s.opts.Logger.LogAttrs(ctx, slog.LevelInfo, "ldaps listener bound",
			slog.String("address", l.Addr().String()))
	}

	var acceptWG sync.WaitGroup
	for _, b := range bindings {
		acceptWG.Add(1)
		go func() {
			defer acceptWG.Done()
			s.acceptLoop(ctx, b.listener, b.tls)
		}()
	}

	<-ctx.Done()

	// Graceful shutdown: stop accepting, then drain connections up to the
	// shutdown deadline; force-close whatever is still open afterwards.
	for _, b := range bindings {
		_ = b.listener.Close()
	}
	acceptWG.Wait()
	drained := make(chan struct{})
	go func() {
		s.connWG.Wait()
		close(drained)
	}()
	timer := time.NewTimer(s.opts.Limits.ShutdownTimeout)
	defer timer.Stop()
	select {
	case <-drained:
	case <-timer.C:
		s.opts.Logger.LogAttrs(context.Background(), slog.LevelInfo,
			"shutdown drain deadline reached; force-closing connections")
		s.closeAllConns()
		<-drained
	}
	return nil
}

// acceptLoop accepts until the listener closes or ctx is canceled.
func (s *Server) acceptLoop(ctx context.Context, l net.Listener, isTLS bool) {
	for {
		nc, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			s.opts.Logger.LogAttrs(ctx, slog.LevelWarn, "ldap accept failed",
				slog.String("error", err.Error()))
			return
		}
		c := s.newConn(ctx, nc, isTLS)
		if !s.addConn(c) {
			// Connection ceiling: tell the client why, then close.
			c.sendNoticeOfDisconnection(ResultBusy, "connection limit reached")
			_ = nc.Close()
			c.cancel()
			continue
		}
		s.metrics().ObserveConnection(1)
		go c.serve()
	}
}

// addConn registers c, enforcing the MaxConnections ceiling.
func (s *Server) addConn(c *conn) bool {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	if len(s.conns) >= s.opts.Limits.MaxConnections {
		return false
	}
	s.conns[c] = struct{}{}
	s.connWG.Add(1)
	return true
}

// removeConn deregisters c at the end of its lifecycle.
func (s *Server) removeConn(c *conn) {
	s.connsMu.Lock()
	delete(s.conns, c)
	s.connsMu.Unlock()
	s.connWG.Done()
	s.metrics().ObserveConnection(-1)
}

// closeAllConns force-closes every open connection (shutdown deadline).
func (s *Server) closeAllConns() {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	for c := range s.conns {
		c.close()
	}
}

// Close releases the store.
func (s *Server) Close() error {
	return s.opts.Store.Close()
}
