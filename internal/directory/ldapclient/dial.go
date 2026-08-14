package ldapclient

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

// Conn is a live LDAP session. Pooled callers must Release or Invalidate.
type Conn struct {
	raw       *ldap.Conn
	cfg       Config
	pool      *Pool
	createdAt time.Time
	lastUsed  time.Time
	broken    atomic.Bool
	released  atomic.Bool
}

// Raw exposes the go-ldap connection for ds389 repositories.
func (c *Conn) Raw() *ldap.Conn {
	if c == nil {
		return nil
	}
	return c.raw
}

func (c *Conn) markBroken() { c.broken.Store(true) }

func (c *Conn) isBroken() bool { return c != nil && c.broken.Load() }

// Connect opens a TLS-protected (or explicit insecure) LDAP connection without binding.
// Simple bind is never performed here so TLS always precedes bind.
func Connect(ctx context.Context, cfg Config) (*Conn, error) {
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, MapError(err)
	}
	raw, err := dialNetwork(ctx, cfg)
	if err != nil {
		return nil, MapError(err)
	}
	applyTimeout(ctx, raw, cfg.OpTimeout)
	now := time.Now()
	return &Conn{raw: raw, cfg: cfg, createdAt: now, lastUsed: now}, nil
}

// Dial connects with configured TLS protection and then performs a simple bind.
func Dial(ctx context.Context, cfg Config) (*Conn, error) {
	c, err := Connect(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if cfg.BindDN == "" && cfg.BindPassword.Reveal() == "" {
		return c, nil
	}
	if err := c.Bind(ctx, cfg.BindDN, cfg.BindPassword); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

func dialNetwork(ctx context.Context, cfg Config) (*ldap.Conn, error) {
	dialer := &net.Dialer{Timeout: cfg.DialTimeout}
	switch cfg.Transport {
	case directory.TransportLDAPS:
		tc, err := tlsConfig(cfg)
		if err != nil {
			return nil, err
		}
		td := &tls.Dialer{NetDialer: dialer, Config: tc}
		nc, err := td.DialContext(ctx, "tcp", cfg.Address)
		if err != nil {
			return nil, err
		}
		conn := ldap.NewConn(nc, true)
		conn.Start()
		return conn, nil
	case directory.TransportStartTLS:
		tc, err := tlsConfig(cfg)
		if err != nil {
			return nil, err
		}
		nc, err := dialer.DialContext(ctx, "tcp", cfg.Address)
		if err != nil {
			return nil, err
		}
		conn := ldap.NewConn(nc, false)
		conn.Start()
		if err := startTLS(ctx, conn, tc); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	default:
		nc, err := dialer.DialContext(ctx, "tcp", cfg.Address)
		if err != nil {
			return nil, err
		}
		conn := ldap.NewConn(nc, false)
		conn.Start()
		return conn, nil
	}
}

func startTLS(ctx context.Context, conn *ldap.Conn, tc *tls.Config) error {
	return runOp(ctx, conn, func() error { return conn.StartTLS(tc) })
}

func applyTimeout(ctx context.Context, conn *ldap.Conn, op time.Duration) {
	if d, ok := ctx.Deadline(); ok {
		rem := time.Until(d)
		if rem < op || op <= 0 {
			op = rem
		}
	}
	if op > 0 {
		conn.SetTimeout(op)
	}
}

func runOp(ctx context.Context, conn *ldap.Conn, fn func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case <-ctx.Done():
		conn.Close()
		<-done
		return ctx.Err()
	case err := <-done:
		return err
	}
}

// Bind performs a simple bind on an already-protected connection.
func (c *Conn) Bind(ctx context.Context, dn string, password observability.Secret) error {
	if c == nil || c.raw == nil {
		return directory.Error("connection", directory.FieldUnavailable, "directory unavailable")
	}
	applyTimeout(ctx, c.raw, c.cfg.OpTimeout)
	err := runOp(ctx, c.raw, func() error { return c.raw.Bind(dn, password.Reveal()) })
	if err != nil {
		c.markBroken()
		return MapError(err)
	}
	return nil
}

// Ping issues a Root DSE base search to detect a dead connection.
func (c *Conn) Ping(ctx context.Context) error {
	_, err := c.Search(ctx, ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 5, false,
		"(objectClass=*)", []string{"namingContexts"}, nil,
	))
	return err
}

// Search runs an LDAP search and maps result codes.
func (c *Conn) Search(ctx context.Context, req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if c == nil || c.raw == nil {
		return nil, directory.Error("connection", directory.FieldUnavailable, "directory unavailable")
	}
	applyTimeout(ctx, c.raw, c.cfg.OpTimeout)
	var res *ldap.SearchResult
	err := runOp(ctx, c.raw, func() error {
		var e error
		res, e = c.raw.Search(req)
		return e
	})
	if err != nil {
		if isBroken(err) {
			c.markBroken()
		}
		return nil, MapError(err)
	}
	return res, nil
}

func (c *Conn) Add(ctx context.Context, req *ldap.AddRequest) error {
	return c.mutate(ctx, func() error { return c.raw.Add(req) })
}

func (c *Conn) Modify(ctx context.Context, req *ldap.ModifyRequest) error {
	return c.mutate(ctx, func() error { return c.raw.Modify(req) })
}

func (c *Conn) Del(ctx context.Context, req *ldap.DelRequest) error {
	return c.mutate(ctx, func() error { return c.raw.Del(req) })
}

func (c *Conn) mutate(ctx context.Context, fn func() error) error {
	if c == nil || c.raw == nil {
		return directory.Error("connection", directory.FieldUnavailable, "directory unavailable")
	}
	applyTimeout(ctx, c.raw, c.cfg.OpTimeout)
	err := runOp(ctx, c.raw, fn)
	if err != nil {
		if isBroken(err) {
			c.markBroken()
		}
		return MapError(err)
	}
	return nil
}

// Close tears down the network session. Prefer Release for pooled conns.
func (c *Conn) Close() error {
	if c == nil {
		return nil
	}
	c.markBroken()
	if c.raw != nil {
		return c.raw.Close()
	}
	return nil
}

// Invalidate marks the connection broken and returns it to the pool for eviction.
func (c *Conn) Invalidate() {
	if c == nil {
		return
	}
	c.markBroken()
	c.Release()
}

// Release returns a healthy connection to the pool or closes a broken one.
func (c *Conn) Release() {
	if c == nil || !c.released.CompareAndSwap(false, true) {
		return
	}
	if c.pool == nil {
		_ = c.Close()
		return
	}
	c.pool.put(c)
}
