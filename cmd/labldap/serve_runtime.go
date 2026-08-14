package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/audit"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ds389"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ldapclient"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
	"github.com/hilather/go-lab-ldap-mcp/internal/reset"
)

type serveFlags struct {
	placeholder bool
	configPath  string
	ldapURL     string
	caFile      string
	dirHost     string
}

func parseServeFlags(args []string) (serveFlags, error) {
	var f serveFlags
	f.ldapURL = os.Getenv("LABLDAP_LDAP_URL")
	f.caFile = os.Getenv("LABLDAP_DIRECTORY_CA_FILE")
	f.dirHost = os.Getenv("LABLDAP_DIRECTORY_HOST")
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--placeholder":
			f.placeholder = true
		case a == "--config":
			if i+1 >= len(args) {
				return f, fmt.Errorf("--config requires a path")
			}
			i++
			f.configPath = args[i]
		case strings.HasPrefix(a, "--config="):
			f.configPath = strings.TrimPrefix(a, "--config=")
		case a == "--ldap-url":
			if i+1 >= len(args) {
				return f, fmt.Errorf("--ldap-url requires a value")
			}
			i++
			f.ldapURL = args[i]
		case strings.HasPrefix(a, "--ldap-url="):
			f.ldapURL = strings.TrimPrefix(a, "--ldap-url=")
		case a == "--directory-ca-file":
			if i+1 >= len(args) {
				return f, fmt.Errorf("--directory-ca-file requires a path")
			}
			i++
			f.caFile = args[i]
		case strings.HasPrefix(a, "--directory-ca-file="):
			f.caFile = strings.TrimPrefix(a, "--directory-ca-file=")
		case a == "--directory-host":
			if i+1 >= len(args) {
				return f, fmt.Errorf("--directory-host requires a value")
			}
			i++
			f.dirHost = args[i]
		case strings.HasPrefix(a, "--directory-host="):
			f.dirHost = strings.TrimPrefix(a, "--directory-host=")
		case a == "-h", a == "--help":
			return f, errServeHelp
		default:
			return f, fmt.Errorf("unknown flag %q", a)
		}
	}
	if !f.placeholder && f.configPath == "" {
		return f, fmt.Errorf("--config PATH or --placeholder is required")
	}
	return f, nil
}

var errServeHelp = fmt.Errorf("help")

func ldapClientConfig(c *config.Compiled, f serveFlags, metrics ldapclient.Metrics) (ldapclient.Config, error) {
	pub := c.Public
	ldapURL := strings.TrimSpace(f.ldapURL)
	if ldapURL == "" {
		host := "127.0.0.1"
		if pub.Spec.Transport.LDAPS.Enabled {
			port := pub.Spec.Transport.LDAPS.Port
			if port <= 0 {
				port = 3636
			}
			ldapURL = "ldaps://" + net.JoinHostPort(host, strconv.Itoa(port))
		} else {
			port := pub.Spec.Transport.LDAP.Port
			if port <= 0 {
				port = 3389
			}
			ldapURL = "ldap://" + net.JoinHostPort(host, strconv.Itoa(port))
		}
	}
	u, err := url.Parse(ldapURL)
	if err != nil || u.Host == "" {
		return ldapclient.Config{}, fmt.Errorf("invalid --ldap-url")
	}
	addr := u.Host
	if u.Port() == "" {
		if u.Scheme == "ldaps" {
			addr = net.JoinHostPort(u.Hostname(), "3636")
		} else {
			addr = net.JoinHostPort(u.Hostname(), "3389")
		}
	}
	transport := directory.TransportLDAPS
	switch strings.ToLower(u.Scheme) {
	case "ldaps":
		transport = directory.TransportLDAPS
	case "ldap":
		if pub.Spec.Transport.StartTLS {
			transport = directory.TransportStartTLS
		} else {
			transport = directory.TransportLDAP
		}
	default:
		return ldapclient.Config{}, fmt.Errorf("unsupported ldap URL scheme")
	}
	dialTO := 5 * time.Second
	if d, err := time.ParseDuration(pub.Spec.Limits.LDAPDialTimeout); err == nil && d > 0 {
		dialTO = d
	}
	idle := time.Duration(0)
	if d, err := time.ParseDuration(pub.Spec.Limits.LDAPMaxIdle); err == nil {
		idle = d
	}
	life := time.Duration(0)
	if d, err := time.ParseDuration(pub.Spec.Limits.LDAPMaxLifetime); err == nil {
		life = d
	}
	serverName := strings.TrimSpace(f.dirHost)
	if serverName == "" {
		serverName = u.Hostname()
	}
	cfg := ldapclient.Config{
		Address:            addr,
		Transport:          transport,
		ServerName:         serverName,
		CAFile:             strings.TrimSpace(f.caFile),
		InsecureSkipVerify: pub.Spec.Transport.InsecureLabMode,
		AllowCleartextBind: pub.Spec.Transport.AllowCleartextBind || pub.Spec.Transport.InsecureLabMode,
		DialTimeout:        dialTO,
		WaitTimeout:        dialTO,
		BindDN:             c.Normalized.Runtime.DN,
		BindPassword:       c.Normalized.Runtime.Password.Value,
		PoolSize:           pub.Spec.Limits.LDAPPoolSize,
		MaxIdle:            idle,
		MaxLifetime:        life,
		Metrics:            metrics,
	}
	return cfg, nil
}

type ldapPoolMetrics struct{ m *observability.Registry }

func (l ldapPoolMetrics) OnDial(ok bool) {
	if l.m != nil {
		l.m.ObserveLDAPDial(ok)
	}
}
func (l ldapPoolMetrics) OnAcquire(d time.Duration) {
	if l.m != nil {
		l.m.ObserveLDAPAcquire(d)
	}
}
func (l ldapPoolMetrics) OnRelease() {
	if l.m != nil {
		l.m.ObserveLDAPRelease()
	}
}
func (l ldapPoolMetrics) OnEvict(reason string) {
	if l.m != nil {
		l.m.ObserveLDAPEvict(reason)
	}
}
func (l ldapPoolMetrics) OnWaitTimeout() {
	if l.m != nil {
		l.m.ObserveLDAPWaitTimeout()
	}
}

func attachDirectory(opt *apiOptionsBuilder) error {
	cfg, err := ldapClientConfig(opt.compiled, opt.flags, ldapPoolMetrics{m: opt.metrics})
	if err != nil {
		return err
	}
	pool, err := ldapclient.NewPool(cfg)
	if err != nil {
		return err
	}
	rtCfg := runtimeConfigFromCompiled(opt.compiled)
	rtCfg.Client = cfg
	if d, err := time.ParseDuration(opt.compiled.Public.Spec.Limits.SearchTimeLimit); err == nil {
		rtCfg.SearchTimeLimit = d
	}
	rt, err := ds389.NewRuntime(pool, rtCfg)
	if err != nil {
		_ = pool.Close()
		return err
	}
	gate := reset.NewGate()
	gate.SetMetrics(opt.metrics)
	sink := audit.NewSink(opt.log, audit.DefaultCapacity)
	n := opt.compiled.Normalized
	svc := app.New(app.Deps{
		Users:            rt.Users(),
		Groups:           rt.Groups(),
		Search:           rt,
		Bind:             rt,
		Schema:           rt,
		Caps:             rt,
		Marker:           rt,
		Audit:            app.HookAuditor{Hook: sink},
		Gate:             gate,
		ResetLock:        gate,
		Limit:            opt.limit,
		ExpectedRevision: opt.compiled.Revisions.Directory,
		ControlRevision:  opt.compiled.Revisions.Control,
		PeopleDN:         n.PeopleDN.String(),
		GroupsDN:         n.GroupsDN.String(),
		Suffix:           n.Suffix.String(),
		RuntimeDN:        n.Runtime.DN,
		MarkerDN:         opt.compiled.Data.Marker,
		ResetDir:         rt,
		Secrets:          config.DirSecretResolver(filepath.Dir(opt.compiled.Source)),
		SoftReset:        n.SoftReset,
		ScenarioName:     n.Name,
		ResetUsers:       n.Users,
		ResetGroups:      n.Groups,
	})
	_ = svc.Reset.Inspect(context.Background())
	probe := &app.Probe{
		Ping: func(ctx context.Context) error {
			return pool.Do(ctx, func(c *ldapclient.Conn) error { return c.Ping(ctx) })
		},
		Marker:      rt,
		Caps:        rt,
		Expected:    opt.compiled.Revisions.Directory,
		StartupMode: n.StartupMode,
		ResetState:  func() string { return string(gate.State()) },
		BaselineOK:  svc.Reset.BaselinePresent,
		Pool: func() app.PoolView {
			st := pool.Stats()
			return app.PoolView{Active: st.Active, Idle: st.Idle, Max: st.Max}
		},
	}
	opt.pool = pool
	opt.probe = probe
	opt.users = svc.Users
	opt.groups = svc.Groups
	opt.query = svc.Query
	opt.system = svc.Query
	opt.audit = sink
	opt.auditHook = sink
	opt.gate = gate
	return nil
}

// apiOptionsBuilder is the serve composition root (KD-R15).
type apiOptionsBuilder struct {
	compiled  *config.Compiled
	flags     serveFlags
	log       *slog.Logger
	metrics   *observability.Registry
	limit     *app.Window
	pool      *ldapclient.Pool
	probe     *app.Probe
	users     *app.Users
	groups    *app.Groups
	query     *app.Query
	system    *app.Query
	audit     *audit.Sink
	auditHook audit.Hook
	gate      *reset.Gate
}
