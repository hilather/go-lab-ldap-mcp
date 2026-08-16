package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/config/v1alpha1"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ds389"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/native"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

// T-146 engine-selection seam (ADR-0008, ADR-0009): labldap-bootstrap is an
// LDAP client of whichever engine the scenario selects. Only the engine
// plane (backend, TLS, password policy, plugins, capability inspect)
// differs between engines; the data plane (wait, tree, ACIs, seed, verify,
// drift, marker) is LDAP-as-Directory-Manager either way.
//
//	engine: 389ds  — the ds389 reconciler set drives dsconf + LDAP probes.
//	engine: native — labldapd self-applies the engine plan at start, so the
//	                 engine plane is the native read-back reconcilers
//	                 (internal/directory/native) and capability inspect
//	                 measures the daemon's published plan through them.
//	                 No ds389 reconciler (and no dsconf) runs in this path.

// wireEngineReconcilers compiles the scenario and selects the reconciler
// set for its engine. It returns the engine-availability gate error: both
// wired engines return nil, anything else fails closed. A read or compile
// failure leaves the default 389ds set wired and returns nil so
// bootstrap.Run stays the single reporter of configuration errors.
func wireEngineReconcilers(ctx context.Context, opt *bootstrap.Options) error {
	src, err := os.ReadFile(opt.ConfigPath)
	if err != nil {
		wireDS389(opt)
		return nil
	}
	compiled, err := config.Compile(ctx, src, opt.ConfigPath, config.LoadOptions{
		Caller:  config.CallerBootstrap,
		Secrets: config.DirSecretResolver(filepath.Dir(opt.ConfigPath)),
	})
	if err != nil {
		wireDS389(opt)
		return nil
	}
	if compiled.Engine.Engine == v1alpha1.EngineNative {
		wireNative(opt, compiled)
	} else {
		wireDS389(opt)
	}
	return config.RequireAvailableEngine(compiled.Engine.Engine)
}

// wireDS389 selects the 389 DS reconciler set (the default, unchanged since
// before T-146): dsconf-backed engine plane and LDAP-as-DM data plane.
func wireDS389(opt *bootstrap.Options) {
	opt.Waiter = ds389.Admin{}
	eng := ds389.Engine{}
	opt.Backend = eng
	opt.TLS = eng
	opt.Policy = eng
	opt.Plugins = eng
	opt.Tree = eng
	opt.ACIs = eng
	opt.Seed = eng
	opt.VerifyRuntime = eng
	opt.VerifyApp = eng
	opt.Drift = eng
	opt.Marker = eng
	opt.Capabilities = eng
}

// wireNative selects the native reconciler set: the read-back reconcilers
// verify the daemon's self-applied engine plan, and the data plane stays
// the LDAP-as-DM ds389 implementations pointed at the native listener
// (ADR-0009 decision 12).
func wireNative(opt *bootstrap.Options, c *config.Compiled) {
	eng := nativeEngineFromCompiled(c, *opt)
	opt.Backend = eng
	opt.TLS = eng
	opt.Policy = eng
	opt.Plugins = eng
	opt.Capabilities = nativeCapabilities{
		eng:     eng,
		policy:  c.Engine.PasswordPolicy,
		plugins: append([]string(nil), c.Engine.Plugins...),
	}

	data := ds389.Engine{}
	opt.Waiter = ds389.Admin{}
	opt.Tree = data
	opt.ACIs = data
	opt.Seed = data
	opt.VerifyRuntime = data
	opt.VerifyApp = data
	opt.Drift = data
	opt.Marker = data
}

// nativeEngineFromCompiled derives the native.Engine probe coordinates from
// the compiled scenario and the CLI overrides. The dial choice mirrors the
// waiter's canonical URL selection (ds389 dialURL): an explicit --ldap-url
// wins; otherwise prefer LDAPS, then StartTLS, then cleartext LDAP.
// --directory-host stays the TLS server name (the certificate name), never
// the dial address.
func nativeEngineFromCompiled(c *config.Compiled, opt bootstrap.Options) native.Engine {
	transport := c.Public.Spec.Transport
	host := opt.DirectoryHost
	if host == "" {
		host = "127.0.0.1"
	}
	ldapPort := transport.LDAP.Port
	if ldapPort <= 0 {
		ldapPort = 3389
	}
	ldapsPort := transport.LDAPS.Port
	if ldapsPort <= 0 {
		ldapsPort = 3636
	}

	addr := net.JoinHostPort(host, strconv.Itoa(ldapsPort))
	mode := directory.TransportLDAPS
	switch {
	case opt.LDAPURL != "":
		addr = strings.TrimPrefix(strings.TrimPrefix(opt.LDAPURL, "ldaps://"), "ldap://")
		mode = directory.TransportLDAP
		if strings.HasPrefix(opt.LDAPURL, "ldaps://") {
			mode = directory.TransportLDAPS
		} else if transport.StartTLS {
			mode = directory.TransportStartTLS
		}
	case transport.LDAPS.Enabled:
		// addr/mode already hold the LDAPS target.
	case transport.StartTLS:
		addr = net.JoinHostPort(host, strconv.Itoa(ldapPort))
		mode = directory.TransportStartTLS
	default:
		addr = net.JoinHostPort(host, strconv.Itoa(ldapPort))
		mode = directory.TransportLDAP
	}

	var dialTO time.Duration
	if d, err := time.ParseDuration(c.Public.Spec.Limits.LDAPDialTimeout); err == nil && d > 0 {
		dialTO = d
	}
	return native.Engine{
		Address:     addr,
		Transport:   mode,
		ServerName:  host,
		CAFile:      opt.CAFile,
		Insecure:    transport.InsecureLabMode,
		DialTimeout: dialTO,
	}
}

// nativeCapabilities is the engine=native capability inspector (parity
// contract C10: measured, not name-assumed). The Compare-based probe seam
// cannot enumerate Root DSE values, so measurement is delegated to the
// native read-back reconcilers, which compare the daemon's published
// cn=config plan as Directory Manager: ReconcilePlugins proves every
// required plugin and ReconcilePolicy proves the storage scheme (and the
// rest of the policy). Transports are request-observed, exactly as the
// ds389 inspector reports them; the tls phase proves them with real binds
// before this inspector runs. Any mismatch fails closed with the native
// reconciler's phase error rather than a silent capability gap.
type nativeCapabilities struct {
	eng     native.Engine
	policy  config.NormalizedPolicy
	plugins []string
}

func (n nativeCapabilities) Capabilities(ctx context.Context, req bootstrap.CapabilityRequest) (bootstrap.Capabilities, error) {
	plugins := req.RequiredPlugins
	if len(plugins) == 0 {
		plugins = n.plugins
	}
	if _, err := n.eng.ReconcilePlugins(ctx, bootstrap.PluginRequest{
		PasswordFile: req.PasswordFile,
		Suffix:       req.Suffix,
		Plugins:      plugins,
	}); err != nil {
		return bootstrap.Capabilities{}, err
	}
	if _, err := n.eng.ReconcilePolicy(ctx, bootstrap.PolicyRequest{
		PasswordFile: req.PasswordFile,
		Policy:       n.policy,
	}); err != nil {
		return bootstrap.Capabilities{}, err
	}

	caps := bootstrap.Capabilities{
		AdapterVersion: observability.CurrentBuild("labldap-bootstrap").Version,
		Transports:     observedTransports(req),
		Plugins:        append([]string(nil), plugins...),
		PasswordScheme: n.policy.StorageScheme,
	}
	sort.Strings(caps.Plugins)
	caps.RequiredOK = len(plugins) > 0 &&
		containsAllFold(caps.Transports, req.RequiredTransports) &&
		schemeMatches(caps.PasswordScheme, req.RequiredScheme)
	return caps, nil
}

// observedTransports mirrors the ds389 inspector's request-derived
// transport list (the tls phase already probed each with a real bind).
func observedTransports(req bootstrap.CapabilityRequest) []string {
	var out []string
	if req.UseLDAPS || strings.HasPrefix(req.LDAPURL, "ldaps://") {
		out = append(out, "ldaps")
	}
	if req.StartTLS {
		out = append(out, "starttls")
	}
	sort.Strings(out)
	return out
}

func containsAllFold(have, want []string) bool {
	set := map[string]struct{}{}
	for _, h := range have {
		set[strings.ToLower(h)] = struct{}{}
	}
	for _, w := range want {
		if _, ok := set[strings.ToLower(w)]; !ok {
			return false
		}
	}
	return true
}

// schemeMatches compares storage schemes in canonical form (uppercase,
// dashes), matching the daemon's published spelling.
func schemeMatches(got, want string) bool {
	if want == "" {
		return true
	}
	canon := func(s string) string {
		return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), "_", "-"))
	}
	return canon(got) == canon(want)
}
