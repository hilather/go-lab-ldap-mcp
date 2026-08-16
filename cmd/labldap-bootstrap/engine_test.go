package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ds389"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/native"
)

// compileTransportScenario compiles a minimal native scenario whose
// transport block is transportYAML, returning the compiled scenario and the
// DM password file path.
func compileTransportScenario(t *testing.T, transportYAML string) (*config.Compiled, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	dmFile := filepath.Join(dir, "secrets", "dm")
	for name, val := range map[string]string{
		"dm":           "lab-fixture-dm-password",
		"runtime-ldap": "lab-fixture-runtime-password",
	} {
		if err := os.WriteFile(filepath.Join(dir, "secrets", name), []byte(val+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "lab.yaml")
	src := fmt.Sprintf(`apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata: { name: wiring }
spec:
  directory: { engine: native, suffix: "dc=example,dc=test" }
  transport:
%s
  runtimeAccount: { id: rt, passwordFile: secrets/runtime-ldap }
`, transportYAML)
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	srcBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := config.Compile(t.Context(), srcBytes, path, config.LoadOptions{
		Caller:  config.CallerBootstrap,
		Secrets: config.DirSecretResolver(dir),
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return c, dmFile
}

func TestWireEngineReconcilersDS389(t *testing.T) {
	opt, err := bootstrap.ParseArgs("plan", []string{"--config", "../../config/examples/example-lab.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	if gateErr := wireEngineReconcilers(t.Context(), &opt); gateErr != nil {
		t.Fatalf("gate: %v", gateErr)
	}
	if _, ok := opt.Waiter.(ds389.Admin); !ok {
		t.Fatalf("Waiter = %T, want ds389.Admin", opt.Waiter)
	}
	for name, rec := range map[string]any{
		"Backend": opt.Backend, "TLS": opt.TLS, "Policy": opt.Policy, "Plugins": opt.Plugins,
		"Tree": opt.Tree, "ACIs": opt.ACIs, "Seed": opt.Seed,
		"VerifyRuntime": opt.VerifyRuntime, "VerifyApp": opt.VerifyApp,
		"Drift": opt.Drift, "Marker": opt.Marker, "Capabilities": opt.Capabilities,
	} {
		if _, ok := rec.(ds389.Engine); !ok {
			t.Errorf("%s = %T, want ds389.Engine (389ds path unchanged)", name, rec)
		}
	}
}

func TestWireEngineReconcilersNative(t *testing.T) {
	_, path := writeNativeScenario(t)
	opt, err := bootstrap.ParseArgs("apply", []string{
		"--config", path,
		"--directory-manager-password-file", filepath.Join(filepath.Dir(path), "secrets", "dm"),
		"--directory-ca-file", "/run/tls/ca.crt",
		"--directory-host", "directory",
	})
	if err != nil {
		t.Fatal(err)
	}
	if gateErr := wireEngineReconcilers(t.Context(), &opt); gateErr != nil {
		t.Fatalf("gate: %v", gateErr)
	}

	// Engine plane: native read-back reconcilers only — no ds389
	// reconciler (and therefore no dsconf) in the native path.
	for name, rec := range map[string]any{
		"Backend": opt.Backend, "TLS": opt.TLS, "Policy": opt.Policy, "Plugins": opt.Plugins,
	} {
		if _, ok := rec.(ds389.Engine); ok {
			t.Errorf("%s = ds389.Engine in the native path", name)
		}
		if _, ok := rec.(native.Engine); !ok {
			t.Errorf("%s = %T, want native.Engine", name, rec)
		}
	}
	eng := opt.Backend.(native.Engine)
	if eng.Address != "directory:3636" || eng.Transport != directory.TransportLDAPS {
		t.Errorf("native.Engine target = %s/%s, want directory:3636/ldaps", eng.Address, eng.Transport)
	}
	if eng.ServerName != "directory" || eng.CAFile != "/run/tls/ca.crt" {
		t.Errorf("native.Engine TLS identity = %q/%q", eng.ServerName, eng.CAFile)
	}
	if eng.Insecure {
		t.Error("Insecure set although insecureLabMode is false")
	}
	if eng.ProbeDial != nil {
		t.Error("ProbeDial must stay nil in production wiring (real LDAP dial)")
	}

	// Capability inspect measures the daemon's published plan through the
	// native reconcilers; it must not be the 389 inspector (which needs
	// cn=plugins,cn=config and dsconf).
	if _, ok := opt.Capabilities.(ds389.Engine); ok {
		t.Error("Capabilities = ds389.Engine in the native path")
	}
	if _, ok := opt.Capabilities.(nativeCapabilities); !ok {
		t.Errorf("Capabilities = %T, want nativeCapabilities", opt.Capabilities)
	}

	// Data plane: the LDAP-as-Directory-Manager ds389 implementations.
	if _, ok := opt.Waiter.(ds389.Admin); !ok {
		t.Errorf("Waiter = %T, want ds389.Admin", opt.Waiter)
	}
	for name, rec := range map[string]any{
		"Tree": opt.Tree, "ACIs": opt.ACIs, "Seed": opt.Seed,
		"VerifyRuntime": opt.VerifyRuntime, "VerifyApp": opt.VerifyApp,
		"Drift": opt.Drift, "Marker": opt.Marker,
	} {
		if _, ok := rec.(ds389.Engine); !ok {
			t.Errorf("%s = %T, want ds389.Engine (data plane stays LDAP-as-DM)", name, rec)
		}
	}
}

func TestNativeEngineCoordinates(t *testing.T) {
	cases := []struct {
		name      string
		transport string
		ldapURL   string
		wantAddr  string
		wantMode  directory.Transport
	}{
		{
			name:      "ldaps preferred when enabled",
			transport: "    ldap: { enabled: true, port: 3389 }\n    ldaps: { enabled: true, port: 3636 }",
			wantAddr:  "127.0.0.1:3636",
			wantMode:  directory.TransportLDAPS,
		},
		{
			name:      "starttls over the ldap port",
			transport: "    ldap: { enabled: true, port: 1389 }\n    ldaps: { enabled: false }\n    startTLS: true",
			wantAddr:  "127.0.0.1:1389",
			wantMode:  directory.TransportStartTLS,
		},
		{
			name:      "cleartext ldap",
			transport: "    insecureLabMode: true\n    ldap: { enabled: true, port: 3389 }\n    ldaps: { enabled: false }\n    allowCleartextBind: true",
			wantAddr:  "127.0.0.1:3389",
			wantMode:  directory.TransportLDAP,
		},
		{
			name:      "ldap-url override wins",
			transport: "    ldap: { enabled: true, port: 3389 }\n    ldaps: { enabled: true, port: 3636 }",
			ldapURL:   "ldaps://dir.internal:4636",
			wantAddr:  "dir.internal:4636",
			wantMode:  directory.TransportLDAPS,
		},
		{
			name:      "ldap-url ldap scheme with starttls policy",
			transport: "    ldap: { enabled: true, port: 3389 }\n    ldaps: { enabled: false }\n    startTLS: true",
			ldapURL:   "ldap://dir.internal:3389",
			wantAddr:  "dir.internal:3389",
			wantMode:  directory.TransportStartTLS,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := compileTransportScenario(t, tc.transport)
			opt := bootstrap.Options{DirectoryHost: "127.0.0.1", LDAPURL: tc.ldapURL, CAFile: "/ca.pem"}
			eng := nativeEngineFromCompiled(c, opt)
			if eng.Address != tc.wantAddr || eng.Transport != tc.wantMode {
				t.Fatalf("target = %s/%s, want %s/%s", eng.Address, eng.Transport, tc.wantAddr, tc.wantMode)
			}
			if eng.ServerName != "127.0.0.1" || eng.CAFile != "/ca.pem" {
				t.Fatalf("TLS identity = %q/%q", eng.ServerName, eng.CAFile)
			}
			wantInsecure := strings.Contains(tc.transport, "insecureLabMode: true")
			if eng.Insecure != wantInsecure {
				t.Fatalf("Insecure = %v, want %v", eng.Insecure, wantInsecure)
			}
		})
	}
}

func TestWireEngineReconcilersCompileFailureKeepsDefault(t *testing.T) {
	// A missing/uncompilable scenario leaves the default 389ds set in place
	// and returns no gate error: bootstrap.Run stays the single reporter of
	// configuration errors.
	opt := bootstrap.Options{Command: "apply", ConfigPath: filepath.Join(t.TempDir(), "missing.yaml")}
	if gateErr := wireEngineReconcilers(t.Context(), &opt); gateErr != nil {
		t.Fatalf("gate: %v", gateErr)
	}
	if _, ok := opt.Backend.(ds389.Engine); !ok {
		t.Fatalf("Backend = %T, want ds389.Engine after compile failure", opt.Backend)
	}

	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("apiVersion: v0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opt = bootstrap.Options{Command: "apply", ConfigPath: bad}
	if gateErr := wireEngineReconcilers(t.Context(), &opt); gateErr != nil {
		t.Fatalf("gate: %v", gateErr)
	}
	if _, ok := opt.Capabilities.(ds389.Engine); !ok {
		t.Fatalf("Capabilities = %T, want ds389.Engine after compile failure", opt.Capabilities)
	}
}

// fakeNativeProbe is a scriptable native.Probe for capability tests; state
// holds the daemon's published cn=config values.
type fakeNativeProbe struct {
	state  map[string][]string
	bindPW string
}

func (p *fakeNativeProbe) Bind(_ context.Context, dn, password string) error {
	if dn == "" || password != p.bindPW {
		return errors.New("invalid credentials")
	}
	return nil
}

func (p *fakeNativeProbe) Compare(_ context.Context, dn, attribute, value string) (bool, error) {
	if dn != "cn=config" {
		return false, errors.New("no such object")
	}
	for _, v := range p.state[attribute] {
		if v == value {
			return true, nil
		}
	}
	return false, nil
}

func (p *fakeNativeProbe) Close() error { return nil }

func fakeProbeDial(p *fakeNativeProbe) native.ProbeDialFunc {
	return func(context.Context, native.ProbeConfig) (native.Probe, error) { return p, nil }
}

var capabilityPolicy = config.NormalizedPolicy{
	MinLength:       9,
	HistoryCount:    3,
	MaxAge:          24 * time.Hour,
	LockoutEnabled:  true,
	MaxFailures:     4,
	LockoutDuration: 15 * time.Minute,
	StorageScheme:   "PBKDF2-SHA256",
}

func capabilityState() map[string][]string {
	return map[string][]string{
		"labldapEngine":                         {"native"},
		"labldapEngineSuffix":                   {"dc=example,dc=test"},
		"labldapPasswordStorageScheme":          {"PBKDF2-SHA256"},
		"labldapPasswordMinLength":              {"9"},
		"labldapPasswordHistoryCount":           {"3"},
		"labldapPasswordMaxAgeSeconds":          {"86400"},
		"labldapPasswordLockoutEnabled":         {"on"},
		"labldapPasswordLockoutMaxFailures":     {"4"},
		"labldapPasswordLockoutDurationSeconds": {"900"},
		"labldapPlugins":                        {"memberof", "referint", "account-disable"},
	}
}

func capabilityInspector(dmFile string, pr *fakeNativeProbe) nativeCapabilities {
	return nativeCapabilities{
		eng: native.Engine{
			Address:   "dir:3636",
			Transport: directory.TransportLDAPS,
			Insecure:  true,
			ProbeDial: fakeProbeDial(pr),
		},
		policy:  capabilityPolicy,
		plugins: []string{"memberof", "referint", "account-disable"},
	}
}

func capabilityRequest(dmFile string) bootstrap.CapabilityRequest {
	return bootstrap.CapabilityRequest{
		TreeRequest:        bootstrap.TreeRequest{Suffix: "dc=example,dc=test", UseLDAPS: true},
		PasswordFile:       dmFile,
		RequiredPlugins:    []string{"memberof", "referint", "account-disable"},
		RequiredTransports: []string{"ldaps"},
		RequiredScheme:     "PBKDF2-SHA256",
		Phase:              "verify_app",
	}
}

func TestNativeCapabilitiesMeasuredOK(t *testing.T) {
	_, dmFile := compileTransportScenario(t, "    ldaps: { enabled: true, port: 3636 }")
	nc := capabilityInspector(dmFile, &fakeNativeProbe{state: capabilityState(), bindPW: "lab-fixture-dm-password"})
	caps, err := nc.Capabilities(t.Context(), capabilityRequest(dmFile))
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if !caps.RequiredOK {
		t.Fatalf("RequiredOK false: %+v", caps)
	}
	if caps.PasswordScheme != "PBKDF2-SHA256" {
		t.Fatalf("PasswordScheme = %q", caps.PasswordScheme)
	}
	if len(caps.Plugins) != 3 || caps.Plugins[0] != "account-disable" {
		t.Fatalf("Plugins = %v (want sorted measured set)", caps.Plugins)
	}
	if len(caps.Transports) != 1 || caps.Transports[0] != "ldaps" {
		t.Fatalf("Transports = %v", caps.Transports)
	}
}

func TestNativeCapabilitiesPluginMissingFailsClosed(t *testing.T) {
	_, dmFile := compileTransportScenario(t, "    ldaps: { enabled: true, port: 3636 }")
	state := capabilityState()
	state["labldapPlugins"] = []string{"memberof", "account-disable"}
	nc := capabilityInspector(dmFile, &fakeNativeProbe{state: state, bindPW: "lab-fixture-dm-password"})
	_, err := nc.Capabilities(t.Context(), capabilityRequest(dmFile))
	if err == nil {
		t.Fatal("a plugin the daemon did not apply must fail")
	}
	var ae *apperr.Error
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v (%T)", err, err)
	}
	fs := ae.Fields()
	if len(fs) == 0 || fs[0].Path != "phase.plugins" || fs[0].Code != "plugin_missing" {
		t.Fatalf("fields = %#v", fs)
	}
}

func TestNativeCapabilitiesPolicyMismatchFailsClosed(t *testing.T) {
	_, dmFile := compileTransportScenario(t, "    ldaps: { enabled: true, port: 3636 }")
	state := capabilityState()
	state["labldapPasswordMinLength"] = []string{"21"}
	nc := capabilityInspector(dmFile, &fakeNativeProbe{state: state, bindPW: "lab-fixture-dm-password"})
	_, err := nc.Capabilities(t.Context(), capabilityRequest(dmFile))
	if err == nil {
		t.Fatal("a policy the daemon did not apply must fail")
	}
	var ae *apperr.Error
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v (%T)", err, err)
	}
	fs := ae.Fields()
	if len(fs) == 0 || fs[0].Path != "phase.pwpolicy" || fs[0].Code != "readback_mismatch" {
		t.Fatalf("fields = %#v", fs)
	}
}

func TestNativeCapabilitiesTransportGap(t *testing.T) {
	_, dmFile := compileTransportScenario(t, "    ldaps: { enabled: true, port: 3636 }")
	nc := capabilityInspector(dmFile, &fakeNativeProbe{state: capabilityState(), bindPW: "lab-fixture-dm-password"})
	req := capabilityRequest(dmFile)
	req.RequiredTransports = []string{"ldaps", "starttls"}
	caps, err := nc.Capabilities(t.Context(), req)
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if caps.RequiredOK {
		t.Fatal("RequiredOK must be false when a required transport was not observed")
	}
}
