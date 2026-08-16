package native_test

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
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/native"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

const (
	testDMFile = "dm.secret"
	testDMPW   = "probe-canary-pw-never-logged"
)

// fakeProbe is a scriptable Probe. state holds cn=config attribute values;
// binds records attempted dn/password pairs so tests can assert which
// binds were tried (and that cleartext/anonymous probes ran).
type fakeProbe struct {
	state  map[string][]string
	bindPW string // accepted DM password; empty accepts everything
	binds  []bindAttempt

	failBindOn map[string]bool // "mode|addr" dial keys that refuse binds
	dialKey    string
}

type bindAttempt struct {
	key string
	dn  string
}

// fakeDial implements native.ProbeDialFunc over a map of fake probes keyed
// by "mode|address". dialErr fails every dial (daemon down).
type fakeDial struct {
	probes     map[string]*fakeProbe
	dialErr    error
	dialedKeys []string
}

func (f *fakeDial) dial(ctx context.Context, cfg native.ProbeConfig) (native.Probe, error) {
	if f.dialErr != nil {
		return nil, f.dialErr
	}
	key := string(cfg.Mode) + "|" + cfg.Address
	f.dialedKeys = append(f.dialedKeys, key)
	pr, ok := f.probes[key]
	if !ok {
		return nil, fmt.Errorf("no listener for %s", key)
	}
	pr.dialKey = key
	return pr, nil
}

func (p *fakeProbe) Bind(_ context.Context, dn, password string) error {
	p.binds = append(p.binds, bindAttempt{key: p.dialKey, dn: dn})
	if p.failBindOn[p.dialKey] {
		return errors.New("bind refused by server policy")
	}
	if dn == "" {
		return errors.New("anonymous bind refused")
	}
	if p.bindPW != "" && password != p.bindPW {
		return errors.New("invalid credentials")
	}
	return nil
}

func (p *fakeProbe) Compare(_ context.Context, dn, attribute, value string) (bool, error) {
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

func (p *fakeProbe) Close() error { return nil }

func writeDM(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), testDMFile)
	if err := os.WriteFile(p, []byte(testDMPW+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// goodState is the cn=config snapshot matching testPolicy/testSuffix.
func goodState() map[string][]string {
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

func testPolicy() config.NormalizedPolicy {
	return config.NormalizedPolicy{
		MinLength:       9,
		HistoryCount:    3,
		MaxAge:          24 * time.Hour,
		LockoutEnabled:  true,
		MaxFailures:     4,
		LockoutDuration: 15 * time.Minute,
		StorageScheme:   "PBKDF2-SHA256",
	}
}

func engineWith(pr *fakeProbe) native.Engine {
	fd := &fakeDial{probes: map[string]*fakeProbe{"ldaps|dir:3636": pr}}
	return native.Engine{
		Address:   "dir:3636",
		Transport: directory.TransportLDAPS,
		Insecure:  true,
		ProbeDial: fd.dial,
	}
}

func phaseCode(t *testing.T, err error) (phase, code string) {
	t.Helper()
	var ae *apperr.Error
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v (%T), want apperr", err, err)
	}
	fs := ae.Fields()
	if len(fs) == 0 {
		t.Fatalf("no fields on %v", err)
	}
	return strings.TrimPrefix(fs[0].Path, "phase."), fs[0].Code
}

func TestBackendMatch(t *testing.T) {
	t.Parallel()
	eng := engineWith(&fakeProbe{state: goodState()})
	res, err := eng.Reconcile(t.Context(), bootstrap.BackendRequest{
		PasswordFile: writeDM(t),
		Name:         "userroot",
		Suffix:       "dc=example,dc=test",
		Write:        true,
	})
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.Action != "matched" || res.Suffix != "dc=example,dc=test" {
		t.Fatalf("result = %+v", res)
	}
}

func TestBackendSuffixMismatchFailsClosed(t *testing.T) {
	t.Parallel()
	eng := engineWith(&fakeProbe{state: goodState()})
	_, err := eng.Reconcile(t.Context(), bootstrap.BackendRequest{
		PasswordFile: writeDM(t),
		Suffix:       "dc=wrong,dc=test",
		Write:        true,
	})
	if err == nil {
		t.Fatal("mismatch must fail")
	}
	_, code := phaseCode(t, err)
	if code != "readback_mismatch" {
		t.Fatalf("code = %q from %v", code, err)
	}
	if strings.Contains(err.Error(), testDMPW) {
		t.Fatal("error leaked the DM password")
	}
}

func TestBackendDaemonDown(t *testing.T) {
	t.Parallel()
	fd := &fakeDial{dialErr: errors.New("connection refused")}
	eng := native.Engine{Address: "dir:3636", Transport: directory.TransportLDAPS, ProbeDial: fd.dial}
	_, err := eng.Reconcile(t.Context(), bootstrap.BackendRequest{
		PasswordFile: writeDM(t),
		Suffix:       "dc=example,dc=test",
	})
	_, code := phaseCode(t, err)
	if code != "unavailable" {
		t.Fatalf("code = %q from %v", code, err)
	}
}

func TestBackendBadDMPassword(t *testing.T) {
	t.Parallel()
	eng := engineWith(&fakeProbe{state: goodState(), bindPW: "different-pw"})
	_, err := eng.Reconcile(t.Context(), bootstrap.BackendRequest{
		PasswordFile: writeDM(t),
		Suffix:       "dc=example,dc=test",
	})
	_, code := phaseCode(t, err)
	if code != "bind_failed" {
		t.Fatalf("code = %q from %v", code, err)
	}
}

func TestPolicyMatchAndMismatch(t *testing.T) {
	t.Parallel()
	eng := engineWith(&fakeProbe{state: goodState()})
	res, err := eng.ReconcilePolicy(t.Context(), bootstrap.PolicyRequest{
		PasswordFile: writeDM(t),
		Policy:       testPolicy(),
	})
	if err != nil {
		t.Fatalf("ReconcilePolicy: %v", err)
	}
	if len(res.Applied) == 0 {
		t.Fatal("Applied empty")
	}

	// Every published field must be enforced: flip each one and expect a
	// readback_mismatch.
	flips := []struct {
		name string
		edit func(*config.NormalizedPolicy)
	}{
		{"scheme", func(p *config.NormalizedPolicy) { p.StorageScheme = "SSHA512" }},
		{"minLength", func(p *config.NormalizedPolicy) { p.MinLength = 12 }},
		{"history", func(p *config.NormalizedPolicy) { p.HistoryCount = 0 }},
		{"maxAge", func(p *config.NormalizedPolicy) { p.MaxAge = 0 }},
		{"lockoutEnabled", func(p *config.NormalizedPolicy) { p.LockoutEnabled = false }},
		{"maxFailures", func(p *config.NormalizedPolicy) { p.MaxFailures = 9 }},
		{"lockoutDuration", func(p *config.NormalizedPolicy) { p.LockoutDuration = time.Hour }},
	}
	for _, fl := range flips {
		p := testPolicy()
		fl.edit(&p)
		_, err := eng.ReconcilePolicy(t.Context(), bootstrap.PolicyRequest{
			PasswordFile: writeDM(t),
			Policy:       p,
		})
		if err == nil {
			t.Fatalf("%s: mismatch must fail", fl.name)
		}
		_, code := phaseCode(t, err)
		if code != "readback_mismatch" {
			t.Fatalf("%s: code = %q", fl.name, code)
		}
	}
}

func TestPluginsMatchMismatchUnknown(t *testing.T) {
	t.Parallel()
	eng := engineWith(&fakeProbe{state: goodState()})
	res, err := eng.ReconcilePlugins(t.Context(), bootstrap.PluginRequest{
		PasswordFile: writeDM(t),
		Plugins:      []string{"memberof", "referint", "account-disable"},
	})
	if err != nil {
		t.Fatalf("ReconcilePlugins: %v", err)
	}
	if len(res.Applied) != 3 {
		t.Fatalf("Applied = %v", res.Applied)
	}

	// Daemon lost a plugin -> fail closed.
	_, err = eng.ReconcilePlugins(t.Context(), bootstrap.PluginRequest{
		PasswordFile: writeDM(t),
		Plugins:      []string{"memberof", "referint", "account-disable", "retro-changelog"},
	})
	_, code := phaseCode(t, err)
	if code != "plugin_missing" {
		t.Fatalf("unknown plugin code = %q", code)
	}

	// Daemon missing a wanted plugin -> fail closed with plugin_missing.
	sparse := &fakeProbe{state: map[string][]string{"labldapPlugins": {"memberof"}}}
	eng = engineWith(sparse)
	_, err = eng.ReconcilePlugins(t.Context(), bootstrap.PluginRequest{
		PasswordFile: writeDM(t),
		Plugins:      []string{"memberof", "referint"},
	})
	_, code = phaseCode(t, err)
	if code != "plugin_missing" {
		t.Fatalf("missing plugin code = %q", code)
	}
}

func TestTLSProbes(t *testing.T) {
	t.Parallel()
	const ldapAddr = "dir:3389"
	const ldapsAddr = "dir:3636"

	// Secure posture: ldaps serves, plaintext refused.
	ldapsProbe := &fakeProbe{}
	ldapProbe := &fakeProbe{failBindOn: map[string]bool{"ldap|" + ldapAddr: true}}
	fd := &fakeDial{probes: map[string]*fakeProbe{
		"ldaps|" + ldapsAddr: ldapsProbe,
		"ldap|" + ldapAddr:   ldapProbe,
	}}
	eng := native.Engine{ProbeDial: fd.dial}
	res, err := eng.ReconcileTLS(t.Context(), bootstrap.TLSRequest{
		LDAPAddr:    ldapAddr,
		LDAPSAddr:   ldapsAddr,
		UseLDAPS:    true,
		Insecure:    true,
		Password:    observability.Secret(testDMPW),
		DialTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("ReconcileTLS: %v", err)
	}
	if len(res.Transports) != 1 || res.Transports[0] != "ldaps" {
		t.Fatalf("transports = %v", res.Transports)
	}

	// Cleartext accepted when the plan forbids it -> fail closed.
	ldapProbe.failBindOn = nil
	_, err = eng.ReconcileTLS(t.Context(), bootstrap.TLSRequest{
		LDAPAddr:    ldapAddr,
		LDAPSAddr:   ldapsAddr,
		UseLDAPS:    true,
		Insecure:    true,
		Password:    observability.Secret(testDMPW),
		DialTimeout: time.Second,
	})
	_, code := phaseCode(t, err)
	if code != "cleartext_enabled" {
		t.Fatalf("code = %q from %v", code, err)
	}

	// Plan allows cleartext: it must actually work.
	_, err = eng.ReconcileTLS(t.Context(), bootstrap.TLSRequest{
		LDAPAddr:       ldapAddr,
		AllowCleartext: true,
		Insecure:       true,
		Password:       observability.Secret(testDMPW),
		DialTimeout:    time.Second,
	})
	if err != nil {
		t.Fatalf("cleartext-allowed ReconcileTLS: %v", err)
	}

	// Required SASL can never be satisfied by the native engine.
	_, err = eng.ReconcileTLS(t.Context(), bootstrap.TLSRequest{
		LDAPAddr:       ldapAddr,
		AllowCleartext: true,
		Insecure:       true,
		Password:       observability.Secret(testDMPW),
		RequiredSASL:   []string{"GSSAPI"},
		DialTimeout:    time.Second,
	})
	_, code = phaseCode(t, err)
	if code != "sasl_missing" {
		t.Fatalf("sasl code = %q from %v", code, err)
	}
}

func TestNoPasswordInErrors(t *testing.T) {
	t.Parallel()
	// Wrong DM password at the server plus a mismatched plan: no error may
	// carry the secret.
	eng := engineWith(&fakeProbe{state: goodState(), bindPW: "server-pw"})
	_, err := eng.ReconcilePolicy(t.Context(), bootstrap.PolicyRequest{
		PasswordFile: writeDM(t),
		Policy:       testPolicy(),
	})
	if err == nil || strings.Contains(err.Error(), testDMPW) {
		t.Fatalf("err = %v", err)
	}
}
