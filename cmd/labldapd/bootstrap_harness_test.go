package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/native"
)

// This file is the T-144 acceptance harness: bootstrap.Run("apply") drives
// the REAL native engine-plane reconcilers (Backend/TLS/Policy/Plugins)
// against a REAL in-process labldapd, with the data plane faked (those
// reconcilers are the unchanged LDAP-as-DM implementations whose wiring is
// T-146). No dsconf exists anywhere in this path: native.Engine has no
// runner seam and internal/directory/native cannot import ds389 (import
// boundary test), so there is nothing to spy on — a dsconf invocation is
// unrepresentable.

// fakeDataPlane records phase invocations for the non-engine reconcilers.
type fakeDataPlane struct {
	markerWrites int
}

func (f *fakeDataPlane) Wait(context.Context, bootstrap.WaitRequest) (bootstrap.WaitResult, error) {
	return bootstrap.WaitResult{Transport: "ldap", NamingContexts: 1}, nil
}

func (f *fakeDataPlane) ReconcileTree(context.Context, bootstrap.TreeRequest) (bootstrap.TreeResult, error) {
	return bootstrap.TreeResult{Matched: []string{"suffix"}}, nil
}

func (f *fakeDataPlane) ReconcileACIs(_ context.Context, req bootstrap.ACIRequest) (bootstrap.ACIResult, error) {
	return bootstrap.ACIResult{Matched: []string{fmt.Sprint(len(req.ACIs))}}, nil
}

func (f *fakeDataPlane) ReconcileSeed(context.Context, bootstrap.SeedRequest) (bootstrap.SeedResult, error) {
	return bootstrap.SeedResult{}, nil
}

func (f *fakeDataPlane) VerifyRuntime(context.Context, bootstrap.VerifyRequest) (bootstrap.VerifyResult, error) {
	return bootstrap.VerifyResult{}, nil
}

func (f *fakeDataPlane) VerifyApp(context.Context, bootstrap.VerifyRequest) (bootstrap.VerifyResult, error) {
	return bootstrap.VerifyResult{}, nil
}

func (f *fakeDataPlane) Inspect(context.Context, bootstrap.DriftRequest) (bootstrap.DriftReport, error) {
	return bootstrap.DriftReport{}, nil
}

func (f *fakeDataPlane) ReadMarker(context.Context, bootstrap.MarkerRequest) (bootstrap.Marker, error) {
	return bootstrap.Marker{}, nil
}

func (f *fakeDataPlane) WriteMarker(context.Context, bootstrap.MarkerRequest) error {
	f.markerWrites++
	return nil
}

func (f *fakeDataPlane) Capabilities(context.Context, bootstrap.CapabilityRequest) (bootstrap.Capabilities, error) {
	return bootstrap.Capabilities{RequiredOK: true}, nil
}

// harnessScenario renders the lab scenario with the daemon's real bound
// port so bootstrap's request builders derive dialable coordinates.
func harnessScenario(suffix, runtimePWFile string, ldapPort int) string {
	return fmt.Sprintf(`apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata: { name: t144-harness }
spec:
  directory: { engine: native, suffix: %q }
  transport:
    insecureLabMode: true
    ldap: { enabled: true, port: %d }
    ldaps: { enabled: false, port: 3636 }
    startTLS: false
    allowCleartextBind: true
    allowAnonymousBind: false
  runtimeAccount: { id: rt, passwordFile: %s }
  passwordPolicy:
    minLength: 9
    historyCount: 3
    maxAge: 24h
    lockout: { enabled: true, maxFailures: 4, lockoutDuration: 15m }
    storageScheme: PBKDF2-SHA256
`, suffix, ldapPort, runtimePWFile)
}

type harness struct {
	daemon   *daemon
	ldapAddr string
	dir      string
	dmFile   string
	rtFile   string
	plane    *fakeDataPlane
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().(*net.TCPAddr).Port
}

// startHarness boots labldapd on a free plaintext port with a scenario that
// names that port, ready for bootstrap.Run.
func startHarness(t *testing.T, suffix string) *harness {
	t.Helper()
	dir := t.TempDir()
	port := freePort(t)
	h := &harness{
		ldapAddr: fmt.Sprintf("127.0.0.1:%d", port),
		dir:      dir,
		dmFile:   writeFile(t, dir, "dm.secret", dmCanary),
		rtFile:   writeFile(t, dir, "runtime.secret", "rt-pw"),
		plane:    &fakeDataPlane{},
	}
	cfg := writeFile(t, dir, "lab.yaml", harnessScenario(suffix, h.rtFile, port))
	d, err := startDaemon(context.Background(), serveFlags{
		configPath:     cfg,
		dataDir:        filepath.Join(dir, "data"),
		listen:         h.ldapAddr,
		ldapsListen:    "",
		dmPasswordFile: h.dmFile,
		healthListen:   "",
	}, testLogger(&bytes.Buffer{}))
	if err != nil {
		t.Fatalf("startDaemon: %v", err)
	}
	h.daemon = d
	return h
}

func (h *harness) stop(t *testing.T) {
	t.Helper()
	stopDaemon(t, h.daemon)
}

// runApply executes bootstrap.Run apply with the real native reconcilers.
// The scenario is recompiled by bootstrap from the same file the daemon
// used unless overrideSuffix asks for a mismatched plan.
func (h *harness) runApply(t *testing.T, scenarioPath string, logs *bytes.Buffer) (bootstrap.Summary, error) {
	t.Helper()
	eng := native.Engine{
		Address:   h.ldapAddr,
		Transport: directory.TransportLDAP,
		Insecure:  true,
	}
	return bootstrap.Run(context.Background(), bootstrap.Options{
		Command:       "apply",
		ConfigPath:    scenarioPath,
		PasswordFile:  h.dmFile,
		Waiter:        h.plane,
		Backend:       eng,
		TLS:           eng,
		Policy:        eng,
		Plugins:       eng,
		Tree:          h.plane,
		ACIs:          h.plane,
		Seed:          h.plane,
		VerifyRuntime: h.plane,
		VerifyApp:     h.plane,
		Drift:         h.plane,
		Marker:        h.plane,
		Capabilities:  h.plane,
		Log:           slog.New(slog.NewTextHandler(logs, nil)),
	}, &bytes.Buffer{}, &bytes.Buffer{})
}

func (h *harness) scenarioFile(t *testing.T, suffix string) string {
	t.Helper()
	port := 0
	fmt.Sscanf(h.ldapAddr, "127.0.0.1:%d", &port)
	return writeFile(t, h.dir, "plan-"+strings.ReplaceAll(suffix, ",", "_")+".yaml",
		harnessScenario(suffix, h.rtFile, port))
}

func TestBootstrapApplyAgainstLabldapd(t *testing.T) {
	t.Parallel()
	h := startHarness(t, "dc=example,dc=test")
	defer h.stop(t)

	var logs bytes.Buffer
	sum, err := h.runApply(t, h.scenarioFile(t, "dc=example,dc=test"), &logs)
	if err != nil {
		t.Fatalf("bootstrap apply: %v", err)
	}
	if !sum.OK {
		t.Fatalf("summary not OK: %+v", sum)
	}
	if h.plane.markerWrites != 1 {
		t.Fatalf("marker writes = %d, want 1", h.plane.markerWrites)
	}
	if strings.Contains(logs.String(), dmCanary) {
		t.Fatalf("bootstrap logs leaked the DM password:\n%s", logs.String())
	}
}

func TestBootstrapApplySuffixMismatchFailsClosed(t *testing.T) {
	t.Parallel()
	h := startHarness(t, "dc=example,dc=test")
	defer h.stop(t)

	var logs bytes.Buffer
	sum, err := h.runApply(t, h.scenarioFile(t, "dc=wrong,dc=test"), &logs)
	if err == nil {
		t.Fatal("mismatched suffix must fail")
	}
	var ae *apperr.Error
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v (%T)", err, err)
	}
	fs := ae.Fields()
	if len(fs) == 0 || fs[0].Path != "phase.backend" || fs[0].Code != "readback_mismatch" {
		t.Fatalf("fields = %#v", fs)
	}
	if h.plane.markerWrites != 0 {
		t.Fatal("marker committed despite failed engine read-back")
	}
	if sum.OK {
		t.Fatal("summary OK despite failure")
	}
}

func TestBootstrapApplyPolicyMismatchFailsClosed(t *testing.T) {
	t.Parallel()
	h := startHarness(t, "dc=example,dc=test")
	defer h.stop(t)

	// Same suffix, but a policy the daemon did not apply.
	port := 0
	fmt.Sscanf(h.ldapAddr, "127.0.0.1:%d", &port)
	scenario := harnessScenario("dc=example,dc=test", h.rtFile, port)
	scenario = strings.Replace(scenario, "minLength: 9", "minLength: 21", 1)
	mismatched := writeFile(t, h.dir, "plan-policy.yaml", scenario)

	var logs bytes.Buffer
	_, err := h.runApply(t, mismatched, &logs)
	if err == nil {
		t.Fatal("mismatched policy must fail")
	}
	var ae *apperr.Error
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v (%T)", err, err)
	}
	fs := ae.Fields()
	if len(fs) == 0 || fs[0].Path != "phase.pwpolicy" || fs[0].Code != "readback_mismatch" {
		t.Fatalf("fields = %#v", fs)
	}
	if h.plane.markerWrites != 0 {
		t.Fatal("marker committed despite failed policy read-back")
	}
}
