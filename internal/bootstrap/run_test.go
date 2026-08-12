package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

type fakeTLS struct {
	err    error
	called int
	req    TLSRequest
}

func (f *fakeTLS) ReconcileTLS(ctx context.Context, req TLSRequest) (TLSResult, error) {
	_ = ctx
	f.called++
	f.req = req
	if f.err != nil {
		return TLSResult{}, f.err
	}
	return TLSResult{Transports: []string{"ldaps"}, SASL: []string{"EXTERNAL"}}, nil
}

type fakeBackend struct {
	err    error
	res    BackendResult
	called int
	req    BackendRequest
}

func (f *fakeBackend) Reconcile(ctx context.Context, req BackendRequest) (BackendResult, error) {
	_ = ctx
	f.called++
	f.req = req
	if f.err != nil {
		return BackendResult{}, f.err
	}
	if f.res.Action == "" {
		f.res = BackendResult{Action: "created", Name: "userroot", Suffix: "dc=example,dc=test"}
	}
	return f.res, nil
}

type fakeWaiter struct {
	err    error
	res    WaitResult
	called int
	req    WaitRequest
}

func (f *fakeWaiter) Wait(ctx context.Context, req WaitRequest) (WaitResult, error) {
	_ = ctx
	f.called++
	f.req = req
	if f.err != nil {
		return WaitResult{}, f.err
	}
	if f.res.Transport == "" {
		f.res.Transport = "ldaps"
		f.res.NamingContexts = 1
	}
	return f.res, nil
}

func testConfigDir(t *testing.T) (cfgPath, pwPath string) {
	t.Helper()
	dir := t.TempDir()
	sec := filepath.Join(dir, "secrets")
	if err := os.Mkdir(sec, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sec, "runtime-ldap"), []byte("runtime-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath = filepath.Join(dir, "lab.yaml")
	src := `apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata: { name: t }
spec:
  directory: { suffix: "dc=example,dc=test" }
  transport: { ldaps: { enabled: true, port: 3636 } }
  runtimeAccount: { id: rt, passwordFile: secrets/runtime-ldap }
`
	if err := os.WriteFile(cfgPath, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	pwPath = filepath.Join(dir, "dm.pw")
	if err := os.WriteFile(pwPath, []byte("dm-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, pwPath
}

func TestPlanOffline(t *testing.T) {
	cfg, _ := testConfigDir(t)
	var stdout, stderr bytes.Buffer
	sum, err := Run(t.Context(), Options{Command: "plan", ConfigPath: cfg}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if !sum.OK || len(sum.Phases) != 1 || sum.Phases[0].Phase != "load" {
		t.Fatalf("%+v", sum)
	}
	if sum.DirectoryRevision == "" || len(sum.Plan) == 0 {
		t.Fatal("missing plan/revision")
	}
	if bytes.Contains(sum.Plan, []byte("runtime-secret")) || bytes.Contains(sum.Plan, []byte("dm-secret")) {
		t.Fatal("plan leaked secret")
	}
}

func TestApplyLoadThenWaitOK(t *testing.T) {
	cfg, pw := testConfigDir(t)
	fw := &fakeWaiter{}
	fb := &fakeBackend{}
	ft := &fakeTLS{}
	sum, err := Run(t.Context(), Options{
		Command:      "apply",
		ConfigPath:   cfg,
		PasswordFile: pw,
		Waiter:       fw,
		Backend:      fb,
		TLS:          ft,
		LDAPURL:      "ldaps://127.0.0.1:3636",
		CAFile:       "/tmp/ca.crt",
	}, ioDiscard(), ioDiscard())
	if err != nil {
		t.Fatal(err)
	}
	if !sum.OK || fw.called != 1 || fb.called != 1 || ft.called != 1 {
		t.Fatalf("sum=%+v wait=%d backend=%d tls=%d", sum, fw.called, fb.called, ft.called)
	}
	if !fb.req.Write {
		t.Fatal("apply merge must write backend")
	}
	if fw.req.Password.Reveal() != "dm-secret" {
		t.Fatal("password not loaded from file")
	}
	if fw.req.LDAPURL != "ldaps://127.0.0.1:3636" {
		t.Fatalf("url = %s", fw.req.LDAPURL)
	}
	if len(sum.Phases) != 4 || sum.Phases[3].Phase != "tls" || !sum.Phases[3].OK {
		t.Fatalf("phases = %+v", sum.Phases)
	}
	if len(sum.Remaining) == 0 {
		t.Fatal("expected remaining phases")
	}
}

func TestApplyWaitBindFailure(t *testing.T) {
	cfg, pw := testConfigDir(t)
	fw := &fakeWaiter{err: PhaseError("wait", "bind", "Directory Manager bind failed")}
	sum, err := Run(t.Context(), Options{
		Command: "apply", ConfigPath: cfg, PasswordFile: pw, Waiter: fw, Backend: &fakeBackend{}, TLS: &fakeTLS{},
	}, ioDiscard(), ioDiscard())
	if err == nil {
		t.Fatal("expected bind failure")
	}
	if sum.OK {
		t.Fatal("summary should not be ok")
	}
	apperr.Assert(t, err).Code(apperr.CodeBootstrap).FieldPath("phase.wait")
	if sum.Phases[len(sum.Phases)-1].Code != "bind" {
		t.Fatalf("phase code = %+v", sum.Phases)
	}
}

func TestApplyValidateModeDoesNotWrite(t *testing.T) {
	dir := t.TempDir()
	sec := filepath.Join(dir, "secrets")
	if err := os.Mkdir(sec, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sec, "runtime-ldap"), []byte("runtime-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "lab.yaml")
	src := `apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata: { name: t }
spec:
  directory: { suffix: "dc=example,dc=test" }
  lifecycle: { startupMode: validate }
  transport: { ldaps: { enabled: true, port: 3636 } }
  runtimeAccount: { id: rt, passwordFile: secrets/runtime-ldap }
`
	if err := os.WriteFile(cfg, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	pw := filepath.Join(dir, "dm.pw")
	if err := os.WriteFile(pw, []byte("dm-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fb := &fakeBackend{}
	ft := &fakeTLS{}
	_, err := Run(t.Context(), Options{
		Command: "apply", ConfigPath: cfg, PasswordFile: pw, Waiter: &fakeWaiter{}, Backend: fb, TLS: ft,
	}, ioDiscard(), ioDiscard())
	if err != nil {
		t.Fatal(err)
	}
	if fb.req.Write || ft.req.Write {
		t.Fatal("startupMode validate must not write")
	}
}

func TestValidateSubcommandDoesNotWrite(t *testing.T) {
	cfg, pw := testConfigDir(t)
	fb := &fakeBackend{res: BackendResult{Action: "matched", Name: "userroot", Suffix: "dc=example,dc=test"}}
	ft := &fakeTLS{}
	sum, err := Run(t.Context(), Options{
		Command: "validate", ConfigPath: cfg, PasswordFile: pw, Waiter: &fakeWaiter{}, Backend: fb, TLS: ft,
	}, ioDiscard(), ioDiscard())
	if err != nil {
		t.Fatal(err)
	}
	if fb.req.Write || ft.req.Write {
		t.Fatal("validate subcommand must not write")
	}
	if !sum.OK || sum.Phases[len(sum.Phases)-1].Phase != "tls" {
		t.Fatalf("%+v", sum)
	}
}

func TestApplyInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("apiVersion: nope\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pw := filepath.Join(dir, "dm.pw")
	if err := os.WriteFile(pw, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum, err := Run(t.Context(), Options{
		Command: "apply", ConfigPath: path, PasswordFile: pw, Waiter: &fakeWaiter{}, Backend: &fakeBackend{}, TLS: &fakeTLS{},
	}, ioDiscard(), ioDiscard())
	if err == nil {
		t.Fatal("expected load failure")
	}
	if sum.OK || sum.Phases[0].OK {
		t.Fatalf("%+v", sum)
	}
}

func TestWriteSummaryStableAndRedacted(t *testing.T) {
	cfg, pw := testConfigDir(t)
	var a, b bytes.Buffer
	opt := Options{Command: "plan", ConfigPath: cfg, PasswordFile: pw}
	s1, err := Run(t.Context(), opt, ioDiscard(), ioDiscard())
	if err != nil {
		t.Fatal(err)
	}
	s2, err := Run(t.Context(), opt, ioDiscard(), ioDiscard())
	if err != nil {
		t.Fatal(err)
	}
	WriteSummary(&a, ioDiscard(), s1, nil)
	WriteSummary(&b, ioDiscard(), s2, nil)
	if !bytes.Contains(a.Bytes(), []byte(`"ok": true`)) {
		t.Fatalf("stdout = %s", a.String())
	}
	if bytes.Contains(a.Bytes(), []byte("runtime-secret")) {
		t.Fatal("summary leaked")
	}
	var j1, j2 map[string]any
	if err := json.Unmarshal(a.Bytes(), &j1); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b.Bytes(), &j2); err != nil {
		t.Fatal(err)
	}
	if j1["directoryRevision"] != j2["directoryRevision"] {
		t.Fatal("revision not stable")
	}
}

func TestSummaryDoesNotFormatSecret(t *testing.T) {
	s := observability.Secret("super-secret")
	if strings.Contains(s.String(), "super-secret") {
		t.Fatal("secret string leaked")
	}
}

func ioDiscard() *bytes.Buffer { return &bytes.Buffer{} }
