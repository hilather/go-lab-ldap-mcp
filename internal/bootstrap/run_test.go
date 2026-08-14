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

type fakePolicy struct {
	err    error
	called int
	req    PolicyRequest
}

func (f *fakePolicy) ReconcilePolicy(ctx context.Context, req PolicyRequest) (PolicyResult, error) {
	_ = ctx
	f.called++
	f.req = req
	if f.err != nil {
		return PolicyResult{}, f.err
	}
	return PolicyResult{Applied: []string{"storageScheme"}}, nil
}

type fakePlugins struct {
	err    error
	called int
	req    PluginRequest
}

func (f *fakePlugins) ReconcilePlugins(ctx context.Context, req PluginRequest) (PluginResult, error) {
	_ = ctx
	f.called++
	f.req = req
	if f.err != nil {
		return PluginResult{}, f.err
	}
	return PluginResult{Applied: []string{"memberof", "referint", "account-disable"}}, nil
}

type fakeTree struct {
	err    error
	called int
	req    TreeRequest
}

func (f *fakeTree) ReconcileTree(ctx context.Context, req TreeRequest) (TreeResult, error) {
	_ = ctx
	f.called++
	f.req = req
	if f.err != nil {
		return TreeResult{}, f.err
	}
	return TreeResult{Created: []string{req.PeopleDN}}, nil
}

type fakeACIs struct {
	err    error
	called int
	req    ACIRequest
}

func (f *fakeACIs) ReconcileACIs(ctx context.Context, req ACIRequest) (ACIResult, error) {
	_ = ctx
	f.called++
	f.req = req
	if f.err != nil {
		return ACIResult{}, f.err
	}
	return ACIResult{Applied: []string{"labldap:runtime-suffix-read"}}, nil
}

type fakeSeed struct {
	err    error
	called int
	req    SeedRequest
}

func (f *fakeSeed) ReconcileSeed(ctx context.Context, req SeedRequest) (SeedResult, error) {
	_ = ctx
	f.called++
	f.req = req
	if f.err != nil {
		return SeedResult{}, f.err
	}
	return SeedResult{Created: []string{"uid=alice,ou=people,dc=example,dc=test"}}, nil
}

type fakeRuntimeVerifier struct {
	err    error
	called int
	req    VerifyRequest
}

func (f *fakeRuntimeVerifier) VerifyRuntime(ctx context.Context, req VerifyRequest) (VerifyResult, error) {
	_ = ctx
	f.called++
	f.req = req
	if f.err != nil {
		return VerifyResult{}, f.err
	}
	return VerifyResult{Allowed: 4, Denied: 4, Skipped: 1}, nil
}

type fakeDrift struct {
	err    error
	called int
	req    DriftRequest
	report DriftReport
}

func (f *fakeDrift) Inspect(ctx context.Context, req DriftRequest) (DriftReport, error) {
	_ = ctx
	f.called++
	f.req = req
	if f.err != nil {
		return DriftReport{}, f.err
	}
	return f.report, nil
}

type fakeMarker struct {
	err    error
	called int
	req    MarkerRequest
	last   Marker
}

func (f *fakeMarker) ReadMarker(ctx context.Context, req MarkerRequest) (Marker, error) {
	_ = ctx
	return f.last, nil
}

func (f *fakeMarker) WriteMarker(ctx context.Context, req MarkerRequest) error {
	_ = ctx
	f.called++
	f.req = req
	if f.err != nil {
		return f.err
	}
	f.last = Marker{
		DN:               req.DN,
		AppliedRevision:  req.AppliedRevision,
		ExpectedRevision: req.ExpectedRevision,
		ApplyVersion:     req.ApplyVersion,
		AppliedAt:        req.AppliedAt,
	}
	return nil
}

type fakeCaps struct {
	err    error
	called int
	ok     bool
	req    CapabilityRequest
}

func (f *fakeCaps) Capabilities(ctx context.Context, req CapabilityRequest) (Capabilities, error) {
	_ = ctx
	f.called++
	f.req = req
	if f.err != nil {
		return Capabilities{}, f.err
	}
	return Capabilities{
		EngineVendor:   "389 Project",
		EngineVersion:  "389-Directory/test",
		AdapterVersion: "dev",
		Transports:     []string{"ldaps"},
		Plugins:        []string{"memberof", "referint", "account-disable"},
		PasswordScheme: "PBKDF2-SHA256",
		RequiredOK:     f.ok,
	}, nil
}

type fakeAppVerifier struct {
	err    error
	called int
	req    VerifyRequest
}

func (f *fakeAppVerifier) VerifyApp(ctx context.Context, req VerifyRequest) (VerifyResult, error) {
	_ = ctx
	f.called++
	f.req = req
	if f.err != nil {
		return VerifyResult{}, f.err
	}
	return VerifyResult{Binds: 1, Groups: 1, SkippedLockout: 1}, nil
}

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
	if err := os.WriteFile(filepath.Join(sec, "user-alice"), []byte("alice-seed-secret\n"), 0o600); err != nil {
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
  users:
    - id: alice
      uid: alice
      passwordFile: secrets/user-alice
  groups:
    - id: staff
      members: [{ user: alice }]
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

func applyOpts(cfg, pw string) (Options, *fakeSeed, *fakeRuntimeVerifier, *fakeAppVerifier, *fakeDrift, *fakeMarker, *fakeCaps) {
	fs := &fakeSeed{}
	fv := &fakeRuntimeVerifier{}
	fap := &fakeAppVerifier{}
	fd := &fakeDrift{}
	fm := &fakeMarker{}
	fc := &fakeCaps{ok: true}
	return Options{
		Command:       "apply",
		ConfigPath:    cfg,
		PasswordFile:  pw,
		Waiter:        &fakeWaiter{},
		Backend:       &fakeBackend{},
		TLS:           &fakeTLS{},
		Policy:        &fakePolicy{},
		Plugins:       &fakePlugins{},
		Tree:          &fakeTree{},
		ACIs:          &fakeACIs{},
		Seed:          fs,
		VerifyRuntime: fv,
		VerifyApp:     fap,
		Drift:         fd,
		Marker:        fm,
		Capabilities:  fc,
	}, fs, fv, fap, fd, fm, fc
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
	if bytes.Contains(sum.Plan, []byte("runtime-secret")) || bytes.Contains(sum.Plan, []byte("dm-secret")) || bytes.Contains(sum.Plan, []byte("alice-seed-secret")) {
		t.Fatal("plan leaked secret")
	}
}

func TestApplyLoadThenWaitOK(t *testing.T) {
	cfg, pw := testConfigDir(t)
	opt, fs, fv, fap, fd, fm, fc := applyOpts(cfg, pw)
	fw := opt.Waiter.(*fakeWaiter)
	fb := opt.Backend.(*fakeBackend)
	ft := opt.TLS.(*fakeTLS)
	fp := opt.Policy.(*fakePolicy)
	fg := opt.Plugins.(*fakePlugins)
	fr := opt.Tree.(*fakeTree)
	fa := opt.ACIs.(*fakeACIs)
	opt.LDAPURL = "ldaps://127.0.0.1:3636"
	opt.CAFile = "/tmp/ca.crt"
	sum, err := Run(t.Context(), opt, ioDiscard(), ioDiscard())
	if err != nil {
		t.Fatal(err)
	}
	if !sum.OK || fw.called != 1 || fb.called != 1 || ft.called != 1 || fp.called != 1 || fg.called != 1 || fr.called != 1 || fa.called != 1 || fs.called != 1 || fv.called != 1 || fap.called != 1 || fd.called != 1 || fm.called != 1 || fc.called != 1 {
		t.Fatalf("sum=%+v wait=%d backend=%d tls=%d policy=%d plugins=%d tree=%d aci=%d seed=%d verify_runtime=%d verify_app=%d drift=%d marker=%d caps=%d", sum, fw.called, fb.called, ft.called, fp.called, fg.called, fr.called, fa.called, fs.called, fv.called, fap.called, fd.called, fm.called, fc.called)
	}
	if !fb.req.Write {
		t.Fatal("apply merge must write backend")
	}
	if !fp.req.Write {
		t.Fatal("apply merge must write policy")
	}
	if !fg.req.Write {
		t.Fatal("apply merge must write plugins")
	}
	if !fr.req.Write {
		t.Fatal("apply merge must write tree")
	}
	if !fa.req.Write {
		t.Fatal("apply merge must write ACIs")
	}
	if !fs.req.Write {
		t.Fatal("apply merge must write seed")
	}
	if len(fs.req.Users) != 1 || fs.req.Users[0].ID != "alice" {
		t.Fatalf("seed users = %+v", fs.req.Users)
	}
	if len(fs.req.Groups) != 1 || fs.req.Groups[0].ID != "staff" {
		t.Fatalf("seed groups = %+v", fs.req.Groups)
	}
	if fs.req.Users[0].Password != nil && fs.req.Users[0].Password.Value.Reveal() == "" {
		t.Fatal("seed user password empty")
	}
	if fw.req.Password.Reveal() != "dm-secret" {
		t.Fatal("password not loaded from file")
	}
	if fw.req.LDAPURL != "ldaps://127.0.0.1:3636" {
		t.Fatalf("url = %s", fw.req.LDAPURL)
	}
	if len(sum.Phases) != 13 || sum.Phases[9].Phase != "verify_runtime" || sum.Phases[10].Phase != "verify_app" || sum.Phases[11].Phase != "drift" || sum.Phases[12].Phase != "marker" || !sum.Phases[12].OK {
		t.Fatalf("phases = %+v", sum.Phases)
	}
	if len(sum.Remaining) != 0 {
		t.Fatalf("remaining = %v, want empty", sum.Remaining)
	}
	if fd.req.CompareMarker {
		t.Fatal("apply drift must not treat the pre-write marker as leftover")
	}
	if fm.req.DN == "" || !strings.HasPrefix(fm.req.ApplyVersion, "labldap-bootstrap/") {
		t.Fatalf("marker req = %+v", fm.req)
	}
	if strings.Contains(fm.req.AppliedRevision, "alice-seed-secret") || strings.Contains(fm.req.ApplyVersion, "alice-seed-secret") {
		t.Fatal("marker contained a secret")
	}
	if len(sum.Capabilities) == 0 || bytes.Contains(sum.Capabilities, []byte("alice-seed-secret")) {
		t.Fatalf("capabilities = %s", sum.Capabilities)
	}
}

func TestTlsRequestUsesCompiledLDAPSPort(t *testing.T) {
	cfg, pw := testConfigDir(t)
	opt, _, _, _, _, _, _ := applyOpts(cfg, pw)
	ft := &fakeTLS{}
	opt.TLS = ft
	_, err := Run(t.Context(), opt, ioDiscard(), ioDiscard())
	if err != nil {
		t.Fatal(err)
	}
	if ft.req.LDAPURL != "" {
		t.Fatalf("expected empty LDAPURL, got %q", ft.req.LDAPURL)
	}
	if !strings.HasSuffix(ft.req.LDAPAddr, ":3389") {
		t.Fatalf("LDAPAddr = %q, want :3389", ft.req.LDAPAddr)
	}
	if !strings.HasSuffix(ft.req.LDAPSAddr, ":3636") {
		t.Fatalf("LDAPSAddr = %q, want compiled LDAPS :3636, not LDAP port", ft.req.LDAPSAddr)
	}
}

func TestApplyWaitBindFailure(t *testing.T) {
	cfg, pw := testConfigDir(t)
	fw := &fakeWaiter{err: PhaseError("wait", "bind", "Directory Manager bind failed")}
	sum, err := Run(t.Context(), Options{
		Command: "apply", ConfigPath: cfg, PasswordFile: pw, Waiter: fw, Backend: &fakeBackend{}, TLS: &fakeTLS{}, Policy: &fakePolicy{}, Plugins: &fakePlugins{}, Tree: &fakeTree{}, ACIs: &fakeACIs{}, Seed: &fakeSeed{},
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
	opt, fs, fv, fap, fd, fm, fc := applyOpts(cfg, pw)
	fb := opt.Backend.(*fakeBackend)
	ft := opt.TLS.(*fakeTLS)
	fp := opt.Policy.(*fakePolicy)
	fg := opt.Plugins.(*fakePlugins)
	fr := opt.Tree.(*fakeTree)
	fa := opt.ACIs.(*fakeACIs)
	sum, err := Run(t.Context(), opt, ioDiscard(), ioDiscard())
	if err != nil {
		t.Fatal(err)
	}
	if fb.req.Write || ft.req.Write || fp.req.Write || fg.req.Write || fr.req.Write || fa.req.Write || fs.req.Write {
		t.Fatal("startupMode validate must not write")
	}
	if fv.called != 0 || fap.called != 0 || fm.called != 0 {
		t.Fatal("validate must not run write-probe verifiers or write the marker")
	}
	if fd.called != 1 || fc.called != 1 {
		t.Fatalf("validate inspect/drift calls: drift=%d caps=%d", fd.called, fc.called)
	}
	if !fd.req.CompareMarker {
		t.Fatal("validate drift must compare the marker revision")
	}
	if len(sum.Remaining) != 0 {
		t.Fatalf("remaining = %v", sum.Remaining)
	}
	if sum.Phases[len(sum.Phases)-1].Phase != "drift" {
		t.Fatalf("last phase = %+v", sum.Phases)
	}
}

func TestValidateSubcommandDoesNotWrite(t *testing.T) {
	cfg, pw := testConfigDir(t)
	opt, fs, fv, fap, fd, fm, _ := applyOpts(cfg, pw)
	opt.Command = "validate"
	fb := &fakeBackend{res: BackendResult{Action: "matched", Name: "userroot", Suffix: "dc=example,dc=test"}}
	opt.Backend = fb
	ft := opt.TLS.(*fakeTLS)
	fp := opt.Policy.(*fakePolicy)
	fg := opt.Plugins.(*fakePlugins)
	fr := opt.Tree.(*fakeTree)
	fa := opt.ACIs.(*fakeACIs)
	sum, err := Run(t.Context(), opt, ioDiscard(), ioDiscard())
	if err != nil {
		t.Fatal(err)
	}
	if fb.req.Write || ft.req.Write || fp.req.Write || fg.req.Write || fr.req.Write || fa.req.Write || fs.req.Write {
		t.Fatal("validate subcommand must not write")
	}
	if fv.called != 0 || fap.called != 0 || fm.called != 0 {
		t.Fatal("validate must not run write-probe verifiers or write the marker")
	}
	if !sum.OK || sum.Phases[len(sum.Phases)-1].Phase != "drift" {
		t.Fatalf("%+v", sum)
	}
	if len(sum.Remaining) != 0 {
		t.Fatalf("remaining = %v", sum.Remaining)
	}
	if !fd.req.CompareMarker {
		t.Fatal("validate subcommand must ignore YAML merge for drift exit codes")
	}
}

func TestApplySeedPasswordFailure(t *testing.T) {
	cfg, pw := testConfigDir(t)
	opt, _, _, _, _, fm, _ := applyOpts(cfg, pw)
	opt.Seed = &fakeSeed{err: PhaseError("seed", "password_set", "could not set seed user password")}
	sum, err := Run(t.Context(), opt, ioDiscard(), ioDiscard())
	if err == nil {
		t.Fatal("expected seed failure")
	}
	if sum.OK {
		t.Fatal("summary should not be ok")
	}
	apperr.Assert(t, err).Code(apperr.CodeBootstrap).FieldPath("phase.seed")
	if sum.Phases[len(sum.Phases)-1].Code != "password_set" {
		t.Fatalf("phase code = %+v", sum.Phases)
	}
	if strings.Contains(err.Error(), "alice-seed-secret") {
		t.Fatal("seed error leaked password")
	}
	if fm.called != 0 {
		t.Fatal("partial seed must not write marker")
	}
}

func TestApplyVerifyRuntimeFailure(t *testing.T) {
	cfg, pw := testConfigDir(t)
	opt, _, _, _, _, fm, _ := applyOpts(cfg, pw)
	opt.VerifyRuntime = &fakeRuntimeVerifier{err: PhaseError("verify_runtime", "deny_failed", "runtime modified cn=config")}
	sum, err := Run(t.Context(), opt, ioDiscard(), ioDiscard())
	if err == nil {
		t.Fatal("expected verify_runtime failure")
	}
	if sum.OK {
		t.Fatal("summary should not be ok")
	}
	apperr.Assert(t, err).Code(apperr.CodeBootstrap).FieldPath("phase.verify_runtime")
	if sum.Phases[len(sum.Phases)-1].Code != "deny_failed" {
		t.Fatalf("phase code = %+v", sum.Phases)
	}
	if strings.Contains(err.Error(), "alice-seed-secret") || strings.Contains(err.Error(), "runtime-secret") {
		t.Fatal("verify error leaked password")
	}
	if fm.called != 0 {
		t.Fatal("verify failure must not write marker")
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
		Command: "apply", ConfigPath: path, PasswordFile: pw, Waiter: &fakeWaiter{}, Backend: &fakeBackend{}, TLS: &fakeTLS{}, Policy: &fakePolicy{}, Plugins: &fakePlugins{}, Tree: &fakeTree{}, ACIs: &fakeACIs{}, Seed: &fakeSeed{},
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
	if bytes.Contains(a.Bytes(), []byte("runtime-secret")) || bytes.Contains(a.Bytes(), []byte("alice-seed-secret")) {
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

func TestValidateDriftFails(t *testing.T) {
	cfg, pw := testConfigDir(t)
	opt, _, _, _, fd, fm, _ := applyOpts(cfg, pw)
	opt.Command = "validate"
	fd.report = DriftReport{Differ: true, ExtraUsers: []string{"uid=extra,ou=people,dc=example,dc=test"}}
	sum, err := Run(t.Context(), opt, ioDiscard(), ioDiscard())
	if err == nil {
		t.Fatal("expected drift failure")
	}
	if sum.OK {
		t.Fatal("validate drift must not report success")
	}
	apperr.Assert(t, err).Code(apperr.CodeBootstrap).FieldPath("phase.drift")
	if sum.Phases[len(sum.Phases)-1].Code != "drift" {
		t.Fatalf("phase code = %+v", sum.Phases)
	}
	if fm.called != 0 {
		t.Fatal("validate must not write marker")
	}
	if !bytes.Contains(sum.Drift, []byte("uid=extra")) {
		t.Fatalf("drift report missing extra: %s", sum.Drift)
	}
}

func TestApplyLeftoverDriftDoesNotFail(t *testing.T) {
	cfg, pw := testConfigDir(t)
	opt, _, _, _, fd, fm, _ := applyOpts(cfg, pw)
	fd.report = DriftReport{Differ: true, ExtraUsers: []string{"uid=runtime-extra,ou=people,dc=example,dc=test"}}
	sum, err := Run(t.Context(), opt, ioDiscard(), ioDiscard())
	if err != nil {
		t.Fatal(err)
	}
	if !sum.OK || fm.called != 1 {
		t.Fatalf("merge leftover must still write marker: ok=%v marker=%d", sum.OK, fm.called)
	}
	if !bytes.Contains(sum.Drift, []byte("runtime-extra")) {
		t.Fatalf("leftover report missing extra: %s", sum.Drift)
	}
}

func TestApplyCapabilityFailureDoesNotWriteMarker(t *testing.T) {
	cfg, pw := testConfigDir(t)
	opt, _, _, _, _, fm, fc := applyOpts(cfg, pw)
	fc.ok = false
	sum, err := Run(t.Context(), opt, ioDiscard(), ioDiscard())
	if err == nil {
		t.Fatal("expected capability failure")
	}
	if sum.OK {
		t.Fatal("bootstrap must not report success after verification failure")
	}
	apperr.Assert(t, err).Code(apperr.CodeBootstrap).FieldPath("phase.verify_app")
	if sum.Phases[len(sum.Phases)-1].Code != "capability" {
		t.Fatalf("phase code = %+v", sum.Phases)
	}
	if fm.called != 0 {
		t.Fatal("capability failure must leave prior marker")
	}
}

func TestApplyMarkerWriteFailure(t *testing.T) {
	cfg, pw := testConfigDir(t)
	opt, _, _, _, _, fm, _ := applyOpts(cfg, pw)
	fm.err = PhaseError("marker", "apply_failed", "injected marker write failure")
	sum, err := Run(t.Context(), opt, ioDiscard(), ioDiscard())
	if err == nil {
		t.Fatal("expected marker failure")
	}
	if sum.OK {
		t.Fatal("marker failure must not report success")
	}
	apperr.Assert(t, err).Code(apperr.CodeBootstrap).FieldPath("phase.marker")
	if fm.last.AppliedRevision != "" {
		t.Fatal("failed write must not commit a new marker")
	}
}

func TestApplyPhaseFailureInjection(t *testing.T) {
	cfg, pw := testConfigDir(t)
	cases := []struct {
		phase, code string
		patch       func(*Options)
	}{
		{"backend", "create_failed", func(o *Options) {
			o.Backend = &fakeBackend{err: PhaseError("backend", "create_failed", "injected backend fail")}
		}},
		{"tls", "tls", func(o *Options) {
			o.TLS = &fakeTLS{err: PhaseError("tls", "tls", "injected tls fail")}
		}},
		{"pwpolicy", "readback_mismatch", func(o *Options) {
			o.Policy = &fakePolicy{err: PhaseError("pwpolicy", "readback_mismatch", "injected policy fail")}
		}},
		{"plugins", "plugin_missing", func(o *Options) {
			o.Plugins = &fakePlugins{err: PhaseError("plugins", "plugin_missing", "injected plugin fail")}
		}},
		{"tree", "parent_failed", func(o *Options) {
			o.Tree = &fakeTree{err: PhaseError("tree", "parent_failed", "injected tree fail")}
		}},
		{"aci", "server_reject", func(o *Options) {
			o.ACIs = &fakeACIs{err: PhaseError("aci", "server_reject", "injected aci fail")}
		}},
		{"seed", "apply_failed", func(o *Options) {
			o.Seed = &fakeSeed{err: PhaseError("seed", "apply_failed", "injected seed fail")}
		}},
		{"marker", "apply_failed", func(o *Options) {
			o.Marker = &fakeMarker{err: PhaseError("marker", "apply_failed", "injected marker fail")}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.phase, func(t *testing.T) {
			opt, _, _, _, _, fm, _ := applyOpts(cfg, pw)
			tc.patch(&opt)
			sum, err := Run(t.Context(), opt, ioDiscard(), ioDiscard())
			if err == nil {
				t.Fatal("expected phase failure")
			}
			if sum.OK {
				t.Fatal("must not report success")
			}
			apperr.Assert(t, err).Code(apperr.CodeBootstrap).FieldPath("phase." + tc.phase)
			last := sum.Phases[len(sum.Phases)-1]
			if last.Phase != tc.phase || last.Code != tc.code {
				t.Fatalf("phase=%s code=%s want %s/%s", last.Phase, last.Code, tc.phase, tc.code)
			}
			if tc.phase != "marker" && fm.called != 0 {
				t.Fatal("failed write phase must not write marker")
			}
			if strings.Contains(err.Error(), "alice-seed-secret") || strings.Contains(err.Error(), "dm-secret") {
				t.Fatal("public error leaked secret")
			}
		})
	}
}

func ioDiscard() *bytes.Buffer { return &bytes.Buffer{} }
