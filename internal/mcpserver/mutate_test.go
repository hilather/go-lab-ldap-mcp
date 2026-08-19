package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

func mutationServices(users directory.UserRepository, groups directory.GroupRepository, bind directory.BindTester) *app.Services {
	return app.New(app.Deps{
		Users:            users,
		Groups:           groups,
		Entries:          newFakeEntries(),
		Search:           &fakeSearch{},
		Bind:             bind,
		Caps:             fakeCaps{caps: directory.Capabilities{EngineVendor: "389 Project"}},
		Marker:           fakeMarker{m: directory.BaselineMarker{AppliedRevision: "aaa"}},
		Schema:           fakeSchema{},
		ExpectedRevision: "aaa",
		ControlRevision:  "bbb",
		PeopleDN:         "ou=people,dc=example,dc=test",
		GroupsDN:         "ou=groups,dc=example,dc=test",
	})
}

func mutationServer(t *testing.T, svc *app.Services, log *slog.Logger) *Server {
	t.Helper()
	s, err := New(Options{
		Registry: testRegistry(t),
		Services: svc,
		Logger:   log,
		Flags:    RegisterFlags{Mutations: true, Password: true},
		MaxBody:  1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func callTool(t *testing.T, sess *mcp.ClientSession, name string, args any) *mcp.CallToolResult {
	t.Helper()
	res, err := sess.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
}

func toolErrText(res *mcp.CallToolResult) string {
	if res == nil {
		return ""
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	raw, _ := json.Marshal(res.StructuredContent)
	b.Write(raw)
	return b.String()
}

func TestMCPUserCreateVisibleViaAppAndNoPasswordLeak(t *testing.T) {
	t.Parallel()
	users, groups := newFakeUsers(), newFakeGroups()
	svc := mutationServices(users, groups, &fakeBind{})
	var logs bytes.Buffer
	s := mutationServer(t, svc, slog.New(slog.NewTextHandler(&logs, nil)))
	mux := http.NewServeMux()
	mux.Handle(MountPath, s.Handler())
	sess, _ := connectMCP(t, mux, testToken, "")

	created := callTool(t, sess, ToolCreateUser, CreateUserInput{
		ID: "alice", Password: mcpUserPass, Attributes: map[string]string{"sn": "Example"},
	})
	if created.IsError {
		t.Fatalf("create: %s", toolErrText(created))
	}
	got := decodeStructured[directory.User](t, created)
	if got.ID != "alice" || got.Revision == "" {
		t.Fatalf("created %+v", got)
	}
	if containsSecret(toolJSON(created.StructuredContent)+toolErrText(created), mcpUserPass) {
		t.Fatalf("password in create result: %+v", created)
	}
	if containsSecret(logs.String(), mcpUserPass) {
		t.Fatalf("password in logs: %s", logs.String())
	}

	// Same Users service REST calls. Cross-transport REST check lives in cmd/labldap.
	live, err := svc.Users.Get(t.Context(), app.Principal{
		Kind: app.KindToken, ID: "admin",
		Scopes: directory.ScopeSet{auth.ScopeDirectoryRead},
	}, "alice")
	if err != nil || live.ID != "alice" {
		t.Fatalf("app get: %+v %v", live, err)
	}
}

func TestMCPUserUpdateDeleteAndPassword(t *testing.T) {
	t.Parallel()
	users, groups := newFakeUsers(), newFakeGroups()
	svc := mutationServices(users, groups, &fakeBind{})
	var logs bytes.Buffer
	s := mutationServer(t, svc, slog.New(slog.NewTextHandler(&logs, nil)))
	mux := http.NewServeMux()
	mux.Handle(MountPath, s.Handler())
	sess, _ := connectMCP(t, mux, testToken, "")

	created := callTool(t, sess, ToolCreateUser, CreateUserInput{ID: "bob", Password: mcpUserPass})
	if created.IsError {
		t.Fatal(toolErrText(created))
	}
	rev := decodeStructured[directory.User](t, created).Revision

	upd := callTool(t, sess, ToolUpdateUser, UpdateUserInput{
		ID: "bob", Revision: string(rev), Attributes: map[string]string{"sn": "Updated"},
	})
	if upd.IsError {
		t.Fatal(toolErrText(upd))
	}
	after := decodeStructured[directory.User](t, upd)
	if after.Revision == rev {
		t.Fatal("revision did not change")
	}

	noConfirm := callTool(t, sess, ToolDeleteUser, DeleteInput{ID: "bob", Revision: string(after.Revision)})
	if !noConfirm.IsError || !strings.Contains(toolErrText(noConfirm), "confirm") {
		t.Fatalf("delete without confirm: %s", toolErrText(noConfirm))
	}
	if _, err := users.Get(t.Context(), "bob"); err != nil {
		t.Fatal("user deleted without confirm")
	}

	const neu = "unit-mcp-user-pass-99"
	pw := callTool(t, sess, ToolSetPassword, SetPasswordInput{ID: "bob", Password: neu, Revision: string(after.Revision)})
	if pw.IsError {
		t.Fatal(toolErrText(pw))
	}
	if containsSecret(toolJSON(pw.StructuredContent)+toolErrText(pw)+logs.String(), mcpUserPass, neu) {
		t.Fatalf("password leaked: %s %s", toolErrText(pw), logs.String())
	}
	users.mu.Lock()
	if users.passwords["bob"] != neu {
		t.Fatalf("password not stored")
	}
	users.mu.Unlock()

	del := callTool(t, sess, ToolDeleteUser, DeleteInput{ID: "bob", Revision: string(after.Revision), Confirm: true})
	if del.IsError {
		t.Fatal(toolErrText(del))
	}
	if _, err := users.Get(t.Context(), "bob"); err == nil {
		t.Fatal("user still present")
	}
}

func TestMCPAccountWorkflowTools(t *testing.T) {
	t.Parallel()
	users, groups := newFakeUsers(), newFakeGroups()
	svc := mutationServices(users, groups, &fakeBind{})
	s := mutationServer(t, svc, nil)
	mux := http.NewServeMux()
	mux.Handle(MountPath, s.Handler())
	sess, _ := connectMCP(t, mux, testToken, "")
	created := callTool(t, sess, ToolCreateUser, CreateUserInput{ID: "dave", Password: mcpUserPass})
	if created.IsError {
		t.Fatal(toolErrText(created))
	}
	rev := string(decodeStructured[directory.User](t, created).Revision)
	exp := callTool(t, sess, ToolExpirePassword, RevisionIDInput{ID: "dave", Revision: rev})
	if exp.IsError {
		t.Fatal(toolErrText(exp))
	}
	st := decodeStructured[directory.AccountState](t, exp)
	if !st.MustChange {
		t.Fatalf("expire: %+v", st)
	}
	got := callTool(t, sess, ToolAccountState, IDOnlyInput{ID: "dave"})
	if got.IsError || !decodeStructured[directory.AccountState](t, got).MustChange {
		t.Fatalf("get state: %s", toolErrText(got))
	}
	lock := callTool(t, sess, ToolLockUser, RevisionIDInput{ID: "dave", Revision: rev})
	if lock.IsError || !decodeStructured[directory.AccountState](t, lock).Locked {
		t.Fatalf("lock: %s", toolErrText(lock))
	}
	unlock := callTool(t, sess, ToolUnlockUser, RevisionIDInput{ID: "dave", Revision: rev})
	if unlock.IsError || decodeStructured[directory.AccountState](t, unlock).Locked {
		t.Fatalf("unlock: %s", toolErrText(unlock))
	}
	if err := svc.Users.SetPassword(t.Context(), app.Principal{
		Kind: app.KindToken, ID: "admin", Scopes: directory.ScopeSet{auth.ScopeDirectoryPassword},
	}, "dave", observability.Secret(mcpUserPass), directory.Revision(rev), false); err != nil {
		t.Fatal(err)
	}
	cleared := callTool(t, sess, ToolAccountState, IDOnlyInput{ID: "dave"})
	if decodeStructured[directory.AccountState](t, cleared).MustChange {
		t.Fatal("set password should clear must-change")
	}
	setMust := callTool(t, sess, ToolSetPassword, SetPasswordInput{ID: "dave", Password: mcpUserPass, Revision: rev, MustChange: true})
	if setMust.IsError {
		t.Fatal(toolErrText(setMust))
	}
	if !decodeStructured[directory.AccountState](t, callTool(t, sess, ToolAccountState, IDOnlyInput{ID: "dave"})).MustChange {
		t.Fatal("set password mustChange should stamp must-change")
	}
	dis := callTool(t, sess, ToolDisableUser, RevisionIDInput{ID: "dave", Revision: rev})
	if dis.IsError || decodeStructured[directory.User](t, dis).Enabled {
		t.Fatalf("disable: %s", toolErrText(dis))
	}
	enRev := string(decodeStructured[directory.User](t, dis).Revision)
	en := callTool(t, sess, ToolEnableUser, RevisionIDInput{ID: "dave", Revision: enRev})
	if en.IsError || !decodeStructured[directory.User](t, en).Enabled {
		t.Fatalf("enable: %s", toolErrText(en))
	}
}

func TestMCPUserWriteScopeDenied(t *testing.T) {
	t.Parallel()
	s := mutationServer(t, mutationServices(newFakeUsers(), newFakeGroups(), &fakeBind{}), nil)
	mux := http.NewServeMux()
	mux.Handle(MountPath, s.Handler())
	reader, _ := connectMCP(t, mux, readToken, "")
	res := callTool(t, reader, ToolCreateUser, CreateUserInput{ID: "carol", Password: mcpUserPass})
	if !res.IsError {
		t.Fatal("reader must not create users")
	}
	if containsSecret(toolErrText(res), "admin", testToken, mcpUserPass) {
		t.Fatalf("leaked identity: %s", toolErrText(res))
	}
	writer, _ := connectMCP(t, mux, writeToken, "")
	created := callTool(t, writer, ToolCreateUser, CreateUserInput{ID: "carol", Password: mcpUserPass})
	if created.IsError {
		t.Fatal(toolErrText(created))
	}
	rev := decodeStructured[directory.User](t, created).Revision
	pw := callTool(t, writer, ToolSetPassword, SetPasswordInput{ID: "carol", Password: mcpUserPass, Revision: string(rev)})
	if !pw.IsError {
		t.Fatal("write must not set password")
	}
}

func TestMCPGroupEmptyCycleAndIdempotentMembers(t *testing.T) {
	t.Parallel()
	users, groups := newFakeUsers(), newFakeGroups()
	svc := mutationServices(users, groups, &fakeBind{})
	s := mutationServer(t, svc, nil)
	mux := http.NewServeMux()
	mux.Handle(MountPath, s.Handler())
	sess, ts := connectMCP(t, mux, testToken, "")

	empty := callTool(t, sess, ToolCreateGroup, directory.GroupSpec{ID: "staff"})
	if !empty.IsError || !strings.Contains(toolErrText(empty), "empty_group") {
		t.Fatalf("empty group: %s", toolErrText(empty))
	}
	self := callTool(t, sess, ToolCreateGroup, directory.GroupSpec{
		ID: "staff", Members: []directory.MemberRef{{Kind: "group", ID: "staff"}},
	})
	if !self.IsError || !strings.Contains(toolErrText(self), "cycle") {
		t.Fatalf("self member: %s", toolErrText(self))
	}

	createUser := callTool(t, sess, ToolCreateUser, CreateUserInput{ID: "alice", Password: mcpUserPass})
	if createUser.IsError {
		t.Fatal(toolErrText(createUser))
	}
	created := callTool(t, sess, ToolCreateGroup, directory.GroupSpec{
		ID: "staff", Members: []directory.MemberRef{{Kind: "user", ID: "alice"}},
	})
	if created.IsError {
		t.Fatal(toolErrText(created))
	}
	rev := decodeStructured[directory.Group](t, created).Revision

	again := callTool(t, sess, ToolAddMembers, MembersInput{
		ID: "staff", Revision: string(rev),
		Members: []directory.MemberRef{{Kind: "user", ID: "alice"}},
	})
	if again.IsError {
		t.Fatal(toolErrText(again))
	}
	sum := decodeStructured[directory.MembershipSummary](t, again)
	if len(sum.Added) != 0 || len(sum.Unchanged) != 1 {
		t.Fatalf("idempotent add %+v", sum)
	}

	bob := callTool(t, sess, ToolCreateUser, CreateUserInput{ID: "bob", Password: mcpUserPass})
	if bob.IsError {
		t.Fatal(toolErrText(bob))
	}
	added := callTool(t, sess, ToolAddMembers, MembersInput{
		ID: "staff", Revision: string(sum.Revision),
		Members: []directory.MemberRef{{Kind: "user", ID: "bob"}},
	})
	if added.IsError {
		t.Fatal(toolErrText(added))
	}
	sum = decodeStructured[directory.MembershipSummary](t, added)
	if len(sum.Added) != 1 {
		t.Fatalf("add bob %+v", sum)
	}
	live, err := svc.Groups.Get(t.Context(), app.Principal{
		Kind: app.KindToken, ID: "admin",
		Scopes: directory.ScopeSet{auth.ScopeDirectoryRead},
	}, "staff")
	if err != nil || len(live.Members) != 2 {
		t.Fatalf("app group %+v %v", live, err)
	}
	_ = ts
}

func TestMCPGroupWriteScopeDenied(t *testing.T) {
	t.Parallel()
	s := mutationServer(t, mutationServices(newFakeUsers(), newFakeGroups(), &fakeBind{}), nil)
	mux := http.NewServeMux()
	mux.Handle(MountPath, s.Handler())
	reader, _ := connectMCP(t, mux, readToken, "")
	res := callTool(t, reader, ToolCreateGroup, directory.GroupSpec{
		ID: "staff", Members: []directory.MemberRef{{Kind: "user", ID: "alice"}},
	})
	if !res.IsError {
		t.Fatal("reader must not create groups")
	}
}

func TestMCPBindTestRequiresPasswordScope(t *testing.T) {
	t.Parallel()
	bind := &fakeBind{identity: "alice", password: mcpUserPass}
	s := mutationServer(t, mutationServices(newFakeUsers(), newFakeGroups(), bind), nil)
	mux := http.NewServeMux()
	mux.Handle(MountPath, s.Handler())

	writer, _ := connectMCP(t, mux, writeToken, "")
	denied := callTool(t, writer, ToolBindTest, BindTestInput{Identity: "alice", Password: mcpUserPass})
	if !denied.IsError {
		t.Fatal("write must not bind-test")
	}

	pw, _ := connectMCP(t, mux, passwordToken, "")
	ok := callTool(t, pw, ToolBindTest, BindTestInput{Identity: "alice", Password: mcpUserPass, Transport: "ldaps"})
	if ok.IsError {
		t.Fatal(toolErrText(ok))
	}
	if decodeStructured[directory.BindTestResult](t, ok).Outcome != directory.BindOutcomeSuccess {
		t.Fatalf("%+v", ok)
	}

	unknown := callTool(t, pw, ToolBindTest, BindTestInput{Identity: "missing", Password: mcpUserPass})
	wrong := callTool(t, pw, ToolBindTest, BindTestInput{Identity: "alice", Password: "unit-mcp-wrong-pass-12"})
	if unknown.IsError || wrong.IsError {
		t.Fatalf("diagnostic: %s %s", toolErrText(unknown), toolErrText(wrong))
	}
	uOut := decodeStructured[directory.BindTestResult](t, unknown)
	wOut := decodeStructured[directory.BindTestResult](t, wrong)
	if uOut.Outcome != directory.BindOutcomeInvalidCredentials || wOut.Outcome != uOut.Outcome {
		t.Fatalf("unknown=%+v wrong=%+v", uOut, wOut)
	}
	if containsSecret(toolErrText(unknown)+toolErrText(wrong)+toolJSON(unknown.StructuredContent), mcpUserPass, "missing") {
		t.Fatal("bind-test leaked identity or password")
	}

	bind.mu.Lock()
	if bind.open != 0 || bind.closed != bind.calls {
		t.Fatalf("connections not closed: open=%d closed=%d calls=%d", bind.open, bind.closed, bind.calls)
	}
	bind.mu.Unlock()
}

func TestMCPBindTestCancellationClosesConn(t *testing.T) {
	t.Parallel()
	hang := make(chan struct{})
	saw := make(chan struct{})
	bind := &fakeBind{hang: hang, saw: saw}
	s := mutationServer(t, mutationServices(newFakeUsers(), newFakeGroups(), bind), nil)
	mux := http.NewServeMux()
	mux.Handle(MountPath, s.Handler())
	sess, _ := connectMCP(t, mux, passwordToken, "")
	ctx, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)
	go func() {
		_, err := sess.CallTool(ctx, &mcp.CallToolParams{
			Name:      ToolBindTest,
			Arguments: BindTestInput{Identity: "alice", Password: mcpUserPass},
		})
		errCh <- err
	}()
	select {
	case <-saw:
	case <-time.After(3 * time.Second):
		t.Fatal("bind-test did not start")
	}
	cancel()
	select {
	case <-hang:
	case <-time.After(3 * time.Second):
		t.Fatal("bind-test was not cancelled")
	}
	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("client call did not return")
	}
	bind.mu.Lock()
	if bind.open != 0 {
		t.Fatalf("connection left open: %d", bind.open)
	}
	bind.mu.Unlock()
}
