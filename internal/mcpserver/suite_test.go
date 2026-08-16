package mcpserver

import (
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/reset"
)

func suiteServices() (*app.Services, *fakeUsers) {
	users := newFakeUsers()
	users.put(directory.User{ID: "seed", UID: "seed"})
	groups := newFakeGroups()
	svc := app.New(app.Deps{
		Users:  users,
		Groups: groups,
		Search: &fakeSearch{pages: []directory.SearchPage{{
			Entries: []directory.SearchEntry{{DN: "uid=seed,ou=people,dc=example,dc=test", Attributes: []directory.AttrKV{{Name: "uid", Value: "seed"}}}},
		}}},
		Bind:             &fakeBind{identity: "alice", password: mcpUserPass},
		Caps:             fakeCaps{caps: directory.Capabilities{EngineVendor: "389 Project", RequiredOK: true}},
		Marker:           fakeMarker{m: directory.BaselineMarker{AppliedRevision: "aaa"}},
		Schema:           fakeSchema{dse: directory.RootDSE{VendorName: "389 Project"}, sch: directory.Schema{Attributes: []directory.AttributeType{{Name: "uid"}}}},
		ExpectedRevision: "aaa",
		ControlRevision:  "bbb",
		PeopleDN:         "ou=people,dc=example,dc=test",
		GroupsDN:         "ou=groups,dc=example,dc=test",
		ResetDir:         &fakeResetDir{ldif: "dn: dc=example,dc=test\nobjectClass: domain\n\n"},
		SoftReset:        true,
		ScenarioName:     "lab",
		ExportMaxBytes:   1 << 20,
		ResetLock:        reset.NewGate(),
	})
	return svc, users
}

func suiteServer(t *testing.T) (*Server, *app.Services) {
	t.Helper()
	svc, _ := suiteServices()
	s, err := New(Options{
		Registry: testRegistry(t),
		Services: svc,
		Flags:    RegisterFlags{Mutations: true, Password: true, Reset: true, Export: true},
		MaxBody:  1 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, svc
}

func TestEveryToolPositiveAndDeniedScope(t *testing.T) {
	t.Parallel()
	s, svc := suiteServer(t)
	mux := http.NewServeMux()
	mux.Handle(MountPath, s.Handler())
	admin, _ := connectMCP(t, mux, testToken, "")
	created := callTool(t, admin, ToolCreateUser, CreateUserInput{ID: "alice", Password: mcpUserPass})
	if created.IsError {
		t.Fatal(toolErrText(created))
	}
	userRev := string(decodeStructured[directory.User](t, created).Revision)
	gcreated := callTool(t, admin, ToolCreateGroup, directory.GroupSpec{
		ID: "staff", Members: []directory.MemberRef{{Kind: "user", ID: "alice"}},
	})
	if gcreated.IsError {
		t.Fatal(toolErrText(gcreated))
	}
	groupRev := string(decodeStructured[directory.Group](t, gcreated).Revision)

	type step struct {
		tool  string
		args  any
		allow string
		deny  string
	}
	steps := []step{
		{tool: ToolCapabilities, args: emptyInput{}, allow: testToken, deny: schemaTok},
		{tool: ToolBaseline, args: emptyInput{}, allow: testToken, deny: schemaTok},
		{tool: ToolSearch, args: directory.SearchQuery{Filter: "(uid=seed)", PageSize: 1}, allow: readToken, deny: schemaTok},
		{tool: ToolGetEntry, args: GetEntryInput{DN: "uid=seed,ou=people,dc=example,dc=test"}, allow: readToken, deny: schemaTok},
		{tool: ToolCreateUser, args: CreateUserInput{ID: "carol", Password: mcpUserPass}, allow: writeToken, deny: readToken},
		{tool: ToolUpdateUser, args: UpdateUserInput{ID: "alice", Revision: userRev, Attributes: map[string]string{"sn": "X"}}, allow: writeToken, deny: readToken},
		{tool: ToolSetPassword, args: SetPasswordInput{ID: "alice", Password: mcpUserPass, Revision: userRev}, allow: passwordToken, deny: writeToken},
		{tool: ToolAccountState, args: IDOnlyInput{ID: "alice"}, allow: readToken, deny: schemaTok},
		{tool: ToolExpirePassword, args: RevisionIDInput{ID: "alice", Revision: userRev}, allow: passwordToken, deny: writeToken},
		{tool: ToolClearPasswordExpiry, args: RevisionIDInput{ID: "alice", Revision: userRev}, allow: passwordToken, deny: writeToken},
		{tool: ToolLockUser, args: RevisionIDInput{ID: "alice", Revision: userRev}, allow: writeToken, deny: readToken},
		{tool: ToolUnlockUser, args: RevisionIDInput{ID: "alice", Revision: userRev}, allow: writeToken, deny: readToken},
		{tool: ToolEnableUser, args: RevisionIDInput{ID: "alice", Revision: userRev}, allow: writeToken, deny: readToken},
		{tool: ToolDisableUser, args: RevisionIDInput{ID: "alice", Revision: userRev}, allow: writeToken, deny: readToken},
		{tool: ToolAddMembers, args: MembersInput{ID: "staff", Revision: groupRev, Members: []directory.MemberRef{{Kind: "user", ID: "alice"}}}, allow: writeToken, deny: readToken},
		{tool: ToolRemoveMembers, args: MembersInput{ID: "staff", Revision: groupRev, Members: []directory.MemberRef{{Kind: "user", ID: "missing"}}}, allow: writeToken, deny: readToken},
		{tool: ToolReplaceMembers, args: MembersInput{ID: "staff", Revision: groupRev, Members: []directory.MemberRef{{Kind: "user", ID: "alice"}}}, allow: writeToken, deny: readToken},
		{tool: ToolBindTest, args: BindTestInput{Identity: "alice", Password: mcpUserPass}, allow: passwordToken, deny: writeToken},
		{tool: ToolExportLDIF, args: ExportLDIFInput{}, allow: exportToken, deny: writeToken},
		{tool: ToolResetSuffix, args: ResetSuffixInput{Name: "lab", ExpectedRevision: "aaa", Confirm: true}, allow: resetToken, deny: writeToken},
		{tool: ToolCreateGroup, args: directory.GroupSpec{ID: "crew", Members: []directory.MemberRef{{Kind: "user", ID: "alice"}}}, allow: writeToken, deny: readToken},
		{tool: ToolDeleteGroup, args: DeleteInput{ID: "crew", Confirm: true}, allow: writeToken, deny: readToken},
		{tool: ToolDeleteUser, args: DeleteInput{ID: "carol", Confirm: true}, allow: writeToken, deny: readToken},
	}

	reader := app.Principal{Kind: app.KindToken, ID: "admin", Scopes: directory.ScopeSet{auth.ScopeDirectoryRead}}
	userRevOf := func(id string) string {
		u, err := svc.Users.Get(t.Context(), reader, directory.UserID(id))
		if err != nil {
			return ""
		}
		return string(u.Revision)
	}
	groupRevOf := func(id string) string {
		g, err := svc.Groups.Get(t.Context(), reader, directory.GroupID(id))
		if err != nil {
			return ""
		}
		return string(g.Revision)
	}
	covered := map[string]bool{}
	for _, st := range steps {
		switch st.tool {
		case ToolUpdateUser:
			st.args = UpdateUserInput{ID: "alice", Revision: userRevOf("alice"), Attributes: map[string]string{"sn": "X"}}
		case ToolSetPassword:
			st.args = SetPasswordInput{ID: "alice", Password: mcpUserPass, Revision: userRevOf("alice")}
		case ToolExpirePassword, ToolClearPasswordExpiry, ToolLockUser, ToolUnlockUser, ToolEnableUser, ToolDisableUser:
			st.args = RevisionIDInput{ID: "alice", Revision: userRevOf("alice")}
		case ToolAddMembers, ToolRemoveMembers, ToolReplaceMembers:
			in := st.args.(MembersInput)
			in.Revision = groupRevOf("staff")
			st.args = in
		case ToolDeleteGroup:
			st.args = DeleteInput{ID: "crew", Revision: groupRevOf("crew"), Confirm: true}
		case ToolDeleteUser:
			st.args = DeleteInput{ID: "carol", Revision: userRevOf("carol"), Confirm: true}
		}
		denySess, _ := connectMCP(t, mux, st.deny, "")
		denied := callTool(t, denySess, st.tool, st.args)
		if !denied.IsError {
			t.Fatalf("%s: missing-scope token %q was allowed", st.tool, st.deny)
		}
		text := toolErrText(denied)
		if strings.Contains(text, "admin") || strings.Contains(text, testToken) {
			t.Fatalf("%s leaked actor: %s", st.tool, text)
		}
		if d, ok := LookupTool(st.tool); ok && !strings.Contains(text, d.Scope) {
			t.Fatalf("%s denied text missing required scope %s: %s", st.tool, d.Scope, text)
		}
		allowSess, _ := connectMCP(t, mux, st.allow, "")
		allowed := callTool(t, allowSess, st.tool, st.args)
		if allowed.IsError {
			// delete with stale revision after mutate refresh should succeed; others must
			t.Fatalf("%s positive: %s", st.tool, toolErrText(allowed))
		}
		covered[st.tool] = true
	}
	for _, d := range Catalog() {
		if !d.ShouldRegister(RegisterFlags{Mutations: true, Password: true, Reset: true, Export: true}) {
			continue
		}
		if !covered[d.Name] {
			t.Errorf("no positive/denied tests for %s", d.Name)
		}
	}
}

func TestConcurrentClientsDoNotShareActor(t *testing.T) {
	t.Parallel()
	s, _ := suiteServer(t)
	mux := http.NewServeMux()
	mux.Handle(MountPath, s.Handler())
	writer, _ := connectMCP(t, mux, writeToken, "writer-request-id-aaaaaaaaaaaa")
	reader, _ := connectMCP(t, mux, readToken, "reader-request-id-bbbbbbbbbbbb")

	var wg sync.WaitGroup
	errCh := make(chan string, 4)
	wg.Add(2)
	go func() {
		defer wg.Done()
		res := callTool(t, writer, ToolCreateUser, CreateUserInput{ID: "conc", Password: mcpUserPass})
		if res.IsError {
			errCh <- "writer create: " + toolErrText(res)
		}
	}()
	go func() {
		defer wg.Done()
		res := callTool(t, reader, ToolCreateUser, CreateUserInput{ID: "noleak", Password: mcpUserPass})
		if !res.IsError {
			errCh <- "reader must not inherit writer scopes"
		}
		caps := callTool(t, reader, ToolCapabilities, emptyInput{})
		if caps.IsError {
			errCh <- "reader capabilities: " + toolErrText(caps)
		}
	}()
	wg.Wait()
	close(errCh)
	for msg := range errCh {
		t.Error(msg)
	}
}

func TestInvalidToolInputIsToolError(t *testing.T) {
	t.Parallel()
	s, _ := suiteServer(t)
	mux := http.NewServeMux()
	mux.Handle(MountPath, s.Handler())
	sess, _ := connectMCP(t, mux, testToken, "")
	res, err := sess.CallTool(t.Context(), &mcp.CallToolParams{
		Name:      ToolCreateUser,
		Arguments: map[string]any{"id": 1, "password": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatalf("invalid schema must be a tool error: %+v", res)
	}
}
