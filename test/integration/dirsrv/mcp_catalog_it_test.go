//go:build integration

package dirsrv

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hilather/go-lab-ldap-mcp/internal/api"
	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/mcpserver"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

const (
	catalogITToken = "lab-it-catalog-admin-token-32xx"
	catalogITPass  = "catalog-user-pass-12"
	catalogShortPW = "short"
	catalogStale   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	catalogApprox  = "(cn~=Alic Anderson)"
)

type catalogHarness struct {
	env  *runtimeEnv
	mux  http.Handler
	sess *mcp.ClientSession
}

func startCatalogHarness(t *testing.T) *catalogHarness {
	t.Helper()
	env := startRuntimeEnv(t)
	svc := app.New(app.Deps{
		Users:    env.rt.Users(),
		Groups:   env.rt.Groups(),
		Search:   env.rt,
		Bind:     env.rt,
		Schema:   env.rt,
		Caps:     env.rt,
		Marker:   env.rt,
		ResetDir: env.rt,
		PeopleDN: runtimePeopleDN,
		GroupsDN: runtimeGroupsDN,
		Suffix:   runtimeSuffix,
	})
	reg, err := auth.NewRegistry([]auth.Token{{
		ID: "admin",
		Scopes: []string{
			auth.ScopeDirectoryRead, auth.ScopeDirectoryWrite, auth.ScopeDirectoryPassword,
			auth.ScopeSchemaRead, auth.ScopeLabReset, auth.ScopeLabExport,
		},
		Secret: observability.Secret(catalogITToken),
	}})
	if err != nil {
		t.Fatal(err)
	}
	rest, err := api.New(api.Options{
		Registry: reg,
		Sessions: auth.NewStore(auth.DefaultSessionConfig()),
		Users:    svc.Users,
		Groups:   svc.Groups,
		Query:    svc.Query,
		System:   svc.Query,
		Export:   svc.Export,
		Ready:    func() bool { return true },
	})
	if err != nil {
		t.Fatal(err)
	}
	ms, err := mcpserver.New(mcpserver.Options{
		Registry: reg,
		Services: svc,
		Flags:    mcpserver.RegisterFlags{Mutations: true, Password: true, Reset: true, Export: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle(mcpserver.MountPath, ms.Handler())
	mux.Handle("/", rest.Handler())
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	client := mcp.NewClient(&mcp.Implementation{Name: "labldap-catalog-it", Version: "v0.0.1"}, nil)
	sess, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{
		Endpoint:             ts.URL + mcpserver.MountPath,
		DisableStandaloneSSE: true,
		HTTPClient:           &http.Client{Transport: bearerRT{base: ts.Client().Transport, token: catalogITToken}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return &catalogHarness{env: env, mux: mux, sess: sess}
}

func TestMCPCatalogAndGoldenPaths(t *testing.T) {
	h := startCatalogHarness(t)
	t.Run("listed_and_invoked", func(t *testing.T) { testCatalogListedAndInvoked(t, h) })
	t.Run("golden_failures", func(t *testing.T) { testCatalogGoldenFailures(t, h) })
	t.Run("d1_d30", func(t *testing.T) { testCatalogListingDeltas(t, h) })
}

func testCatalogListedAndInvoked(t *testing.T, h *catalogHarness) {
	t.Helper()
	flags := mcpserver.RegisterFlags{Mutations: true, Password: true, Reset: true, Export: true}
	wantTools := map[string]struct{}{}
	for _, d := range mcpserver.Catalog() {
		if d.ShouldRegister(flags) {
			wantTools[d.Name] = struct{}{}
		}
	}
	gotTools := map[string]struct{}{}
	for tool, err := range h.sess.Tools(t.Context(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		gotTools[tool.Name] = struct{}{}
	}
	if !sameStringSet(gotTools, wantTools) {
		t.Fatalf("listed tools = %v want %v", keysOf(gotTools), keysOf(wantTools))
	}

	wantRes := map[string]struct{}{}
	wantTpl := map[string]struct{}{}
	for _, r := range mcpserver.ResourceCatalog() {
		if r.URI != "" {
			wantRes[r.URI] = struct{}{}
		}
		if r.URITemplate != "" {
			wantTpl[r.URITemplate] = struct{}{}
		}
	}
	gotRes := map[string]struct{}{}
	for res, err := range h.sess.Resources(t.Context(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		gotRes[res.URI] = struct{}{}
	}
	if !sameStringSet(gotRes, wantRes) {
		t.Fatalf("listed resources = %v want %v", keysOf(gotRes), keysOf(wantRes))
	}
	gotTpl := map[string]struct{}{}
	for tpl, err := range h.sess.ResourceTemplates(t.Context(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		gotTpl[tpl.URITemplate] = struct{}{}
	}
	if !sameStringSet(gotTpl, wantTpl) {
		t.Fatalf("listed templates = %v want %v", keysOf(gotTpl), keysOf(wantTpl))
	}

	mustToolOK(t, h, mcpserver.ToolCapabilities, map[string]any{})
	mustToolOK(t, h, mcpserver.ToolBaseline, map[string]any{})
	mustToolOK(t, h, mcpserver.ToolSearch, directory.SearchQuery{
		Base: runtimePeopleDN, Scope: directory.SearchScopeOne, Filter: "(uid=rt)",
	})
	mustToolOK(t, h, mcpserver.ToolGetEntry, mcpserver.GetEntryInput{DN: runtimeBindDN})

	created := mustToolOK(t, h, mcpserver.ToolCreateUser, mcpserver.CreateUserInput{
		ID: "cat-alice", Password: catalogITPass, Attributes: map[string]string{"sn": "Catalog", "cn": "Alice Catalog"},
	})
	alice := decodeMCP[directory.User](t, created)
	updated := mustToolOK(t, h, mcpserver.ToolUpdateUser, mcpserver.UpdateUserInput{
		ID: "cat-alice", Revision: string(alice.Revision), Attributes: map[string]string{"description": "catalog"},
	})
	alice = decodeMCP[directory.User](t, updated)
	mustToolOK(t, h, mcpserver.ToolSetPassword, mcpserver.SetPasswordInput{
		ID: "cat-alice", Password: catalogITPass + "x", Revision: string(alice.Revision),
	})

	gcreated := mustToolOK(t, h, mcpserver.ToolCreateGroup, directory.GroupSpec{
		ID: "cat-staff", Members: []directory.MemberRef{{Kind: "user", ID: "cat-alice"}},
	})
	group := decodeMCP[directory.Group](t, gcreated)
	sum := mustToolOK(t, h, mcpserver.ToolAddMembers, mcpserver.MembersInput{
		ID: "cat-staff", Revision: string(group.Revision), Members: []directory.MemberRef{{Kind: "user", ID: "cat-alice"}},
	})
	group.Revision = decodeMCP[directory.MembershipSummary](t, sum).Revision
	sum = mustToolOK(t, h, mcpserver.ToolRemoveMembers, mcpserver.MembersInput{
		ID: "cat-staff", Revision: string(group.Revision), Members: []directory.MemberRef{{Kind: "user", ID: "missing"}},
	})
	group.Revision = decodeMCP[directory.MembershipSummary](t, sum).Revision
	sum = mustToolOK(t, h, mcpserver.ToolReplaceMembers, mcpserver.MembersInput{
		ID: "cat-staff", Revision: string(group.Revision), Members: []directory.MemberRef{{Kind: "user", ID: "cat-alice"}},
	})
	group.Revision = decodeMCP[directory.MembershipSummary](t, sum).Revision

	bind := mustToolOK(t, h, mcpserver.ToolBindTest, mcpserver.BindTestInput{
		Identity: "cat-alice", Password: catalogITPass + "x", Transport: string(directory.TransportLDAPS),
	})
	if decodeMCP[directory.BindTestResult](t, bind).Outcome != directory.BindOutcomeSuccess {
		t.Fatalf("bind-test success: %s", mcpToolText(bind))
	}
	mustToolOK(t, h, mcpserver.ToolExportLDIF, mcpserver.ExportLDIFInput{})
	denied := callMCPTool(t, h, mcpserver.ToolResetSuffix, mcpserver.ResetSuffixInput{
		Name: "runtime", ExpectedRevision: "nope", Confirm: false,
	})
	if !denied.IsError || !strings.Contains(mcpToolText(denied), "confirm") {
		t.Fatalf("reset without confirm: %s", mcpToolText(denied))
	}

	mustToolOK(t, h, mcpserver.ToolDeleteGroup, mcpserver.DeleteInput{
		ID: "cat-staff", Revision: string(group.Revision), Confirm: true,
	})
	alice = mustGetUser(t, h, "cat-alice")
	mustToolOK(t, h, mcpserver.ToolDeleteUser, mcpserver.DeleteInput{
		ID: "cat-alice", Revision: string(alice.Revision), Confirm: true,
	})

	for _, uri := range []string{
		"labldap://capabilities", "labldap://baseline", "labldap://rootdse", "labldap://schema",
		"labldap://schema/objectclass/inetOrgPerson", "labldap://schema/attribute/cn",
		"labldap://entry?dn=uid%3Drt%2Cou%3Dpeople%2Cdc%3Dexample%2Cdc%3Dtest",
	} {
		res, err := h.sess.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: uri})
		if err != nil || res == nil || len(res.Contents) == 0 || res.Contents[0].Text == "" {
			t.Fatalf("read %s: %v %+v", uri, err, res)
		}
	}
}

func testCatalogGoldenFailures(t *testing.T, h *catalogHarness) {
	t.Helper()
	created := mustToolOK(t, h, mcpserver.ToolCreateUser, mcpserver.CreateUserInput{
		ID: "cat-gold", Password: catalogITPass, Attributes: map[string]string{"sn": "Gold", "cn": "Alice Anderson"},
	})
	u := decodeMCP[directory.User](t, created)

	shortMCP := callMCPTool(t, h, mcpserver.ToolSetPassword, mcpserver.SetPasswordInput{
		ID: "cat-gold", Password: catalogShortPW, Revision: string(u.Revision),
	})
	shortREST := restJSON(t, h, http.MethodPost, "/api/v1/users/cat-gold/password",
		`{"password":"`+catalogShortPW+`","revision":"`+string(u.Revision)+`"}`)
	assertGoldenProblem(t, "short-password", shortREST, shortMCP, http.StatusBadRequest, directory.FieldConstraint)

	staleMCP := callMCPTool(t, h, mcpserver.ToolUpdateUser, mcpserver.UpdateUserInput{
		ID: "cat-gold", Revision: catalogStale, Attributes: map[string]string{"description": "stale"},
	})
	staleREST := restJSONHeader(t, h, http.MethodPatch, "/api/v1/users/cat-gold",
		`{"attributes":{"description":"stale"}}`, map[string]string{"If-Match": `"` + catalogStale + `"`})
	assertGoldenProblem(t, "stale-revision", staleREST, staleMCP, http.StatusPreconditionFailed, directory.FieldConflict)

	approxMCP := callMCPTool(t, h, mcpserver.ToolSearch, directory.SearchQuery{
		Base: runtimePeopleDN, Scope: directory.SearchScopeSub, Filter: catalogApprox,
	})
	approxREST := restJSON(t, h, http.MethodPost, "/api/v1/search",
		`{"base":"`+runtimePeopleDN+`","scope":"sub","filter":"`+catalogApprox+`"}`)
	assertGoldenProblem(t, "approx-filter", approxREST, approxMCP, http.StatusBadRequest, "unsupported_filter")

	unknownMCP := callMCPTool(t, h, mcpserver.ToolBindTest, mcpserver.BindTestInput{
		Identity: "no-such-catalog-user", Password: catalogITPass,
	})
	wrongMCP := callMCPTool(t, h, mcpserver.ToolBindTest, mcpserver.BindTestInput{
		Identity: "cat-gold", Password: "wrong-catalog-pass-99",
	})
	if unknownMCP.IsError || wrongMCP.IsError {
		t.Fatalf("bind-test diagnostics: %s %s", mcpToolText(unknownMCP), mcpToolText(wrongMCP))
	}
	unknownOut := decodeMCP[directory.BindTestResult](t, unknownMCP)
	wrongOut := decodeMCP[directory.BindTestResult](t, wrongMCP)
	if unknownOut.Outcome != directory.BindOutcomeInvalidCredentials || wrongOut.Outcome != unknownOut.Outcome {
		t.Fatalf("unknown=%s wrong=%s", unknownOut.Outcome, wrongOut.Outcome)
	}
	unknownREST := restJSON(t, h, http.MethodPost, "/api/v1/auth-tests",
		`{"identity":"no-such-catalog-user","password":"`+catalogITPass+`"}`)
	wrongREST := restJSON(t, h, http.MethodPost, "/api/v1/auth-tests",
		`{"identity":"cat-gold","password":"wrong-catalog-pass-99"}`)
	if unknownREST.status != http.StatusOK || wrongREST.status != http.StatusOK {
		t.Fatalf("bind-test REST %d %s / %d %s", unknownREST.status, unknownREST.body, wrongREST.status, wrongREST.body)
	}
	if restBindOutcome(t, unknownREST) != directory.BindOutcomeInvalidCredentials || restBindOutcome(t, wrongREST) != directory.BindOutcomeInvalidCredentials {
		t.Fatalf("REST bind outcomes %s / %s", unknownREST.body, wrongREST.body)
	}

	malformedMCP := callMCPTool(t, h, mcpserver.ToolBindTest, mcpserver.BindTestInput{
		Identity: "cn=not a dn", Password: catalogITPass,
	})
	if malformedMCP.IsError {
		t.Fatalf("malformed identity: %s", mcpToolText(malformedMCP))
	}
	if decodeMCP[directory.BindTestResult](t, malformedMCP).Outcome != directory.BindOutcomeInvalidCredentials {
		t.Fatalf("malformed outcome %s", mcpToolText(malformedMCP))
	}
	malformedREST := restJSON(t, h, http.MethodPost, "/api/v1/auth-tests",
		`{"identity":"cn=not a dn","password":"`+catalogITPass+`"}`)
	if malformedREST.status != http.StatusOK || restBindOutcome(t, malformedREST) != directory.BindOutcomeInvalidCredentials {
		t.Fatalf("REST malformed %d %s", malformedREST.status, malformedREST.body)
	}

	mustToolOK(t, h, mcpserver.ToolCreateUser, mcpserver.CreateUserInput{
		ID: "cat-lock", Password: catalogITPass, Attributes: map[string]string{"sn": "Lock"},
	})
	for i := 0; i < 6; i++ {
		fail := callMCPTool(t, h, mcpserver.ToolBindTest, mcpserver.BindTestInput{
			Identity: "cat-lock", Password: "wrong-lock-pass-99",
		})
		if fail.IsError {
			t.Fatalf("lockout probe %d: %s", i, mcpToolText(fail))
		}
	}
	var locked directory.BindTestResult
	deadline := time.Now().Add(3 * time.Second)
	for {
		res := callMCPTool(t, h, mcpserver.ToolBindTest, mcpserver.BindTestInput{
			Identity: "cat-lock", Password: catalogITPass,
		})
		if res.IsError {
			t.Fatalf("lockout bind-test: %s", mcpToolText(res))
		}
		locked = decodeMCP[directory.BindTestResult](t, res)
		if locked.Outcome == directory.BindOutcomeLocked || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if locked.Outcome != directory.BindOutcomeLocked {
		t.Fatalf("lockout MCP outcome=%s", locked.Outcome)
	}
	lockREST := restJSON(t, h, http.MethodPost, "/api/v1/auth-tests",
		`{"identity":"cat-lock","password":"`+catalogITPass+`"}`)
	if lockREST.status != http.StatusOK || restBindOutcome(t, lockREST) != directory.BindOutcomeLocked {
		t.Fatalf("lockout REST %d %s", lockREST.status, lockREST.body)
	}
}

func testCatalogListingDeltas(t *testing.T, h *catalogHarness) {
	t.Helper()
	capsRes := mustToolOK(t, h, mcpserver.ToolCapabilities, map[string]any{})
	caps := decodeMCP[directory.Capabilities](t, capsRes)
	restCaps := restJSON(t, h, http.MethodGet, "/api/v1/capabilities", "")
	if restCaps.status != http.StatusOK {
		t.Fatalf("GET capabilities %d %s", restCaps.status, restCaps.body)
	}
	var restBody directory.Capabilities
	if err := json.Unmarshal([]byte(restCaps.body), &restBody); err != nil {
		t.Fatal(err)
	}
	if restBody.EngineVendor != caps.EngineVendor {
		t.Fatalf("REST vendor %q MCP vendor %q", restBody.EngineVendor, caps.EngineVendor)
	}
	switch itEngine(t) {
	case EngineNative:
		if !strings.Contains(caps.EngineVendor, "LabLDAP") || strings.Contains(caps.EngineVendor, "389") {
			t.Fatalf("D1 native vendor = %q", caps.EngineVendor)
		}
	default:
		if caps.EngineVendor == "" || strings.EqualFold(caps.EngineVendor, "LabLDAP") {
			t.Fatalf("D1 389 vendor = %q", caps.EngineVendor)
		}
	}

	schemaRes, err := h.sess.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: "labldap://schema"})
	if err != nil || schemaRes == nil || len(schemaRes.Contents) == 0 {
		t.Fatalf("schema resource: %v %+v", err, schemaRes)
	}
	var sch directory.Schema
	if err := json.Unmarshal([]byte(schemaRes.Contents[0].Text), &sch); err != nil {
		t.Fatal(err)
	}
	hasLock := schemaHasAttr(sch, "pwdAccountLockedTime")
	attrURI := "labldap://schema/attribute/pwdAccountLockedTime"
	attrRes, attrErr := h.sess.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: attrURI})
	attrREST := restJSON(t, h, http.MethodGet, "/api/v1/schema/attributes/pwdAccountLockedTime", "")
	switch itEngine(t) {
	case EngineNative:
		if !hasLock {
			t.Fatal("D30 native schema must list pwdAccountLockedTime")
		}
		if attrErr != nil || attrRes == nil || len(attrRes.Contents) == 0 {
			t.Fatalf("D30 native attribute resource: %v", attrErr)
		}
		if attrREST.status != http.StatusOK {
			t.Fatalf("D30 native GET attribute %d %s", attrREST.status, attrREST.body)
		}
	default:
		if hasLock {
			t.Fatal("D30 389 schema must not list pwdAccountLockedTime")
		}
		if attrErr == nil {
			t.Fatalf("D30 389 attribute resource must 404: %+v", attrRes)
		}
		if attrREST.status != http.StatusNotFound {
			t.Fatalf("D30 389 GET attribute %d %s", attrREST.status, attrREST.body)
		}
	}
}

type restProblem struct {
	status int
	body   string
	code   string
	path   string
}

func restJSON(t *testing.T, h *catalogHarness, method, path, body string) restProblem {
	t.Helper()
	return restJSONHeader(t, h, method, path, body, nil)
}

func restJSONHeader(t *testing.T, h *catalogHarness, method, path, body string, extra map[string]string) restProblem {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Authorization", "Bearer "+catalogITToken)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	out := restProblem{status: rec.Code, body: rec.Body.String()}
	var parsed struct {
		Errors []struct {
			Path string `json:"path"`
			Code string `json:"code"`
		} `json:"errors"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &parsed)
	if len(parsed.Errors) > 0 {
		out.path = parsed.Errors[0].Path
		out.code = parsed.Errors[0].Code
	}
	return out
}

func assertGoldenProblem(t *testing.T, name string, rest restProblem, mcpRes *mcp.CallToolResult, wantStatus int, wantField string) {
	t.Helper()
	if rest.status != wantStatus {
		t.Fatalf("%s REST status %d want %d body=%s", name, rest.status, wantStatus, rest.body)
	}
	if rest.code != wantField {
		t.Fatalf("%s REST field %q want %q body=%s", name, rest.code, wantField, rest.body)
	}
	if mcpRes == nil || !mcpRes.IsError {
		t.Fatalf("%s MCP must be a tool error: %+v", name, mcpRes)
	}
	text := mcpToolText(mcpRes)
	if !strings.Contains(text, wantField) {
		t.Fatalf("%s MCP missing field %q: %s", name, wantField, text)
	}
}

func restBindOutcome(t *testing.T, p restProblem) string {
	t.Helper()
	var res directory.BindTestResult
	if err := json.Unmarshal([]byte(p.body), &res); err != nil {
		t.Fatalf("bind-test body: %v %s", err, p.body)
	}
	return res.Outcome
}

func mustToolOK(t *testing.T, h *catalogHarness, name string, args any) *mcp.CallToolResult {
	t.Helper()
	res := callMCPTool(t, h, name, args)
	if res.IsError {
		t.Fatalf("%s: %s", name, mcpToolText(res))
	}
	return res
}

func callMCPTool(t *testing.T, h *catalogHarness, name string, args any) *mcp.CallToolResult {
	t.Helper()
	res, err := h.sess.CallTool(t.Context(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
}

func mustGetUser(t *testing.T, h *catalogHarness, id string) directory.User {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+catalogITToken)
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET user %s: %d %s", id, rec.Code, rec.Body.String())
	}
	var u directory.User
	if err := json.Unmarshal(rec.Body.Bytes(), &u); err != nil {
		t.Fatal(err)
	}
	return u
}

func decodeMCP[T any](t *testing.T, res *mcp.CallToolResult) T {
	t.Helper()
	var out T
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return out
}

func mcpToolText(res *mcp.CallToolResult) string {
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

func schemaHasAttr(sch directory.Schema, name string) bool {
	for _, at := range sch.Attributes {
		if strings.EqualFold(at.Name, name) {
			return true
		}
	}
	return false
}

func sameStringSet(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

func keysOf(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
