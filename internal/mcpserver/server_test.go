package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

const (
	testToken     = "lab-test-static-token-value-32ch"
	readToken     = "lab-test-reader-token-value-32ch"
	schemaTok     = "lab-test-schema-token-value-32ch"
	writeToken    = "lab-test-writer-token-value-32ch"
	passwordToken = "lab-test-password-token-value-32"
	resetToken    = "lab-test-reset-token-value-32xxxx"
	exportToken   = "lab-test-export-token-value-32xxx"
	badSecret     = "not-the-token-value-xxxxxxxxxxxxxxx"
	mcpUserPass   = "unit-mcp-user-pass-12"
)

func testRegistry(t *testing.T) *auth.Registry {
	t.Helper()
	reg, err := auth.NewRegistry([]auth.Token{
		{ID: "admin", Scopes: []string{
			auth.ScopeDirectoryRead, auth.ScopeDirectoryWrite, auth.ScopeDirectoryPassword,
			auth.ScopeSchemaRead, auth.ScopeLabReset, auth.ScopeLabExport,
		}, Secret: observability.Secret(testToken)},
		{ID: "reader", Scopes: []string{auth.ScopeDirectoryRead}, Secret: observability.Secret(readToken)},
		{ID: "schema", Scopes: []string{auth.ScopeSchemaRead}, Secret: observability.Secret(schemaTok)},
		{ID: "writer", Scopes: []string{auth.ScopeDirectoryWrite}, Secret: observability.Secret(writeToken)},
		{ID: "password", Scopes: []string{auth.ScopeDirectoryPassword}, Secret: observability.Secret(passwordToken)},
		{ID: "resetter", Scopes: []string{auth.ScopeLabReset}, Secret: observability.Secret(resetToken)},
		{ID: "exporter", Scopes: []string{auth.ScopeLabExport}, Secret: observability.Secret(exportToken)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

type fakeSearch struct {
	mu    sync.Mutex
	calls []directory.SearchQuery
	pages []directory.SearchPage
	err   error
	hang  chan struct{}
	saw   chan struct{}
}

func (f *fakeSearch) Search(ctx context.Context, q directory.SearchQuery) (directory.SearchPage, error) {
	if f.saw != nil {
		select {
		case <-f.saw:
		default:
			close(f.saw)
		}
	}
	if f.hang != nil {
		select {
		case <-ctx.Done():
			close(f.hang)
			return directory.SearchPage{}, ctx.Err()
		case <-time.After(8 * time.Second):
			return directory.SearchPage{}, context.DeadlineExceeded
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, q)
	if f.err != nil {
		return directory.SearchPage{}, f.err
	}
	if len(f.pages) == 0 {
		return directory.SearchPage{Entries: []directory.SearchEntry{}}, nil
	}
	p := f.pages[0]
	if len(f.pages) > 1 {
		f.pages = f.pages[1:]
	}
	return p, nil
}

type fakeCaps struct {
	caps directory.Capabilities
	err  error
}

func (f fakeCaps) Capabilities(context.Context) (directory.Capabilities, error) {
	return f.caps, f.err
}

type fakeMarker struct {
	m   directory.BaselineMarker
	err error
}

func (f fakeMarker) ReadMarker(context.Context) (directory.BaselineMarker, error) {
	return f.m, f.err
}

type fakeSchema struct {
	dse directory.RootDSE
	sch directory.Schema
	err error
}

func (f fakeSchema) RootDSE(context.Context) (directory.RootDSE, error) { return f.dse, f.err }
func (f fakeSchema) Schema(context.Context) (directory.Schema, error)   { return f.sch, f.err }

func testServices(search directory.SearchRepository, caps directory.CapabilityInspector, marker directory.MarkerReader, schema directory.SchemaRepository) *app.Services {
	return app.New(app.Deps{
		Search:           search,
		Entries:          newFakeEntries(),
		Caps:             caps,
		Marker:           marker,
		Schema:           schema,
		ExpectedRevision: "aaa",
		ControlRevision:  "bbb",
	})
}

func testServer(t *testing.T, svc *app.Services) *Server {
	t.Helper()
	if svc == nil {
		svc = testServices(&fakeSearch{}, fakeCaps{caps: directory.Capabilities{EngineVendor: "389 Project"}}, fakeMarker{m: directory.BaselineMarker{AppliedRevision: "aaa"}}, fakeSchema{})
	}
	s, err := New(Options{Registry: testRegistry(t), Services: svc, MaxBody: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type bearerTransport struct {
	base  http.RoundTripper
	token string
	rid   string
}

func (t bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	if t.token != "" {
		req.Header.Set("Authorization", "Bearer "+t.token)
	}
	if t.rid != "" {
		req.Header.Set(headerRequestID, t.rid)
	}
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

func connectMCP(t *testing.T, h http.Handler, token, requestID string) (*mcp.ClientSession, *httptest.Server) {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	client := mcp.NewClient(&mcp.Implementation{Name: "labldap-test", Version: "v0.0.1"}, nil)
	sess, err := client.Connect(t.Context(), &mcp.StreamableClientTransport{
		Endpoint:             ts.URL + MountPath,
		DisableStandaloneSSE: true,
		HTTPClient: &http.Client{Transport: bearerTransport{
			base:  ts.Client().Transport,
			token: token,
			rid:   requestID,
		}},
	}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = sess.Close() })
	return sess, ts
}

func TestOfficialSDKNegotiatesStatelessProtocol(t *testing.T) {
	t.Parallel()
	s := testServer(t, nil)
	mux := http.NewServeMux()
	mux.Handle(MountPath, s.Handler())
	sess, _ := connectMCP(t, mux, testToken, "")
	res := sess.InitializeResult()
	if res == nil || res.ProtocolVersion != ProtocolVersion {
		t.Fatalf("protocol = %+v want %s", res, ProtocolVersion)
	}
	if res.ServerInfo == nil || res.ServerInfo.Name != "labldap" {
		t.Fatalf("server info = %+v", res.ServerInfo)
	}
	var names []string
	for tool, err := range sess.Tools(t.Context(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, tool.Name)
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Errorf("%s missing read-only hint", tool.Name)
		}
	}
	want := registeredReadTools()
	if strings.Join(names, ",") != strings.Join(want, ",") && !equalSet(names, want) {
		t.Fatalf("tools = %v want %v", names, want)
	}
	for _, n := range names {
		if n == ToolCreateUser || n == ToolResetSuffix {
			t.Fatalf("mutation tool registered by default: %s", n)
		}
	}
}

func TestNoLegacyUnauthenticatedSSE(t *testing.T) {
	t.Parallel()
	s := testServer(t, nil)
	mux := http.NewServeMux()
	mux.Handle(MountPath, s.Handler())
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	for _, path := range []string{MountPath, "/sse", "/mcp/sse"} {
		req, err := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Accept", "text/event-stream")
		resp, err := ts.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if path == MountPath {
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("GET %s unauthenticated = %d %s", path, resp.StatusCode, body)
			}
		} else if resp.StatusCode == http.StatusOK && strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
			t.Fatalf("legacy SSE exposed at %s", path)
		}
	}

	req, err := http.NewRequest(http.MethodGet, ts.URL+MountPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Accept", "text/event-stream")
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("authenticated GET /mcp = %d want 405 (stateless, no SSE)", resp.StatusCode)
	}
}

func TestSessionCookieWithoutBearerIs401(t *testing.T) {
	t.Parallel()
	s := testServer(t, nil)
	store := auth.NewStore(auth.DefaultSessionConfig())
	cookie, _, sess, err := store.Create("admin", directory.ScopeSet{auth.ScopeDirectoryRead})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, MountPath, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(auth.NewSessionCookie(cookie, false, 0))
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("session cookie without bearer = %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "admin") || strings.Contains(body, cookie) || strings.Contains(body, sess.ID) || strings.Contains(body, testToken) {
		t.Fatalf("leaked session identity: %s", body)
	}
}

func TestEveryRequestRequiresBearer(t *testing.T) {
	t.Parallel()
	s := testServer(t, nil)
	mux := http.NewServeMux()
	mux.Handle(MountPath, s.Handler())
	h := mux
	for _, tc := range []struct {
		name   string
		header string
	}{
		{name: "missing"},
		{name: "malformed", header: "Basic abc"},
		{name: "invalid", header: "Bearer " + badSecret},
	} {
		req := httptest.NewRequest(http.MethodPost, MountPath, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		req.Header.Set("Content-Type", "application/json")
		if tc.header != "" {
			req.Header.Set("Authorization", tc.header)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status %d %s", tc.name, rec.Code, rec.Body.String())
		}
		body := rec.Body.String()
		if strings.Contains(body, "admin") || strings.Contains(body, testToken) || strings.Contains(body, badSecret) {
			t.Fatalf("%s leaked identity: %s", tc.name, body)
		}
		if rec.Header().Get(headerRequestID) == "" {
			t.Fatalf("%s missing request id", tc.name)
		}
	}
}

func TestRequestIDInHeaderAndToolResult(t *testing.T) {
	t.Parallel()
	s := testServer(t, nil)
	mux := http.NewServeMux()
	mux.Handle(MountPath, s.Handler())
	const rid = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	sess, _ := connectMCP(t, mux, testToken, rid)
	res, err := sess.CallTool(t.Context(), &mcp.CallToolParams{Name: ToolCapabilities})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError {
		t.Fatalf("tool error: %+v", res)
	}
	got, _ := res.Meta["requestId"].(string)
	if got != rid {
		t.Fatalf("meta requestId = %q want %q (meta=%v)", got, rid, res.Meta)
	}
}

func TestHostAndOriginChecks(t *testing.T) {
	t.Parallel()
	s := testServer(t, nil)
	s.allowedOrigins = []string{"https://lab.example"}
	s.allowedHosts = []string{"127.0.0.1:8443"}
	h := s.Handler()

	post := func(host, origin string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, MountPath, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		req.Host = host
		req.Header.Set("Authorization", "Bearer "+testToken)
		req.Header.Set("Content-Type", "application/json")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if rec := post("", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("empty host = %d", rec.Code)
	}
	if rec := post("evil.example", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("bad host = %d", rec.Code)
	}
	if rec := post("127.0.0.1:8443", "https://evil.example"); rec.Code != http.StatusForbidden {
		t.Fatalf("bad origin = %d", rec.Code)
	}
	if rec := post("127.0.0.1:8443", ""); rec.Code == http.StatusForbidden || rec.Code == http.StatusUnauthorized {
		t.Fatalf("good host, no origin should pass middleware: %d %s", rec.Code, rec.Body.String())
	}
	if rec := post("127.0.0.1:8443", "https://lab.example"); rec.Code == http.StatusForbidden || rec.Code == http.StatusUnauthorized {
		t.Fatalf("allowed origin: %d %s", rec.Code, rec.Body.String())
	}
	if rec := post("192.0.2.10:8443", ""); rec.Code == http.StatusForbidden || rec.Code == http.StatusUnauthorized {
		t.Fatalf("literal IP host should pass middleware: %d %s", rec.Code, rec.Body.String())
	}
}

func TestBodyLimit(t *testing.T) {
	t.Parallel()
	s := testServer(t, nil)
	s.maxBody = 64
	h := s.Handler()
	req := httptest.NewRequest(http.MethodPost, MountPath, bytes.NewReader(bytes.Repeat([]byte("x"), 4096)))
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge && rec.Code != http.StatusBadRequest {
		t.Fatalf("oversize body = %d %s", rec.Code, rec.Body.String())
	}
}

func TestCancelledRequestCancelsSearch(t *testing.T) {
	t.Parallel()
	hang := make(chan struct{})
	saw := make(chan struct{})
	svc := testServices(&fakeSearch{hang: hang, saw: saw}, fakeCaps{}, fakeMarker{}, fakeSchema{})
	s := testServer(t, svc)
	mux := http.NewServeMux()
	mux.Handle(MountPath, s.Handler())
	sess, _ := connectMCP(t, mux, testToken, "")
	ctx, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)
	go func() {
		_, err := sess.CallTool(ctx, &mcp.CallToolParams{
			Name:      ToolSearch,
			Arguments: directory.SearchQuery{Filter: "(uid=alice)"},
		})
		errCh <- err
	}()
	select {
	case <-saw:
	case <-time.After(3 * time.Second):
		t.Fatal("search did not start")
	}
	cancel()
	select {
	case <-hang:
	case <-time.After(3 * time.Second):
		t.Fatal("downstream search was not cancelled")
	}
	select {
	case <-errCh:
	case <-time.After(3 * time.Second):
		t.Fatal("client call did not return")
	}
}

func TestDisabledHandler(t *testing.T) {
	t.Parallel()
	h := Disabled(testRegistry(t))
	req := httptest.NewRequest(http.MethodPost, MountPath, strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("disabled without bearer = %d", rec.Code)
	}
	req = httptest.NewRequest(http.MethodPost, MountPath, strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("disabled with bearer = %d %s", rec.Code, rec.Body.String())
	}
}

func TestHostsFromListen(t *testing.T) {
	t.Parallel()
	got := HostsFromListen("127.0.0.1:8443")
	if !auth.HostAllowed("127.0.0.1:8443", got) || !auth.HostAllowed("localhost:8443", got) {
		t.Fatalf("loopback listen = %v", got)
	}
	all := HostsFromListen("0.0.0.0:8443")
	if !auth.HostAllowed("127.0.0.1:8443", all) || auth.HostAllowed("evil.test", all) {
		t.Fatalf("bind-all must allow-list loopback hosts, got %v", all)
	}
	if len(HostsFromListen("10.0.0.5:9000")) != 1 || HostsFromListen("10.0.0.5:9000")[0] != "10.0.0.5:9000" {
		t.Fatalf("public listen = %v", HostsFromListen("10.0.0.5:9000"))
	}
}

func TestProtocolRecord(t *testing.T) {
	t.Parallel()
	if SDKVersion != "v1.7.0" || ProtocolVersion != "2026-07-28" || !Stateless {
		t.Fatalf("OD-015 pin: %s %s stateless=%v", SDKVersion, ProtocolVersion, Stateless)
	}
	if RPCDiscover != "server/discover" || MountPath != "/mcp" {
		t.Fatal("RPC record")
	}
}

func equalSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, x := range a {
		seen[x]++
	}
	for _, x := range b {
		seen[x]--
		if seen[x] < 0 {
			return false
		}
	}
	return true
}

func decodeStructured[T any](t *testing.T, res *mcp.CallToolResult) T {
	t.Helper()
	var out T
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("structured %s: %v", raw, err)
	}
	return out
}
