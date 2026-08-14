package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
	"github.com/hilather/go-lab-ldap-mcp/internal/reset"
)

const (
	resetToken = "lab-test-reset-token-value-32xxxx"
	resetWrite = "lab-test-write-token-value-32xxxxx"
)

func resetServer(t *testing.T) (*Server, *app.Services, *liveAPIReset) {
	t.Helper()
	users := newMemUsers()
	groups := newMemGroups()
	inv := newLiveAPIReset(users, groups)
	gate := reset.NewGate()
	svc := app.New(app.Deps{
		Users:            users,
		Groups:           groups,
		Gate:             gate,
		ResetLock:        gate,
		ResetDir:         inv,
		SoftReset:        true,
		ScenarioName:     "lab",
		ExpectedRevision: "rev-dir",
		PeopleDN:         "ou=people,dc=example,dc=test",
		GroupsDN:         "ou=groups,dc=example,dc=test",
		Suffix:           "dc=example,dc=test",
		ResetUsers:       nil,
		ResetGroups:      nil,
		Marker:           stubMarker{m: directory.BaselineMarker{AppliedRevision: "rev-dir"}},
	})
	reg, err := auth.NewRegistry([]auth.Token{
		{ID: "resetter", Scopes: []string{auth.ScopeLabReset, auth.ScopeDirectoryRead, auth.ScopeDirectoryWrite}, Secret: observability.Secret(resetToken)},
		{ID: "writer", Scopes: []string{auth.ScopeDirectoryWrite}, Secret: observability.Secret(resetWrite)},
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{
		Registry: reg,
		Sessions: auth.NewStore(auth.DefaultSessionConfig()),
		Users:    svc.Users,
		Groups:   svc.Groups,
		Reset:    svc.Reset,
		Export:   svc.Export,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, svc, inv
}

func TestResetWriteScopeDeniedAndWrongConfirmation(t *testing.T) {
	t.Parallel()
	s, _, inv := resetServer(t)
	h := s.Handler()

	deny := httptest.NewRequest(http.MethodPost, "/api/v1/reset", strings.NewReader(`{"name":"lab","expectedRevision":"rev-dir"}`))
	deny.Header.Set("Authorization", "Bearer "+resetWrite)
	deny.Header.Set("Content-Type", "application/json")
	dr := httptest.NewRecorder()
	h.ServeHTTP(dr, deny)
	if dr.Code != http.StatusForbidden {
		t.Fatalf("write without lab:reset %d %s", dr.Code, dr.Body.String())
	}

	wrong := httptest.NewRequest(http.MethodPost, "/api/v1/reset", strings.NewReader(`{"name":"other","expectedRevision":"rev-dir"}`))
	wrong.Header.Set("Authorization", "Bearer "+resetToken)
	wrong.Header.Set("Content-Type", "application/json")
	wr := httptest.NewRecorder()
	h.ServeHTTP(wr, wrong)
	if wr.Code != http.StatusConflict {
		t.Fatalf("wrong name %d %s", wr.Code, wr.Body.String())
	}
	rev := httptest.NewRequest(http.MethodPost, "/api/v1/reset", strings.NewReader(`{"name":"lab","expectedRevision":"nope"}`))
	rev.Header.Set("Authorization", "Bearer "+resetToken)
	rev.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, rev)
	if rr.Code != http.StatusConflict {
		t.Fatalf("wrong rev %d %s", rr.Code, rr.Body.String())
	}
	if len(inv.deleted) != 0 {
		t.Fatalf("mutated %v", inv.deleted)
	}

	get := httptest.NewRequest(http.MethodGet, "/api/v1/reset", nil)
	get.Header.Set("Authorization", "Bearer "+resetToken)
	gr := httptest.NewRecorder()
	h.ServeHTTP(gr, get)
	if gr.Code != http.StatusOK {
		t.Fatalf("get %d %s", gr.Code, gr.Body.String())
	}
	if !strings.Contains(gr.Body.String(), `"state":"Ready"`) {
		t.Fatalf("status %s", gr.Body.String())
	}
}

func TestResetDuplicateReturnsCurrentOperation(t *testing.T) {
	t.Parallel()
	s, _, inv := resetServer(t)
	block := make(chan struct{}, 1)
	unblock := make(chan struct{})
	inv.block = block
	inv.unblock = unblock
	h := s.Handler()

	done := make(chan int, 1)
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/reset", strings.NewReader(`{"name":"lab","expectedRevision":"rev-dir"}`))
		req.Header.Set("Authorization", "Bearer "+resetToken)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		done <- rec.Code
	}()
	<-block
	dup := httptest.NewRequest(http.MethodPost, "/api/v1/reset", strings.NewReader(`{"name":"lab","expectedRevision":"rev-dir"}`))
	dup.Header.Set("Authorization", "Bearer "+resetToken)
	dup.Header.Set("Content-Type", "application/json")
	dr := httptest.NewRecorder()
	h.ServeHTTP(dr, dup)
	if dr.Code != http.StatusConflict {
		t.Fatalf("duplicate %d %s", dr.Code, dr.Body.String())
	}
	if !strings.Contains(dr.Body.String(), `"state"`) || strings.Contains(dr.Body.String(), "password") {
		t.Fatalf("duplicate body %s", dr.Body.String())
	}
	var st app.ResetStatus
	if err := json.Unmarshal(dr.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.State == string(reset.Ready) {
		t.Fatalf("expected in-progress %+v", st)
	}
	close(unblock)
	if code := <-done; code != http.StatusAccepted {
		t.Fatalf("first reset %d", code)
	}
}

type liveAPIReset struct {
	mu        sync.Mutex
	users     *memUsers
	groups    *memGroups
	deleted   []string
	extraGone bool
	block     chan struct{}
	unblock   chan struct{}
}

func newLiveAPIReset(users *memUsers, groups *memGroups) *liveAPIReset {
	return &liveAPIReset{users: users, groups: groups}
}

func (f *liveAPIReset) Inventory(context.Context) (directory.ManagedInventory, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var extra []string
	if !f.extraGone {
		extra = []string{"uid=runtime-extra,ou=people,dc=example,dc=test"}
	}
	return directory.ManagedInventory{Extra: extra}, nil
}

func (f *liveAPIReset) DeleteManaged(_ context.Context, dn string) error {
	f.mu.Lock()
	block, unblock := f.block, f.unblock
	f.block, f.unblock = nil, nil
	f.mu.Unlock()
	if block != nil {
		block <- struct{}{}
		if unblock != nil {
			<-unblock
		}
	}
	f.mu.Lock()
	f.deleted = append(f.deleted, dn)
	if strings.Contains(dn, "runtime-extra") {
		f.extraGone = true
	}
	f.mu.Unlock()
	return nil
}

func (f *liveAPIReset) Export(ctx context.Context, w io.Writer, opts directory.ExportOptions) error {
	enc := directory.NewEncoder(w, opts)
	return enc.Close()
}
