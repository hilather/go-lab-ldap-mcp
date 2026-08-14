package api

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

const exportToken = "lab-test-export-token-value-32xxx"

type scriptedExport struct {
	entries []directory.SearchEntry
	started chan struct{}
	block   chan struct{}
	reads   int
}

func (s *scriptedExport) Inventory(context.Context) (directory.ManagedInventory, error) {
	return directory.ManagedInventory{}, nil
}
func (s *scriptedExport) DeleteManaged(context.Context, string) error { return nil }

func (s *scriptedExport) Export(ctx context.Context, w io.Writer, opts directory.ExportOptions) error {
	if opts.MaxEntries > 0 && len(s.entries) > opts.MaxEntries {
		return directory.ExportLimit("export.entries", "export entry limit exceeded")
	}
	enc := directory.NewEncoder(w, opts)
	for _, e := range s.entries {
		if s.started != nil {
			select {
			case s.started <- struct{}{}:
			default:
			}
		}
		if s.block != nil {
			select {
			case <-s.block:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		s.reads++
		if err := enc.WriteEntry(ctx, e); err != nil {
			return err
		}
	}
	return enc.Close()
}

func exportServer(t *testing.T, dir directory.ResetSupport, maxEntries int) *Server {
	t.Helper()
	svc := app.New(app.Deps{
		Users:            newMemUsers(),
		Groups:           newMemGroups(),
		ResetDir:         dir,
		ExportMaxEntries: maxEntries,
		SoftReset:        true,
		ScenarioName:     "lab",
		ExpectedRevision: "rev-dir",
	})
	reg, err := auth.NewRegistry([]auth.Token{
		{ID: "exporter", Scopes: []string{auth.ScopeLabExport}, Secret: observability.Secret(exportToken)},
		{ID: "writer", Scopes: []string{auth.ScopeDirectoryWrite}, Secret: observability.Secret(resetWrite)},
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{
		Registry: reg,
		Sessions: auth.NewStore(auth.DefaultSessionConfig()),
		Reset:    svc.Reset,
		Export:   svc.Export,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestExportRequiresScopeAndSetsSafeHeaders(t *testing.T) {
	t.Parallel()
	src := &scriptedExport{entries: []directory.SearchEntry{{
		DN: "uid=alice,ou=people,dc=example,dc=test",
		Attributes: []directory.AttrKV{
			{Name: "uid", Value: "alice"},
			{Name: "userPassword", Value: "unit-export-secret-12"},
		},
	}}}
	s := exportServer(t, src, 0)
	h := s.Handler()

	deny := httptest.NewRequest(http.MethodGet, "/api/v1/export", nil)
	deny.Header.Set("Authorization", "Bearer "+resetWrite)
	dr := httptest.NewRecorder()
	h.ServeHTTP(dr, deny)
	if dr.Code != http.StatusForbidden {
		t.Fatalf("write without lab:export %d %s", dr.Code, dr.Body.String())
	}

	ok := httptest.NewRequest(http.MethodGet, "/api/v1/export", nil)
	ok.Header.Set("Authorization", "Bearer "+exportToken)
	or := httptest.NewRecorder()
	h.ServeHTTP(or, ok)
	if or.Code != http.StatusOK {
		t.Fatalf("export %d %s", or.Code, or.Body.String())
	}
	if or.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache %q", or.Header().Get("Cache-Control"))
	}
	if !strings.Contains(or.Header().Get("Content-Disposition"), `filename="labldap-export.ldif"`) {
		t.Fatalf("disposition %q", or.Header().Get("Content-Disposition"))
	}
	if !strings.HasPrefix(or.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("type %q", or.Header().Get("Content-Type"))
	}
	body := or.Body.String()
	if strings.Contains(body, "unit-export-secret-12") || strings.Contains(strings.ToLower(body), "userpassword") {
		t.Fatalf("secret leaked:\n%s", body)
	}
	if !strings.Contains(body, directory.LDIFCompleteMark) {
		t.Fatalf("missing complete mark:\n%s", body)
	}
	got, err := directory.ParseLDIF(bytes.NewReader(or.Body.Bytes()))
	if err != nil || len(got) != 1 || got[0].DN != "uid=alice,ou=people,dc=example,dc=test" {
		t.Fatalf("parse %+v %v", got, err)
	}
}

func TestExportLimitIsNotCompleteOutput(t *testing.T) {
	t.Parallel()
	src := &scriptedExport{entries: []directory.SearchEntry{
		{DN: "uid=a,dc=example,dc=test", Attributes: []directory.AttrKV{{Name: "uid", Value: "a"}}},
		{DN: "uid=b,dc=example,dc=test", Attributes: []directory.AttrKV{{Name: "uid", Value: "b"}}},
	}}
	s := exportServer(t, src, 1)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/export", nil)
	req.Header.Set("Authorization", "Bearer "+exportToken)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("limit %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), directory.LDIFCompleteMark) {
		t.Fatalf("complete mark on limit: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "limit") {
		t.Fatalf("expected limit problem: %s", rec.Body.String())
	}
}

func TestExportClientDisconnectCancels(t *testing.T) {
	t.Parallel()
	started := make(chan struct{}, 1)
	block := make(chan struct{})
	src := &scriptedExport{
		started: started,
		block:   block,
		entries: []directory.SearchEntry{
			{DN: "uid=a,dc=example,dc=test", Attributes: []directory.AttrKV{{Name: "uid", Value: "a"}}},
			{DN: "uid=b,dc=example,dc=test", Attributes: []directory.AttrKV{{Name: "uid", Value: "b"}}},
		},
	}
	s := exportServer(t, src, 0)
	ctx, cancel := context.WithCancel(t.Context())
	req := httptest.NewRequest(http.MethodGet, "/api/v1/export", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+exportToken)
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		s.Handler().ServeHTTP(rec, req)
		close(done)
	}()
	<-started
	cancel()
	<-done
	if src.reads > 1 {
		t.Fatalf("continued after cancel: reads=%d", src.reads)
	}
}
