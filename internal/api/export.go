package api

import (
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

const exportFilename = "labldap-export.ldif"

// Export is the application export surface. *app.Export implements it.
type Export interface {
	Write(ctx context.Context, p app.Principal, w io.Writer, req app.ExportRequest) error
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireScope(w, r, auth.ScopeLabExport)
	if !ok || !s.requireExport(w, r) {
		return
	}
	omit, err := parseOmitSecrets(r)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	cw := &countingWriter{w: w}
	req := app.ExportRequest{OmitSecrets: &omit}
	// Headers before the first byte so a pre-write limit error can
	// still become Problem Details.
	setExportHeaders(w)
	err = s.export.Write(r.Context(), p, cw, req)
	if err != nil {
		if cw.n == 0 {
			writeProblem(w, r, err)
			return
		}
		_, _ = io.WriteString(w, "\n"+directory.LDIFAbortMark+"\n")
		return
	}
}

func (s *Server) requireExport(w http.ResponseWriter, r *http.Request) bool {
	if s == nil || s.export == nil {
		writeProblemStatus(w, r, http.StatusServiceUnavailable, "export", "not ready", nil)
		return false
	}
	return true
}

func parseOmitSecrets(r *http.Request) (bool, error) {
	if r == nil || r.URL == nil {
		return true, nil
	}
	raw := strings.TrimSpace(r.URL.Query().Get("omitSecrets"))
	if raw == "" {
		return true, nil
	}
	switch strings.ToLower(raw) {
	case "true", "1", "yes":
		return true, nil
	case "false", "0", "no":
		return false, nil
	default:
		return true, apperr.New(apperr.CodeConfiguration, "omitSecrets is invalid").
			WithField(apperr.Field{Path: "omitSecrets", Code: "invalid", Message: "omitSecrets must be true or false"})
	}
}

func setExportHeaders(w http.ResponseWriter) {
	setNoStore(w)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+exportFilename+`"`)
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	if c == nil || c.w == nil {
		return 0, io.ErrClosedPipe
	}
	if hw, ok := c.w.(http.ResponseWriter); ok && c.n == 0 {
		hw.WriteHeader(http.StatusOK)
		if f, ok := hw.(http.Flusher); ok {
			f.Flush()
		}
	}
	n, err := c.w.Write(p)
	c.n += int64(n)
	if f, ok := c.w.(http.Flusher); ok {
		f.Flush()
	}
	return n, err
}
