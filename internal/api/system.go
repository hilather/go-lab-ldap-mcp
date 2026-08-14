package api

import (
	"context"
	"net/http"

	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

// System is the application surface for capability and baseline reads.
// *app.Query implements it. Transports must not inspect LDAP themselves.
type System interface {
	Capabilities(ctx context.Context, p app.Principal) (directory.Capabilities, error)
	Baseline(ctx context.Context, p app.Principal) (app.Baseline, error)
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, auth.ScopeDirectoryRead); !ok {
		return
	}
	setNoStore(w)
	writeJSON(w, r, http.StatusOK, "application/json", s.build)
}

func (s *Server) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireScope(w, r, auth.ScopeDirectoryRead)
	if !ok {
		return
	}
	if s.system == nil {
		writeProblemStatus(w, r, http.StatusServiceUnavailable, "directory", "not ready", nil)
		return
	}
	caps, err := s.system.Capabilities(r.Context(), p)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	setNoStore(w)
	writeJSON(w, r, http.StatusOK, "application/json", capabilitiesBody(caps))
}

func (s *Server) handleBaseline(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireScope(w, r, auth.ScopeDirectoryRead)
	if !ok {
		return
	}
	if s.system == nil {
		writeProblemStatus(w, r, http.StatusServiceUnavailable, "directory", "not ready", nil)
		return
	}
	b, err := s.system.Baseline(r.Context(), p)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	setNoStore(w)
	writeJSON(w, r, http.StatusOK, "application/json", b)
}

func (s *Server) requireScope(w http.ResponseWriter, r *http.Request, scope string) (app.Principal, bool) {
	p, ok := auth.PrincipalFrom(r.Context())
	if !ok {
		writeProblem(w, r, auth.AuthRequired())
		return app.Principal{}, false
	}
	if err := auth.Require(p.Scopes, scope); err != nil {
		writeProblem(w, r, err)
		return app.Principal{}, false
	}
	return app.Principal{Kind: p.Kind, ID: p.ID, Scopes: p.Scopes}, true
}

func capabilitiesBody(c directory.Capabilities) directory.Capabilities {
	if c.Transports == nil {
		c.Transports = []string{}
	}
	if c.Plugins == nil {
		c.Plugins = []string{}
	}
	if c.Controls == nil {
		c.Controls = []string{}
	}
	return c
}

func setNoStore(w http.ResponseWriter) {
	if w != nil {
		w.Header().Set("Cache-Control", "no-store")
	}
}

func writeNoContent(w http.ResponseWriter, r *http.Request) {
	setNoStore(w)
	if id := requestIDOf(r); id != "" {
		w.Header().Set(headerRequestID, id)
	}
	w.WriteHeader(http.StatusNoContent)
}

// currentBuild is used when Options.Build is empty.
func currentBuild() observability.BuildInfo {
	return observability.CurrentBuild("labldap")
}
