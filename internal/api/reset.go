package api

import (
	"context"
	"net/http"

	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/reset"
)

// Reset is the application reset surface. *app.Reset implements it.
type Reset interface {
	Start(ctx context.Context, p app.Principal, req app.ResetRequest) (app.ResetStatus, error)
	Current(ctx context.Context, p app.Principal) (app.ResetStatus, error)
	Status() app.ResetStatus
}

func (s *Server) handleStartReset(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireScope(w, r, auth.ScopeLabReset)
	if !ok || !s.requireReset(w, r) || !requireJSONBody(w, r) {
		return
	}
	if err := s.allowReset(r, p); err != nil {
		writeProblem(w, r, err)
		return
	}
	var body app.ResetRequest
	if err := DecodeJSON(r.Body, &body); err != nil {
		writeProblem(w, r, err)
		return
	}
	st, err := s.reset.Start(r.Context(), p, body)
	if err != nil {
		if isDuplicateReset(err, st) {
			// Duplicate in-progress: 409 with the current operation.
			setNoStore(w)
			writeJSON(w, r, http.StatusConflict, "application/json", resetView(st))
			return
		}
		writeProblem(w, r, err)
		return
	}
	setNoStore(w)
	writeJSON(w, r, http.StatusAccepted, "application/json", resetView(st))
}

func (s *Server) handleGetReset(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireScope(w, r, auth.ScopeLabReset)
	if !ok || !s.requireReset(w, r) {
		return
	}
	st, err := s.reset.Current(r.Context(), p)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	setNoStore(w)
	writeJSON(w, r, http.StatusOK, "application/json", resetView(st))
}

func (s *Server) requireReset(w http.ResponseWriter, r *http.Request) bool {
	if s == nil || s.reset == nil {
		writeProblemStatus(w, r, http.StatusServiceUnavailable, "reset", "not ready", nil)
		return false
	}
	return true
}

func (s *Server) allowReset(r *http.Request, p app.Principal) error {
	if s == nil || s.limiter == nil {
		return nil
	}
	if !s.limiter.Allow("reset:ip:" + requestIP(r)) {
		return rateLimited()
	}
	if p.ID != "" && !s.limiter.Allow("reset:actor:"+p.ID) {
		return rateLimited()
	}
	return nil
}

func resetView(st app.ResetStatus) app.ResetStatus {
	return st
}

func isDuplicateReset(err error, st app.ResetStatus) bool {
	if st.State == "" || st.State == string(reset.Ready) {
		return false
	}
	for _, f := range fieldsOf(err) {
		if f.Path == "reset" && f.Code == "conflict" {
			return true
		}
	}
	return false
}
