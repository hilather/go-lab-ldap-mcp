package api

import (
	"net/http"

	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
)

type healthBody struct {
	Status string `json:"status"`
}

type diagnosticsBody struct {
	Ready       bool          `json:"ready"`
	MarkerMatch bool          `json:"markerMatch"`
	Pool        app.PoolView  `json:"pool"`
	Reset       app.ResetHint `json:"reset"`
}

func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	// Liveness must not consult LDAP or readiness.
	writeJSON(w, r, http.StatusOK, "application/json", healthBody{Status: "live"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if s.ready != nil && s.ready() {
		writeJSON(w, r, http.StatusOK, "application/json", healthBody{Status: "ready"})
		return
	}
	writeProblemStatus(w, r, http.StatusServiceUnavailable, "directory", "not ready", nil)
}

func (s *Server) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	if _, ok := auth.PrincipalFrom(r.Context()); !ok {
		writeProblem(w, r, auth.AuthRequired())
		return
	}
	d := app.Diagnostics{Reset: app.ResetHint{State: "Ready"}}
	if s.diagnostics != nil {
		d = s.diagnostics()
	}
	if d.Reset.State == "" {
		d.Reset.State = "Ready"
	}
	setNoStore(w)
	writeJSON(w, r, http.StatusOK, "application/json", diagnosticsBody{
		Ready: d.Ready, MarkerMatch: d.MarkerMatch, Pool: d.Pool, Reset: d.Reset,
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if !s.metricsEnabled {
		writeProblemStatus(w, r, http.StatusNotFound, "configuration", "metrics disabled", nil)
		return
	}
	if s.metricsAuth {
		if _, ok := auth.PrincipalFrom(r.Context()); !ok {
			writeProblem(w, r, auth.AuthRequired())
			return
		}
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if id := observabilityRequestID(r); id != "" {
		w.Header().Set(headerRequestID, id)
	}
	w.WriteHeader(http.StatusOK)
	if s.metrics != nil {
		s.metrics.WritePrometheus(w)
		return
	}
	_, _ = w.Write([]byte("# no metrics registry\n"))
}
