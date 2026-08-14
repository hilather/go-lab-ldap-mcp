package api

import (
	"net/http"

	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
)

type healthBody struct {
	Status string `json:"status"`
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
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	if id := observabilityRequestID(r); id != "" {
		w.Header().Set(headerRequestID, id)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("# labldap metrics land in T-074\n"))
}
