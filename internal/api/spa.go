package api

import (
	"net/http"
	"path"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/web"
)

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.NotFound(w, r)
		return
	}
	if reservedManagementPath(r.URL.Path) {
		http.NotFound(w, r)
		return
	}
	if web.ServeAsset(s.assets, w, r) {
		return
	}
	web.ServeIndex(s.assets, w, r)
}

func reservedManagementPath(raw string) bool {
	p := path.Clean("/" + raw)
	switch {
	case p == "/health", strings.HasPrefix(p, "/health/"):
		return true
	case p == "/metrics", strings.HasPrefix(p, "/metrics/"):
		return true
	case p == "/mcp", strings.HasPrefix(p, "/mcp/"):
		return true
	case strings.HasPrefix(p, "/api/"):
		return true
	default:
		return false
	}
}
