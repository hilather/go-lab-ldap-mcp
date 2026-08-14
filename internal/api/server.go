package api

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/audit"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

const (
	headerRequestID = "X-Request-ID"
	defaultMaxBody  = 1 << 20
)

// Limiter is the T-063 rate-limit framework. T-074 fills real buckets.
type Limiter interface {
	Allow(key string) bool
}

// NopLimiter permits every key.
type NopLimiter struct{}

func (NopLimiter) Allow(string) bool { return true }

// Options configure the net/http management plane.
type Options struct {
	Registry        *auth.Registry
	Sessions        *auth.Store
	Ready           func() bool
	Logger          *slog.Logger
	AllowedOrigins  []string
	MaxBody         int64
	ForceSecure     bool
	MetricsAuth     bool
	MetricsEnabled  bool
	Limiter         Limiter
	System          System
	Users           Users
	Groups          Groups
	Query           Query
	Audit           audit.Lister
	AuditHook       audit.Hook
	Diagnostics     func() app.Diagnostics
	Metrics         *observability.Registry
	Build           observability.BuildInfo
	PageSizeDefault int
	PageSizeMax     int
	CursorKey       config.CursorKey
}

// Server is the REST transport. It does not import mcpserver or LDAP.
type Server struct {
	registry        *auth.Registry
	sessions        *auth.Store
	ready           func() bool
	log             *slog.Logger
	allowedOrigins  []string
	maxBody         int64
	forceSecure     bool
	metricsAuth     bool
	metricsEnabled  bool
	limiter         Limiter
	system          System
	users           Users
	groups          Groups
	query           Query
	audit           audit.Lister
	auditHook       audit.Hook
	diagnostics     func() app.Diagnostics
	metrics         *observability.Registry
	build           observability.BuildInfo
	pageSizeDefault int
	pageSizeMax     int
	cursorKey       config.CursorKey
}

func New(opt Options) (*Server, error) {
	for _, o := range opt.AllowedOrigins {
		if strings.TrimSpace(o) == "*" {
			return nil, apperr.New(apperr.CodeConfiguration, "wildcard credentialed CORS is impossible").
				WithField(apperr.Field{Path: "spec.management.cors.allowedOrigins", Code: "insecure", Message: "wildcard origin cannot be used with cookies"})
		}
	}
	maxBody := opt.MaxBody
	if maxBody <= 0 {
		maxBody = defaultMaxBody
	}
	ready := opt.Ready
	if ready == nil {
		ready = func() bool { return false }
	}
	log := opt.Logger
	if log == nil {
		log = slog.Default()
	}
	lim := opt.Limiter
	if lim == nil {
		lim = NopLimiter{}
	}
	build := opt.Build
	if build.Component == "" {
		build = currentBuild()
	}
	pageDef := opt.PageSizeDefault
	if pageDef <= 0 {
		pageDef = defaultPageSize
	}
	pageMax := opt.PageSizeMax
	if pageMax <= 0 {
		pageMax = defaultPageMax
	}
	return &Server{
		registry:        opt.Registry,
		sessions:        opt.Sessions,
		ready:           ready,
		log:             log,
		allowedOrigins:  append([]string(nil), opt.AllowedOrigins...),
		maxBody:         maxBody,
		forceSecure:     opt.ForceSecure,
		metricsAuth:     opt.MetricsAuth,
		metricsEnabled:  opt.MetricsEnabled,
		limiter:         lim,
		system:          opt.System,
		users:           opt.Users,
		groups:          opt.Groups,
		query:           opt.Query,
		audit:           opt.Audit,
		auditHook:       opt.AuditHook,
		diagnostics:     opt.Diagnostics,
		metrics:         opt.Metrics,
		build:           build,
		pageSizeDefault: pageDef,
		pageSizeMax:     pageMax,
		cursorKey:       append(config.CursorKey(nil), opt.CursorKey...),
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleLive)
	mux.HandleFunc("GET /health/ready", s.handleReady)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("GET /api/v1/version", s.handleVersion)
	mux.HandleFunc("GET /api/v1/capabilities", s.handleCapabilities)
	mux.HandleFunc("GET /api/v1/baseline", s.handleBaseline)
	mux.HandleFunc("POST /api/v1/session", s.handleCreateSession)
	mux.HandleFunc("GET /api/v1/session", s.handleGetSession)
	mux.HandleFunc("DELETE /api/v1/session", s.handleDeleteSession)

	mux.HandleFunc("GET /api/v1/users", s.handleListUsers)
	mux.HandleFunc("POST /api/v1/users", s.handleCreateUser)
	mux.HandleFunc("GET /api/v1/users/{id}", s.handleGetUser)
	mux.HandleFunc("PATCH /api/v1/users/{id}", s.handlePatchUser)
	mux.HandleFunc("DELETE /api/v1/users/{id}", s.handleDeleteUser)
	mux.HandleFunc("POST /api/v1/users/{id}/password", s.handleSetUserPassword)
	mux.HandleFunc("POST /api/v1/users/{id}/enable", s.handleEnableUser)
	mux.HandleFunc("POST /api/v1/users/{id}/disable", s.handleDisableUser)
	mux.HandleFunc("GET /api/v1/users/{id}/groups", s.handleListUserGroups)

	// No PATCH /api/v1/groups/{id} in v1 — membership writes are the update path.
	mux.HandleFunc("GET /api/v1/groups", s.handleListGroups)
	mux.HandleFunc("POST /api/v1/groups", s.handleCreateGroup)
	mux.HandleFunc("GET /api/v1/groups/{id}", s.handleGetGroup)
	mux.HandleFunc("DELETE /api/v1/groups/{id}", s.handleDeleteGroup)
	mux.HandleFunc("POST /api/v1/groups/{id}/members", s.handleAddGroupMembers)
	mux.HandleFunc("DELETE /api/v1/groups/{id}/members", s.handleRemoveGroupMembers)
	mux.HandleFunc("PUT /api/v1/groups/{id}/members", s.handleReplaceGroupMembers)

	mux.HandleFunc("POST /api/v1/search", s.handleSearch)
	mux.HandleFunc("POST /api/v1/auth-tests", s.handleBindTest)
	mux.HandleFunc("GET /api/v1/rootdse", s.handleRootDSE)
	mux.HandleFunc("GET /api/v1/schema", s.handleSchema)
	mux.HandleFunc("GET /api/v1/schema/objectclasses/{name}", s.handleObjectClass)
	mux.HandleFunc("GET /api/v1/schema/attributes/{name}", s.handleAttributeType)
	mux.HandleFunc("GET /api/v1/audit", s.handleListAudit)
	mux.HandleFunc("GET /api/v1/diagnostics", s.handleDiagnostics)

	var h http.Handler = mux
	h = s.authMiddleware(h)
	h = s.corsMiddleware(h)
	h = s.securityHeaders(h)
	h = s.bodyLimit(h)
	h = s.metricsMiddleware(h)
	h = s.requestID(h)
	h = s.recoverPanic(h)
	return h
}

func (s *Server) Timeouts(request, shutdown time.Duration) (read, write, idle, stop time.Duration) {
	if request <= 0 {
		request = 30 * time.Second
	}
	if shutdown <= 0 {
		shutdown = 15 * time.Second
	}
	return request, request, 60 * time.Second, shutdown
}

func writeJSON(w http.ResponseWriter, r *http.Request, status int, contentType string, v any) {
	if contentType == "" {
		contentType = "application/json"
	}
	b, err := encodeJSON(v)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	if r != nil {
		if id := observability.RequestID(r.Context()); id != "" {
			w.Header().Set(headerRequestID, id)
		}
	}
	w.WriteHeader(status)
	_, _ = w.Write(b)
}
