package api

import (
	"io/fs"
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
	"github.com/hilather/go-lab-ldap-mcp/internal/web"
)

const (
	headerRequestID = "X-Request-ID"
	defaultMaxBody  = 1 << 20
)

// Limiter is the HTTP bind-test / request bucket.
type Limiter interface {
	Allow(key string) bool
}

// NopLimiter permits every key.
type NopLimiter struct{}

func (NopLimiter) Allow(string) bool { return true }

// FuncLimiter adapts a function (typically *app.Window.AllowKey).
type FuncLimiter func(string) bool

func (f FuncLimiter) Allow(key string) bool {
	if f == nil {
		return true
	}
	return f(key)
}

// Options configure the net/http management plane.
type Options struct {
	Registry        *auth.Registry
	Sessions        *auth.Store
	Ready           func() bool
	Logger          *slog.Logger
	AllowedOrigins  []string
	AllowedHosts    []string
	MaxBody         int64
	ForceSecure     bool
	MetricsAuth     bool
	MetricsEnabled  bool
	Limiter         Limiter
	System          System
	Users           Users
	Groups          Groups
	Query           Query
	Entries         Entries
	Audit           audit.Lister
	AuditHook       audit.Hook
	Diagnostics     func() app.Diagnostics
	Reset           Reset
	Export          Export
	Metrics         *observability.Registry
	Build           observability.BuildInfo
	PageSizeDefault int
	PageSizeMax     int
	CursorKey       config.CursorKey
	Assets          fs.FS
}

// Server is the REST transport. It does not import mcpserver or LDAP.
type Server struct {
	registry        *auth.Registry
	sessions        *auth.Store
	ready           func() bool
	log             *slog.Logger
	allowedOrigins  []string
	allowedHosts    []string
	maxBody         int64
	forceSecure     bool
	metricsAuth     bool
	metricsEnabled  bool
	limiter         Limiter
	system          System
	users           Users
	groups          Groups
	query           Query
	entries         Entries
	audit           audit.Lister
	auditHook       audit.Hook
	diagnostics     func() app.Diagnostics
	reset           Reset
	export          Export
	metrics         *observability.Registry
	build           observability.BuildInfo
	pageSizeDefault int
	pageSizeMax     int
	cursorKey       config.CursorKey
	assets          fs.FS
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
	assets := opt.Assets
	if assets == nil {
		assets = web.FS()
	}
	return &Server{
		registry:        opt.Registry,
		sessions:        opt.Sessions,
		ready:           ready,
		log:             log,
		allowedOrigins:  append([]string(nil), opt.AllowedOrigins...),
		allowedHosts:    append([]string(nil), opt.AllowedHosts...),
		maxBody:         maxBody,
		forceSecure:     opt.ForceSecure,
		metricsAuth:     opt.MetricsAuth,
		metricsEnabled:  opt.MetricsEnabled,
		limiter:         lim,
		system:          opt.System,
		users:           opt.Users,
		groups:          opt.Groups,
		query:           opt.Query,
		entries:         opt.Entries,
		audit:           opt.Audit,
		auditHook:       opt.AuditHook,
		diagnostics:     opt.Diagnostics,
		reset:           opt.Reset,
		export:          opt.Export,
		metrics:         opt.Metrics,
		build:           build,
		pageSizeDefault: pageDef,
		pageSizeMax:     pageMax,
		cursorKey:       append(config.CursorKey(nil), opt.CursorKey...),
		assets:          assets,
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
	// GET / is a subtree pattern: hashed assets or index.html fallback.
	mux.HandleFunc("GET /", s.handleUI)

	mux.HandleFunc("GET /api/v1/users", s.handleListUsers)
	mux.HandleFunc("POST /api/v1/users", s.handleCreateUser)
	mux.HandleFunc("GET /api/v1/users/{id}", s.handleGetUser)
	mux.HandleFunc("PATCH /api/v1/users/{id}", s.handlePatchUser)
	mux.HandleFunc("DELETE /api/v1/users/{id}", s.handleDeleteUser)
	mux.HandleFunc("POST /api/v1/users/{id}/password", s.handleSetUserPassword)
	mux.HandleFunc("POST /api/v1/users/{id}/enable", s.handleEnableUser)
	mux.HandleFunc("POST /api/v1/users/{id}/disable", s.handleDisableUser)
	mux.HandleFunc("GET /api/v1/users/{id}/account-state", s.handleGetAccountState)
	mux.HandleFunc("POST /api/v1/users/{id}/expire-password", s.handleExpirePassword)
	mux.HandleFunc("POST /api/v1/users/{id}/clear-password-expiry", s.handleClearPasswordExpiry)
	mux.HandleFunc("POST /api/v1/users/{id}/lock", s.handleLockUser)
	mux.HandleFunc("POST /api/v1/users/{id}/unlock", s.handleUnlockUser)
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
	mux.HandleFunc("GET /api/v1/suffixes", s.handleListSuffixes)
	mux.HandleFunc("POST /api/v1/tree", s.handleListTree)
	mux.HandleFunc("GET /api/v1/entries", s.handleGetEntry)
	mux.HandleFunc("POST /api/v1/entries", s.handleCreateEntry)
	mux.HandleFunc("PATCH /api/v1/entries", s.handleUpdateEntry)
	mux.HandleFunc("DELETE /api/v1/entries", s.handleDeleteEntry)
	mux.HandleFunc("POST /api/v1/entries/move", s.handleMoveEntry)
	mux.HandleFunc("POST /api/v1/auth-tests", s.handleBindTest)
	mux.HandleFunc("GET /api/v1/rootdse", s.handleRootDSE)
	mux.HandleFunc("GET /api/v1/schema", s.handleSchema)
	mux.HandleFunc("GET /api/v1/schema/objectclasses/{name}", s.handleObjectClass)
	mux.HandleFunc("GET /api/v1/schema/attributes/{name}", s.handleAttributeType)
	mux.HandleFunc("GET /api/v1/audit", s.handleListAudit)
	mux.HandleFunc("GET /api/v1/diagnostics", s.handleDiagnostics)
	mux.HandleFunc("POST /api/v1/reset", s.handleStartReset)
	mux.HandleFunc("GET /api/v1/reset", s.handleGetReset)
	mux.HandleFunc("GET /api/v1/export", s.handleExport)

	var h http.Handler = mux
	h = s.authMiddleware(h)
	h = s.corsMiddleware(h)
	h = s.hostMiddleware(h)
	h = s.securityHeaders(h)
	h = s.bodyLimit(h)
	h = s.metricsMiddleware(h)
	h = s.accessLog(h)
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
