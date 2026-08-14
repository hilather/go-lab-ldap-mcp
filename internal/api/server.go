package api

import (
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
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
	Registry       *auth.Registry
	Sessions       *auth.Store
	Ready          func() bool
	Logger         *slog.Logger
	AllowedOrigins []string
	MaxBody        int64
	ForceSecure    bool
	MetricsAuth    bool
	MetricsEnabled bool
	Limiter        Limiter
}

// Server is the REST transport. It does not import mcpserver or LDAP.
type Server struct {
	registry       *auth.Registry
	sessions       *auth.Store
	ready          func() bool
	log            *slog.Logger
	allowedOrigins []string
	maxBody        int64
	forceSecure    bool
	metricsAuth    bool
	metricsEnabled bool
	limiter        Limiter
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
	return &Server{
		registry:       opt.Registry,
		sessions:       opt.Sessions,
		ready:          ready,
		log:            log,
		allowedOrigins: append([]string(nil), opt.AllowedOrigins...),
		maxBody:        maxBody,
		forceSecure:    opt.ForceSecure,
		metricsAuth:    opt.MetricsAuth,
		metricsEnabled: opt.MetricsEnabled,
		limiter:        lim,
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleLive)
	mux.HandleFunc("GET /health/ready", s.handleReady)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("POST /api/v1/session", s.handleCreateSession)
	mux.HandleFunc("GET /api/v1/session", s.handleGetSession)
	mux.HandleFunc("DELETE /api/v1/session", s.handleDeleteSession)

	var h http.Handler = mux
	h = s.authMiddleware(h)
	h = s.corsMiddleware(h)
	h = s.securityHeaders(h)
	h = s.bodyLimit(h)
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
