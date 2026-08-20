package mcpserver

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

// Options configure the Streamable HTTP MCP transport.
type Options struct {
	Registry       *auth.Registry
	Services       *app.Services
	Logger         *slog.Logger
	AllowedOrigins []string
	AllowedHosts   []string
	MaxBody        int64
	Flags          RegisterFlags
}

// Server is the MCP transport. It does not import internal/api or LDAP.
type Server struct {
	registry       *auth.Registry
	svc            *app.Services
	log            *slog.Logger
	allowedOrigins []string
	allowedHosts   []string
	maxBody        int64
	flags          RegisterFlags
	inner          http.Handler
	mcp            *mcp.Server
	actor          auth.Principal
}

func New(opt Options) (*Server, error) {
	if err := ValidateCatalog(); err != nil {
		return nil, apperr.New(apperr.CodeConfiguration, "invalid MCP catalog").Wrap(err)
	}
	log := opt.Logger
	if log == nil {
		log = slog.Default()
	}
	maxBody := opt.MaxBody
	if maxBody <= 0 {
		maxBody = defaultMaxBodyBytes
	}
	s := &Server{
		registry:       opt.Registry,
		svc:            opt.Services,
		log:            log,
		allowedOrigins: append([]string(nil), opt.AllowedOrigins...),
		allowedHosts:   append([]string(nil), opt.AllowedHosts...),
		maxBody:        maxBody,
		flags:          opt.Flags,
	}
	impl := observability.CurrentBuild("labldap")
	ms := mcp.NewServer(&mcp.Implementation{
		Name:        "labldap",
		Title:       "LabLDAP",
		Version:     impl.Version,
		Description: "LabLDAP directory control plane (Streamable HTTP, spec " + ProtocolVersion + ", Stateless)",
	}, nil)
	s.registerTools(ms)
	s.registerResources(ms)
	s.mcp = ms
	s.inner = mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server {
		return ms
	}, &mcp.StreamableHTTPOptions{
		Stateless:                    Stateless,
		Logger:                       log,
		MaxRequestBodyBytes:          maxBody,
		PropagateRequestCancellation: true,
	})
	return s, nil
}

func (s *Server) Handler() http.Handler {
	var h http.Handler = s.inner
	h = s.requireBearer(h)
	h = s.hostOrigin(h)
	h = s.bodyLimit(h)
	h = s.requestID(h)
	h = s.recoverPanic(h)
	return h
}

// Disabled returns /mcp when the transport is off. Every request still
// requires a valid bearer (T-086); a valid token then gets 501.
func Disabled(reg *auth.Registry) http.Handler {
	s := &Server{registry: reg, maxBody: defaultMaxBodyBytes}
	h := http.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeProblem(w, r, http.StatusNotImplemented, "internal", "MCP transport not registered")
	}))
	h = s.requireBearer(h)
	h = s.requestID(h)
	return h
}

// HostsFromListen builds the MCP Host allowlist from spec.management.listen.
// Bind-all and loopback listens share the published loopback Host list.
func HostsFromListen(listen string) []string {
	listen = strings.TrimSpace(listen)
	if listen == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return []string{listen}
	}
	if hosts := auth.LoopbackHosts(listen); len(hosts) > 0 {
		return hosts
	}
	return []string{net.JoinHostPort(host, port)}
}

func (s *Server) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if s != nil && s.log != nil {
					s.log.Error("mcp panic recovered", slog.String("request_id", observability.RequestID(r.Context())))
				}
				writeProblem(w, r, http.StatusInternalServerError, "internal", "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.Header.Get(headerRequestID))
		if id == "" || strings.ContainsAny(id, " \t\r\n") || len(id) > maxRequestIDLen {
			id = observability.NewRequestID()
		}
		ctx := observability.WithRequestID(r.Context(), id)
		w.Header().Set(headerRequestID, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) bodyLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && r.Body != http.NoBody {
			r.Body = http.MaxBytesReader(w, r.Body, s.maxBody)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) hostOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hostAllowed(r.Host, s.allowedHosts) {
			writeProblem(w, r, http.StatusForbidden, "auth", "host check failed")
			return
		}
		origin := auth.RequestOrigin(r)
		if origin != "" && !auth.OriginAllowed(r, origin, s.allowedOrigins) {
			writeProblem(w, r, http.StatusForbidden, "auth", "origin check failed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireBearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secret, ok, malformed := auth.ParseBearer(r.Header.Get("Authorization"))
		if malformed || !ok {
			writeProblem(w, r, http.StatusUnauthorized, "auth", "authentication required")
			return
		}
		p, found := s.lookupToken(secret)
		if !found {
			writeProblem(w, r, http.StatusUnauthorized, "auth", "authentication required")
			return
		}
		ctx := auth.WithPrincipal(r.Context(), p)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) lookupToken(secret string) (auth.Principal, bool) {
	if s == nil || s.registry == nil {
		return auth.Principal{}, false
	}
	return s.registry.Lookup(secret)
}

func hostAllowed(host string, allowed []string) bool {
	host = strings.TrimSpace(host)
	if host == "" || strings.ContainsAny(host, " \t\r\n/") {
		return false
	}
	return auth.HostAllowed(host, allowed)
}

func (s *Server) principal(ctx context.Context) (app.Principal, error) {
	p, ok := auth.PrincipalFrom(ctx)
	if ok && p.ID != "" {
		return app.Principal{Kind: p.Kind, ID: p.ID, Scopes: p.Scopes}, nil
	}
	if s != nil && s.actor.ID != "" {
		return app.Principal{Kind: s.actor.Kind, ID: s.actor.ID, Scopes: s.actor.Scopes}, nil
	}
	return app.Principal{}, auth.AuthRequired()
}

// SetActor pins the stdio process actor. HTTP requests still use the bearer.
func (s *Server) SetActor(p auth.Principal) {
	if s == nil {
		return
	}
	s.actor = p
}

// Run serves one MCP session on t (stdio or in-process IO).
func (s *Server) Run(ctx context.Context, t mcp.Transport) error {
	if s == nil || s.mcp == nil {
		return directoryUnavailable()
	}
	return s.mcp.Run(ctx, t)
}

// RunStdio serves MCP on stdin/stdout. Logs must go to stderr only.
func (s *Server) RunStdio(ctx context.Context) error {
	return s.Run(ctx, &mcp.StdioTransport{})
}

func (s *Server) query() (*app.Query, error) {
	if s == nil || s.svc == nil || s.svc.Query == nil {
		return nil, directoryUnavailable()
	}
	return s.svc.Query, nil
}

func directoryUnavailable() error {
	return apperr.New(apperr.CodeDirectory, "directory unavailable").
		WithField(apperr.Field{Path: "directory", Code: "unavailable", Message: "directory unavailable"})
}

func requestMeta(ctx context.Context) mcp.Meta {
	id := observability.RequestID(ctx)
	if id == "" {
		return nil
	}
	return mcp.Meta{"requestId": id}
}

func (s *Server) logTool(ctx context.Context, name string, p app.Principal) {
	if s == nil || s.log == nil {
		return
	}
	s.log.Info("mcp tool",
		slog.String("tool", name),
		slog.String("request_id", observability.RequestID(ctx)),
		slog.String("actor", p.Kind+":"+p.ID),
	)
}

func boolPtr(v bool) *bool { return &v }

func writeProblem(w http.ResponseWriter, r *http.Request, status int, code, title string) {
	if code == "" {
		code = "internal"
	}
	body := map[string]any{
		"type":   problemTypePrefix + code,
		"title":  title,
		"status": status,
		"extensions": map[string]string{
			"requestId": observability.RequestID(r.Context()),
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/problem+json")
	if id := observability.RequestID(r.Context()); id != "" {
		w.Header().Set(headerRequestID, id)
	}
	w.WriteHeader(status)
	_, _ = w.Write(b)
}
