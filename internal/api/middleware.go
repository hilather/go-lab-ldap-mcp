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

func (s *Server) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if s != nil && s.log != nil {
					s.log.Error("http panic recovered", slog.String("request_id", observability.RequestID(r.Context())))
				}
				writeProblemStatus(w, r, http.StatusInternalServerError, "internal", "internal error", nil)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.Header.Get(headerRequestID))
		if id == "" || strings.ContainsAny(id, " \t\r\n") || len(id) > 128 {
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

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := auth.RequestOrigin(r)
		if origin != "" && auth.OriginAllowed(r, origin, s.allowedOrigins) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-CSRF-Token, X-Request-ID, If-Match")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Add("Vary", "Origin")
		}
		if r.Method == http.MethodOptions {
			if origin != "" && !auth.OriginAllowed(r, origin, s.allowedOrigins) {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = s.authenticate(r)
		if needsCSRF(r) {
			if err := s.requireCookieCSRF(r); err != nil {
				writeProblem(w, r, err)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authenticate(r *http.Request) *http.Request {
	if secret, ok, malformed := auth.ParseBearer(r.Header.Get("Authorization")); malformed {
		s.observeAuth("failure", "malformed")
		return r
	} else if ok {
		if p, found := s.lookupToken(secret); found {
			s.observeAuth("success", "ok")
			return r.WithContext(auth.WithPrincipal(r.Context(), p))
		}
		s.observeAuth("failure", "invalid")
		return r
	}
	c, err := r.Cookie(auth.CookieName)
	if err != nil || c.Value == "" || s.sessions == nil {
		if r.Header.Get("Authorization") != "" {
			s.observeAuth("failure", "malformed")
		}
		return r
	}
	sess, _, ok := s.sessions.Lookup(c.Value)
	if !ok {
		s.observeAuth("failure", "invalid")
		return r
	}
	s.observeAuth("success", "ok")
	p := auth.Principal{Kind: auth.KindSession, ID: sess.ID, Scopes: sess.Scopes}
	return r.WithContext(auth.WithPrincipal(r.Context(), p))
}

func (s *Server) observeAuth(result, reason string) {
	if s != nil && s.metrics != nil {
		s.metrics.ObserveAuth(result, reason)
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (w *statusRecorder) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (s *Server) metricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s == nil || s.metrics == nil {
			next.ServeHTTP(w, r)
			return
		}
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(rec, r)
		route := observability.RouteTemplate(r.Method, r.URL.Path)
		s.metrics.ObserveHTTP(r.Method, route, observability.StatusClass(rec.status), time.Since(start))
	})
}

func (s *Server) lookupToken(secret string) (auth.Principal, bool) {
	if s.registry == nil {
		return auth.Principal{}, false
	}
	return s.registry.Lookup(secret)
}

func (s *Server) requireCookieCSRF(r *http.Request) error {
	// Gate on a valid session cookie, not the resolved principal. A
	// malformed or invalid Authorization header must not skip CSRF.
	if !s.hasSessionCookie(r) {
		return nil
	}
	origin := auth.RequestOrigin(r)
	if !auth.OriginAllowed(r, origin, s.allowedOrigins) {
		return apperr.New(apperr.CodeAuth, "origin check failed").
			WithField(apperr.Field{Path: "origin", Code: "forbidden", Message: "origin is not allowed"})
	}
	c, err := r.Cookie(auth.CookieName)
	if err != nil {
		return auth.AuthRequired()
	}
	if s.sessions == nil || !s.sessions.ValidCSRF(c.Value, r.Header.Get(auth.CSRFHeader)) {
		return apperr.New(apperr.CodeAuth, "csrf check failed").
			WithField(apperr.Field{Path: "csrf", Code: "forbidden", Message: "csrf token is missing or invalid"})
	}
	return nil
}

func (s *Server) hasSessionCookie(r *http.Request) bool {
	if s == nil || s.sessions == nil || r == nil {
		return false
	}
	c, err := r.Cookie(auth.CookieName)
	if err != nil || c.Value == "" {
		return false
	}
	_, _, ok := s.sessions.Lookup(c.Value)
	return ok
}

func needsCSRF(r *http.Request) bool {
	if !auth.UnsafeMethod(r.Method) {
		return false
	}
	// Token exchange is not cookie-authenticated yet.
	if r.Method == http.MethodPost && r.URL.Path == "/api/v1/session" {
		return false
	}
	return true
}

func observabilityRequestID(r *http.Request) string {
	return observability.RequestID(r.Context())
}
