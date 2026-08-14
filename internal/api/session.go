package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/audit"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
)

type sessionCreateBody struct {
	Token string `json:"token"`
}

type sessionCreatedBody struct {
	CSRFToken string `json:"csrfToken"`
}

type sessionViewBody struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind"`
	Scopes    []string `json:"scopes"`
	ExpiresAt string   `json:"expiresAt"`
}

func (s *Server) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	if !isJSON(r) {
		writeProblemStatus(w, r, http.StatusUnsupportedMediaType, "configuration", "content type must be application/json", nil)
		return
	}
	var body sessionCreateBody
	if err := DecodeJSON(r.Body, &body); err != nil {
		writeProblem(w, r, err)
		return
	}
	if strings.TrimSpace(body.Token) == "" {
		writeProblem(w, r, auth.AuthRequired())
		return
	}
	p, ok := s.lookupToken(body.Token)
	if !ok {
		s.emitAudit(r, audit.ActionAuthenticate, "", "session", audit.ResultFailure)
		writeProblem(w, r, auth.AuthRequired())
		return
	}
	if s.sessions == nil {
		writeProblemStatus(w, r, http.StatusServiceUnavailable, "auth", "session store unavailable", nil)
		return
	}
	old := ""
	if c, err := r.Cookie(auth.CookieName); err == nil {
		old = c.Value
	}
	cookie, csrf, _, err := s.sessions.Rotate(old, p.ID, p.Scopes)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	secure := auth.CookieSecure(r, s.forceSecure)
	http.SetCookie(w, auth.NewSessionCookie(cookie, secure, 0))
	actor := appActor(auth.KindToken, p.ID)
	s.emitAudit(r, audit.ActionAuthenticate, actor, "session", audit.ResultSuccess)
	s.emitAudit(r, audit.ActionSessionCreate, actor, "session", audit.ResultSuccess)
	setNoStore(w)
	writeJSON(w, r, http.StatusOK, "application/json", sessionCreatedBody{CSRFToken: csrf})
}

func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(auth.CookieName)
	if err != nil || s.sessions == nil {
		writeProblem(w, r, bearerOrSession401(r))
		return
	}
	sess, _, ok := s.sessions.Lookup(c.Value)
	if !ok {
		writeProblem(w, r, bearerOrSession401(r))
		return
	}
	scopes := append([]string(nil), sess.Scopes...)
	if scopes == nil {
		scopes = []string{}
	}
	setNoStore(w)
	writeJSON(w, r, http.StatusOK, "application/json", sessionViewBody{
		ID:        sess.ID,
		Kind:      auth.KindSession,
		Scopes:    scopes,
		ExpiresAt: s.sessions.ExpiresAt(sess).UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(auth.CookieName)
	if err != nil || s.sessions == nil {
		writeProblem(w, r, auth.AuthRequired())
		return
	}
	sess, _, ok := s.sessions.Lookup(c.Value)
	if !ok {
		writeProblem(w, r, auth.AuthRequired())
		return
	}
	s.sessions.Delete(c.Value)
	http.SetCookie(w, auth.ClearSessionCookie(auth.CookieSecure(r, s.forceSecure)))
	s.emitAudit(r, audit.ActionSessionDestroy, appActor(auth.KindSession, sess.ID), "session", audit.ResultSuccess)
	writeNoContent(w, r)
}

func appActor(kind, id string) string {
	if id == "" {
		return kind
	}
	return kind + ":" + id
}

func bearerOrSession401(r *http.Request) error {
	// Same public 401 for missing, malformed, and invalid credentials.
	_ = r
	return auth.AuthRequired()
}

func isJSON(r *http.Request) bool {
	ct := strings.TrimSpace(r.Header.Get("Content-Type"))
	if ct == "" {
		return false
	}
	media, _, _ := strings.Cut(ct, ";")
	return strings.EqualFold(strings.TrimSpace(media), "application/json")
}
