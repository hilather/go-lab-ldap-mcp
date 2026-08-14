package auth

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

const (
	CookieName = "labldap_session"
	CSRFHeader = "X-CSRF-Token"
	cookiePath = "/"
)

type SessionConfig struct {
	Idle     time.Duration
	Absolute time.Duration
	Max      int
}

func DefaultSessionConfig() SessionConfig {
	return SessionConfig{
		Idle:     30 * time.Minute,
		Absolute: 8 * time.Hour,
		Max:      64,
	}
}

// Session is the public, non-secret view of an in-memory session.
type Session struct {
	ID        string
	TokenID   string
	Scopes    directory.ScopeSet
	CreatedAt time.Time
	LastSeen  time.Time
}

// Store is a process-local session table. Cookie values and CSRF secrets
// stay in memory and are never persisted.
type Store struct {
	mu       sync.Mutex
	sessions map[string]*record
	cfg      SessionConfig
	now      func() time.Time
}

type record struct {
	public    Session
	csrf      string
	cookie    string
	createdAt time.Time
	lastSeen  time.Time
}

func NewStore(cfg SessionConfig) *Store {
	if cfg.Idle <= 0 {
		cfg.Idle = 30 * time.Minute
	}
	if cfg.Absolute <= 0 {
		cfg.Absolute = 8 * time.Hour
	}
	if cfg.Max <= 0 {
		cfg.Max = 64
	}
	return &Store{
		sessions: make(map[string]*record),
		cfg:      cfg,
		now:      time.Now,
	}
}

func (s *Store) SetClock(now func() time.Time) {
	if s == nil || now == nil {
		return
	}
	s.now = now
}

// Create issues a new session and CSRF secret. The caller must set the
// cookie from cookieValue and return csrf in the login body only.
func (s *Store) Create(tokenID string, scopes directory.ScopeSet) (cookieValue, csrf string, sess Session, err error) {
	if s == nil {
		return "", "", Session{}, apperr.New(apperr.CodeAuth, "session store unavailable")
	}
	cookieValue, err = randomHex(32)
	if err != nil {
		return "", "", Session{}, err
	}
	csrf, err = randomHex(32)
	if err != nil {
		return "", "", Session{}, err
	}
	publicID, err := randomHex(16)
	if err != nil {
		return "", "", Session{}, err
	}
	now := s.now()
	rec := &record{
		public: Session{
			ID:        publicID,
			TokenID:   tokenID,
			Scopes:    append(directory.ScopeSet(nil), scopes...),
			CreatedAt: now,
			LastSeen:  now,
		},
		csrf:      csrf,
		cookie:    cookieValue,
		createdAt: now,
		lastSeen:  now,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(now)
	if len(s.sessions) >= s.cfg.Max {
		s.evictOldestLocked()
	}
	s.sessions[cookieValue] = rec
	return cookieValue, csrf, rec.public, nil
}

// Rotate deletes an existing cookie session (if any) and creates a new one.
func (s *Store) Rotate(oldCookie, tokenID string, scopes directory.ScopeSet) (cookieValue, csrf string, sess Session, err error) {
	if oldCookie != "" {
		s.Delete(oldCookie)
	}
	return s.Create(tokenID, scopes)
}

func (s *Store) Lookup(cookieValue string) (Session, string, bool) {
	if s == nil || cookieValue == "" {
		return Session{}, "", false
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.sessions[cookieValue]
	if !ok || s.expiredLocked(rec, now) {
		if ok {
			delete(s.sessions, cookieValue)
		}
		return Session{}, "", false
	}
	rec.lastSeen = now
	rec.public.LastSeen = now
	return rec.public, rec.csrf, true
}

func (s *Store) Delete(cookieValue string) {
	if s == nil || cookieValue == "" {
		return
	}
	s.mu.Lock()
	delete(s.sessions, cookieValue)
	s.mu.Unlock()
}

func (s *Store) ValidCSRF(cookieValue, presented string) bool {
	if s == nil || cookieValue == "" || presented == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.sessions[cookieValue]
	if !ok {
		return false
	}
	return EqualDigest(DigestSecret([]byte(rec.csrf)), DigestSecret([]byte(presented)))
}

func (s *Store) Count() int {
	if s == nil {
		return 0
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked(now)
	return len(s.sessions)
}

func (s *Store) ExpiresAt(sess Session) time.Time {
	idle := sess.LastSeen.Add(s.cfg.Idle)
	abs := sess.CreatedAt.Add(s.cfg.Absolute)
	if idle.Before(abs) {
		return idle
	}
	return abs
}

func (s *Store) expiredLocked(rec *record, now time.Time) bool {
	if now.Sub(rec.lastSeen) > s.cfg.Idle {
		return true
	}
	return now.Sub(rec.createdAt) > s.cfg.Absolute
}

func (s *Store) expireLocked(now time.Time) {
	for k, rec := range s.sessions {
		if s.expiredLocked(rec, now) {
			delete(s.sessions, k)
		}
	}
}

func (s *Store) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	first := true
	for k, rec := range s.sessions {
		if first || rec.lastSeen.Before(oldest) {
			oldestKey = k
			oldest = rec.lastSeen
			first = false
		}
	}
	if oldestKey != "" {
		delete(s.sessions, oldestKey)
	}
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", apperr.New(apperr.CodeAuth, "session material unavailable").Wrap(err)
	}
	return hex.EncodeToString(b), nil
}

// NewSessionCookie builds the browser cookie. Secure is set when the
// request is TLS or the server requires TLS cookies.
func NewSessionCookie(value string, secure bool, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     CookieName,
		Value:    value,
		Path:     cookiePath,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	}
}

func ClearSessionCookie(secure bool) *http.Cookie {
	c := NewSessionCookie("", secure, -1)
	c.Expires = time.Unix(0, 0).UTC()
	return c
}

func CookieSecure(r *http.Request, force bool) bool {
	if force {
		return true
	}
	return r != nil && r.TLS != nil
}

func UnsafeMethod(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}
