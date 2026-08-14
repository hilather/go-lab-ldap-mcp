package api

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

const (
	defaultPageSize = 50
	defaultPageMax  = 500
)

// PageParams is the GET list query (pageSize, cursor).
type PageParams struct {
	PageSize int
	Cursor   string
}

type listEnvelope struct {
	Items      any    `json:"items"`
	NextCursor string `json:"nextCursor,omitempty"`
}

// ParsePageParams reads pageSize and cursor. Omitted pageSize uses def;
// values above max or below 1 are field errors.
func ParsePageParams(q url.Values, def, max int) (PageParams, error) {
	if def <= 0 {
		def = defaultPageSize
	}
	if max <= 0 {
		max = defaultPageMax
	}
	if def > max {
		def = max
	}
	out := PageParams{PageSize: def}
	if q == nil {
		return out, nil
	}
	out.Cursor = q.Get("cursor")
	raw := strings.TrimSpace(q.Get("pageSize"))
	if raw == "" {
		return out, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return PageParams{}, apperr.New(apperr.CodeConfiguration, "pageSize is invalid").WithField(apperr.Field{
			Path: "pageSize", Code: "invalid", Message: "pageSize must be a positive integer",
		})
	}
	if n > max {
		return PageParams{}, apperr.New(apperr.CodeConfiguration, "pageSize exceeds the configured maximum").WithField(apperr.Field{
			Path: "pageSize", Code: "too_large", Message: "pageSize exceeds the configured maximum",
		})
	}
	out.PageSize = n
	return out, nil
}

func (s *Server) parsePageParams(r *http.Request) (PageParams, error) {
	def, max := defaultPageSize, defaultPageMax
	if s != nil {
		if s.pageSizeDefault > 0 {
			def = s.pageSizeDefault
		}
		if s.pageSizeMax > 0 {
			max = s.pageSizeMax
		}
	}
	var q url.Values
	if r != nil && r.URL != nil {
		q = r.URL.Query()
	}
	return ParsePageParams(q, def, max)
}

// DecodeCursor verifies a protected list/search cursor. Tamper, expiry,
// missing key, or a query mismatch yield path cursor / code invalid.
func DecodeCursor(key config.CursorKey, token, query string, now time.Time) (config.Cursor, error) {
	if strings.TrimSpace(token) == "" {
		return config.Cursor{}, nil
	}
	if now.IsZero() {
		now = time.Now()
	}
	c, err := config.UnprotectCursor(key, token, now)
	if err != nil {
		return config.Cursor{}, err
	}
	if query != "" && c.Query != query {
		return config.Cursor{}, apperr.New(apperr.CodeConfiguration, "cursor is invalid").WithField(apperr.Field{
			Path: "cursor", Code: "invalid", Message: "cursor does not match this query",
		})
	}
	return c, nil
}

// EncodeCursor HMAC-wraps a cursor with the process-local key and default TTL.
func EncodeCursor(key config.CursorKey, c config.Cursor, now time.Time) (string, error) {
	if now.IsZero() {
		now = time.Now()
	}
	return config.ProtectCursor(key, c, now.Add(config.DefaultCursorTTL))
}

func writeList(w http.ResponseWriter, r *http.Request, items any, nextCursor string) {
	if items == nil {
		items = []struct{}{}
	}
	writeJSON(w, r, http.StatusOK, "application/json", listEnvelope{Items: items, NextCursor: nextCursor})
}
