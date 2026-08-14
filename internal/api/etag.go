package api

import (
	"net/http"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

// FormatETag quotes a revision hex as a strong ETag (§3.8).
func FormatETag(rev directory.Revision) string {
	return `"` + string(rev) + `"`
}

// SetETag writes ETag: "<revision>". Empty revisions are omitted.
func SetETag(w http.ResponseWriter, rev directory.Revision) {
	if w == nil || rev == "" {
		return
	}
	w.Header().Set("ETag", FormatETag(rev))
}

// RequireIfMatch parses a required If-Match header into a revision.
// Missing or stale-format preconditions use documented field codes so
// statusFor returns 412 for required/conflict and 400 for invalid syntax.
func RequireIfMatch(r *http.Request) (directory.Revision, error) {
	if r == nil {
		return "", missingIfMatch()
	}
	return ParseIfMatch(r.Header.Get("If-Match"))
}

// ParseIfMatch accepts one quoted strong ETag. Lists, "*", and weak tags fail.
func ParseIfMatch(header string) (directory.Revision, error) {
	s := strings.TrimSpace(header)
	if s == "" {
		return "", missingIfMatch()
	}
	if strings.EqualFold(s, "*") {
		return "", invalidIfMatch("If-Match * is not supported")
	}
	if strings.HasPrefix(s, "W/") || strings.HasPrefix(s, "w/") {
		return "", invalidIfMatch("weak ETags are not supported")
	}
	if strings.Contains(s, ",") {
		return "", invalidIfMatch("If-Match lists are not supported")
	}
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		return "", invalidIfMatch("If-Match must be a quoted revision")
	}
	inner := s[1 : len(s)-1]
	if inner == "" || strings.ContainsAny(inner, `"\\`) || !isRevisionHex(inner) {
		return "", invalidIfMatch("If-Match must be a quoted revision")
	}
	return directory.Revision(inner), nil
}

// isRevisionHex is the lowercase hex alphabet used by directory.RevisionHash.
func isRevisionHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'f' {
			continue
		}
		return false
	}
	return true
}

func missingIfMatch() error {
	return apperr.New(apperr.CodeConfiguration, "if-match is required").WithField(apperr.Field{
		Path:    "If-Match",
		Code:    "required",
		Message: "If-Match is required",
	})
}

func invalidIfMatch(msg string) error {
	return apperr.New(apperr.CodeConfiguration, "if-match is invalid").WithField(apperr.Field{
		Path:    "If-Match",
		Code:    "invalid",
		Message: msg,
	})
}
