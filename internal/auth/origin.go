package auth

import (
	"net/http"
	"net/url"
	"strings"
)

// OriginAllowed reports whether Origin is same-origin with the request
// or an exact entry in allowed. Empty Origin is not allowed.
func OriginAllowed(r *http.Request, origin string, allowed []string) bool {
	origin = strings.TrimSpace(origin)
	if origin == "" || strings.EqualFold(origin, "null") {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	if r != nil && sameOrigin(r, u) {
		return true
	}
	for _, a := range allowed {
		if a == "*" {
			// Wildcard origins are rejected at Server construction.
			continue
		}
		if strings.EqualFold(strings.TrimRight(a, "/"), strings.TrimRight(origin, "/")) {
			return true
		}
	}
	return false
}

func sameOrigin(r *http.Request, u *url.URL) bool {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return strings.EqualFold(u.Scheme, scheme) && strings.EqualFold(u.Host, r.Host)
}

func RequestOrigin(r *http.Request) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(r.Header.Get("Origin"))
}
