package auth

import (
	"net"
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

// HostAllowed reports whether the request Host is permitted. An empty
// allow-list accepts any Host (Compose in-container listen is 0.0.0.0).
func HostAllowed(host string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	for _, a := range allowed {
		if strings.EqualFold(strings.TrimSpace(a), host) {
			return true
		}
	}
	return false
}

// LoopbackHosts returns Host values accepted when listen is loopback-only.
// A non-loopback listen (including 0.0.0.0) returns nil so Host is not restricted.
func LoopbackHosts(listen string) []string {
	host, port, err := net.SplitHostPort(strings.TrimSpace(listen))
	if err != nil || port == "" {
		return nil
	}
	switch strings.ToLower(host) {
	case "127.0.0.1", "localhost", "::1", "[::1]":
	default:
		return nil
	}
	return []string{
		net.JoinHostPort("127.0.0.1", port),
		net.JoinHostPort("localhost", port),
		net.JoinHostPort("::1", port),
	}
}
