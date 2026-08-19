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
// Do not pass an empty list when LoopbackHosts produced defaults
// (ADR-0010): that would disable DNS-rebinding protection.
//
// Allowed entries that include a port match Request.Host exactly
// (case-insensitive). Entries without a port match the hostname of
// Request.Host on any port. Wildcard "*" never matches.
func HostAllowed(host string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	for _, a := range allowed {
		if hostEntryMatches(host, strings.TrimSpace(a)) {
			return true
		}
	}
	return false
}

func hostEntryMatches(requestHost, allowed string) bool {
	if allowed == "" || allowed == "*" {
		return false
	}
	if strings.EqualFold(requestHost, allowed) {
		return true
	}
	reqName, _, reqOK := splitHostMaybePort(requestHost)
	allName, allPort, allOK := splitHostMaybePort(allowed)
	if !reqOK || !allOK {
		return false
	}
	if !sameHostName(reqName, allName) {
		return false
	}
	return allPort == ""
}

func splitHostMaybePort(s string) (name, port string, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsAny(s, " \t\r\n/") {
		return "", "", false
	}
	if h, p, err := net.SplitHostPort(s); err == nil {
		return h, p, true
	}
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") && len(s) > 2 {
		inner := s[1 : len(s)-1]
		if net.ParseIP(inner) != nil {
			return inner, "", true
		}
		return "", "", false
	}
	return s, "", true
}

func sameHostName(a, b string) bool {
	a = strings.Trim(a, "[]")
	b = strings.Trim(b, "[]")
	if ipa, ipb := net.ParseIP(a), net.ParseIP(b); ipa != nil && ipb != nil {
		return ipa.Equal(ipb)
	}
	return strings.EqualFold(a, b)
}

// LoopbackHosts returns Host values accepted when listen is loopback or
// bind-all (0.0.0.0 / ::). Compose publishes those listeners on loopback,
// so DNS-rebinding Host: evil.test is rejected. A specific non-loopback
// listen returns nil (no Host restriction from this helper).
func LoopbackHosts(listen string) []string {
	host, port, err := net.SplitHostPort(strings.TrimSpace(listen))
	if err != nil || port == "" {
		return nil
	}
	switch strings.ToLower(host) {
	case "127.0.0.1", "localhost", "::1", "[::1]", "0.0.0.0", "::", "":
	default:
		return nil
	}
	return []string{
		net.JoinHostPort("127.0.0.1", port),
		net.JoinHostPort("localhost", port),
		net.JoinHostPort("::1", port),
		net.JoinHostPort("control", port),
	}
}

// LoopbackHostnames returns host-only loopback names when listen is
// loopback or bind-all. Host-only entries match any port, so published
// mappings (localhost:9443) work without listing every host:port pair.
// Arbitrary hostnames stay rejected (ADR-0010).
func LoopbackHostnames(listen string) []string {
	if len(LoopbackHosts(listen)) == 0 {
		return nil
	}
	return []string{"127.0.0.1", "localhost", "::1", "control"}
}
