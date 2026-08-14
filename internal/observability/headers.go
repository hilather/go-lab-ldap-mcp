package observability

import (
	"net/http"
	"strings"
)

const redactedHeader = "[redacted]"

// Sensitive header names (canonical MIME). Values must never appear in logs.
var sensitiveHeader = map[string]bool{
	"Authorization":       true,
	"Proxy-Authorization": true,
	"Cookie":              true,
	"Set-Cookie":          true,
	"X-Csrf-Token":        true,
}

// SanitizeHeader returns a log-safe header value. Sensitive names become
// [redacted]; others are returned unchanged.
func SanitizeHeader(name, value string) string {
	if SensitiveHeaderName(name) {
		return redactedHeader
	}
	return value
}

func SensitiveHeaderName(name string) bool {
	return sensitiveHeader[http.CanonicalHeaderKey(strings.TrimSpace(name))]
}

// SanitizeHeaders copies h with sensitive values replaced. The original map
// is not modified.
func SanitizeHeaders(h http.Header) http.Header {
	out := make(http.Header, len(h))
	if h == nil {
		return out
	}
	for k, vals := range h {
		if SensitiveHeaderName(k) {
			out[k] = []string{redactedHeader}
			continue
		}
		out[k] = append([]string(nil), vals...)
	}
	return out
}
