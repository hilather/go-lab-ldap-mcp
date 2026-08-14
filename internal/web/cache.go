package web

import (
	"path"
	"regexp"
	"strings"
)

// hashedFile matches Vite production filenames (name-<hash>.ext).
// Unhashed names such as index.html must not be treated as immutable.
var hashedFile = regexp.MustCompile(`(?i)^[^/]*-[A-Za-z0-9_-]{8,}\.[A-Za-z0-9]+$`)

const (
	cacheHashed     = "public, max-age=31536000, immutable"
	cacheRevalidate = "no-cache"
)

// IsHashedAsset reports whether name is a content-hashed build artifact.
func IsHashedAsset(name string) bool {
	base := path.Base(strings.TrimPrefix(path.Clean("/"+name), "/"))
	if base == "." || base == "/" || base == "" {
		return false
	}
	return hashedFile.MatchString(base)
}

// CacheControl returns the Cache-Control value for a UI asset path.
func CacheControl(name string) string {
	if IsHashedAsset(name) {
		return cacheHashed
	}
	return cacheRevalidate
}
