package auth

import (
	"crypto/sha256"
	"crypto/subtle"
)

// DigestSecret hashes secret bytes for constant-time comparison.
func DigestSecret(secret []byte) [sha256.Size]byte {
	return sha256.Sum256(secret)
}

// EqualDigest reports whether two SHA-256 digests are equal using
// crypto/subtle so the comparison does not short-circuit on the first
// differing byte.
func EqualDigest(a, b [sha256.Size]byte) bool {
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}
