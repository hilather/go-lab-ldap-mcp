package ldapserver

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// Password storage schemes (parity contract C4; encoding shape is Delta
// D3 — byte-identical blobs with 389 are not required, bind is the test).
// The strings mirror internal/config/v1alpha1 scheme identifiers; the
// engine keeps its own constants so it never depends on the file-format
// package.
const (
	SchemePBKDF2SHA256 = "PBKDF2-SHA256"
	SchemeSSHA512      = "SSHA512"
)

// Hash-format bounds. Verification faces stored values that may have been
// tampered with, so every parsed knob has a ceiling: a forged iteration
// count or a giant blob must not become a CPU or memory amplifier.
const (
	// maxStoredPasswordBytes rejects absurd stored blobs before base64
	// decoding allocates.
	maxStoredPasswordBytes = 4096
	// maxVerifyIterations caps the iteration count honored from a stored
	// PBKDF2 blob. Anything higher is treated as corrupt, not as a hint.
	maxVerifyIterations = 4_000_000
	pbkdf2SaltBytes     = 16
	pbkdf2KeyBytes      = 32
	ssha512SaltBytes    = 16
	maxSaltBytes        = 128
	minSaltBytes        = 8
)

// DefaultPBKDF2Iterations balances stretch against lab interactivity. 389
// DS defaults to 50k; OWASP 2023 guidance for PBKDF2-HMAC-SHA256 is 210k.
// The native engine defaults to the OWASP figure and lets tests lower it
// through StandardHasher.Iterations.
const DefaultPBKDF2Iterations = 210_000

// PasswordHasher is the small seam that replaces the T-126 plaintext stub:
// Hash encodes a plaintext password for storage, Verify reports whether a
// plaintext candidate matches a stored value. Implementations must compare
// in constant time and must never log either side.
//
// Verification is scheme-aware from the stored value's {SCHEME} prefix, so
// a directory holding mixed schemes (imports, seed fixtures) verifies them
// all regardless of the configured write scheme.
type PasswordHasher interface {
	// Hash encodes plaintext into a {SCHEME}payload storage value.
	Hash(password []byte) ([]byte, error)
	// Verify reports whether plaintext matches stored; any malformed,
	// oversized, or unknown-scheme stored value returns false (fail
	// closed), never an error that could leak parse detail.
	Verify(stored, password []byte) bool
}

// StandardHasher writes {PBKDF2-SHA256} or {SSHA512} values. The zero Rand
// is crypto/rand.Reader; the zero Iterations is DefaultPBKDF2Iterations.
type StandardHasher struct {
	Scheme     string
	Iterations int
	Rand       io.Reader
}

// NewStandardHasher validates scheme and returns the hasher. The empty
// scheme selects PBKDF2-SHA256 (config default; PBKDF2_SHA256 alias folds).
func NewStandardHasher(scheme string) (*StandardHasher, error) {
	norm, err := normalizeScheme(scheme)
	if err != nil {
		return nil, err
	}
	return &StandardHasher{Scheme: norm, Iterations: DefaultPBKDF2Iterations, Rand: rand.Reader}, nil
}

// normalizeScheme maps config spellings onto the canonical scheme name.
func normalizeScheme(scheme string) (string, error) {
	switch strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(scheme), "_", "-")) {
	case "", SchemePBKDF2SHA256:
		return SchemePBKDF2SHA256, nil
	case SchemeSSHA512:
		return SchemeSSHA512, nil
	default:
		return "", fmt.Errorf("ldapserver: unknown password storage scheme %q", scheme)
	}
}

func (h *StandardHasher) iterations() int {
	if h.Iterations > 0 {
		return h.Iterations
	}
	return DefaultPBKDF2Iterations
}

func (h *StandardHasher) entropy() io.Reader {
	if h.Rand != nil {
		return h.Rand
	}
	return rand.Reader
}

// Hash encodes password under the configured scheme:
//
//	{PBKDF2-SHA256}base64( uint32be(iterations) || salt16 || dk32 )
//	{SSHA512}base64( sha512(password || salt16) || salt16 )
func (h *StandardHasher) Hash(password []byte) ([]byte, error) {
	scheme, err := normalizeScheme(h.Scheme)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, pbkdf2SaltBytes)
	if _, err := io.ReadFull(h.entropy(), salt); err != nil {
		return nil, fmt.Errorf("ldapserver: hash password: %w", err)
	}
	switch scheme {
	case SchemePBKDF2SHA256:
		dk := pbkdf2.Key(password, salt, h.iterations(), pbkdf2KeyBytes, sha256.New)
		payload := make([]byte, 4, 4+len(salt)+len(dk))
		binary.BigEndian.PutUint32(payload, uint32(h.iterations()))
		payload = append(payload, salt...)
		payload = append(payload, dk...)
		return encodePrefixed(scheme, payload), nil
	case SchemeSSHA512:
		payload := ssha512Digest(password, salt)
		return encodePrefixed(scheme, payload), nil
	default:
		// normalizeScheme returned one of the two; unreachable.
		return nil, fmt.Errorf("ldapserver: unknown password storage scheme %q", scheme)
	}
}

// Verify delegates to the scheme-aware verifier; the configured scheme only
// steers Hash.
func (h *StandardHasher) Verify(stored, password []byte) bool {
	return verifyPassword(stored, password)
}

func encodePrefixed(scheme string, payload []byte) []byte {
	out := make([]byte, 0, len(scheme)+2+base64.StdEncoding.EncodedLen(len(payload)))
	out = append(out, '{')
	out = append(out, scheme...)
	out = append(out, '}')
	return append(out, base64.StdEncoding.EncodeToString(payload)...)
}

// isPreHashed reports whether v already carries a {SCHEME} prefix. Seed and
// import paths use it to pass pre-hashed values through the write policy
// untouched.
func isPreHashed(v []byte) bool {
	_, _, ok := splitScheme(v)
	return ok
}

// splitScheme splits "{SCHEME}payload". A value without a well-formed
// prefix is plaintext (ok == false).
func splitScheme(v []byte) (scheme string, payload []byte, ok bool) {
	if len(v) < 3 || v[0] != '{' {
		return "", nil, false
	}
	end := strings.IndexByte(string(v[1:]), '}')
	if end < 1 {
		return "", nil, false
	}
	scheme = string(v[1 : 1+end])
	for _, r := range scheme {
		if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			continue
		}
		return "", nil, false
	}
	return scheme, v[1+end+1:], true
}

// verifyPassword is the scheme-aware verifier behind PasswordHasher.Verify
// and the bind path. Every failure mode returns false; the caller cannot
// distinguish "unknown user", "wrong password", and "corrupt stored value"
// from this result, which is the point (parity contract C3).
func verifyPassword(stored, password []byte) bool {
	if len(stored) == 0 || len(stored) > maxStoredPasswordBytes {
		return false
	}
	scheme, payload, ok := splitScheme(stored)
	if !ok {
		// T-126 plaintext compatibility: seed fixtures store cleartext
		// userPassword (Delta D3). Constant-time compare either way.
		return subtle.ConstantTimeCompare(stored, password) == 1
	}
	switch strings.ToUpper(scheme) {
	case "CLEARTEXT":
		// 389 spell: {CLEARTEXT}payload is raw, not base64.
		return subtle.ConstantTimeCompare(payload, password) == 1
	case SchemePBKDF2SHA256:
		return verifyPBKDF2(payload, password)
	case SchemeSSHA512, "SSHA-512":
		return verifySSHA512(payload, password)
	default:
		// Unknown scheme: fail closed.
		return false
	}
}

func decodePayload(payload []byte) ([]byte, bool) {
	raw, err := base64.StdEncoding.DecodeString(string(payload))
	if err != nil || len(raw) > maxStoredPasswordBytes {
		return nil, false
	}
	return raw, true
}

func verifyPBKDF2(payload, password []byte) bool {
	raw, ok := decodePayload(payload)
	if !ok || len(raw) < 4+minSaltBytes+pbkdf2KeyBytes {
		return false
	}
	iter := binary.BigEndian.Uint32(raw[:4])
	if iter < 1 || iter > maxVerifyIterations {
		return false
	}
	body := raw[4:]
	dk := body[len(body)-pbkdf2KeyBytes:]
	salt := body[:len(body)-pbkdf2KeyBytes]
	if len(salt) < minSaltBytes || len(salt) > maxSaltBytes {
		return false
	}
	derived := pbkdf2.Key(password, salt, int(iter), pbkdf2KeyBytes, sha256.New)
	return subtle.ConstantTimeCompare(derived, dk) == 1
}

func ssha512Digest(password, salt []byte) []byte {
	buf := make([]byte, 0, len(password)+len(salt))
	buf = append(buf, password...)
	buf = append(buf, salt...)
	sum := sha512.Sum512(buf)
	return append(sum[:], salt...)
}

func verifySSHA512(payload, password []byte) bool {
	raw, ok := decodePayload(payload)
	if !ok || len(raw) < sha512.Size+minSaltBytes || len(raw) > sha512.Size+maxSaltBytes {
		return false
	}
	digest := raw[:sha512.Size]
	salt := raw[sha512.Size:]
	return subtle.ConstantTimeCompare(ssha512Digest(password, salt)[:sha512.Size], digest) == 1
}
