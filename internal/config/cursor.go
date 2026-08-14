package config

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"time"
)

// Cursor is an opaque codec for paged search. HMAC wrapping is ProtectCursor.
type Cursor struct {
	Query string `json:"q"`
	Page  string `json:"p"`
}

// DefaultCursorTTL is the process-local cursor lifetime. Restart also invalidates.
const DefaultCursorTTL = 15 * time.Minute

const cursorMACSize = sha256.Size

// CursorKey is a process-local HMAC-SHA256 key. A new key is generated at
// control start so a restart invalidates every outstanding cursor.
type CursorKey []byte

func NewCursorKey() CursorKey {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is unrecoverable for cursor integrity.
		return nil
	}
	out := make(CursorKey, len(b))
	copy(out, b[:])
	return out
}

func EncodeCursor(c Cursor) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	payload := append(sum[:8], b...)
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func DecodeCursor(s string) (Cursor, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) < 8 {
		return Cursor{}, fieldErr("cursor", "invalid", "cursor is malformed")
	}
	var c Cursor
	if err := json.Unmarshal(raw[8:], &c); err != nil {
		return Cursor{}, fieldErr("cursor", "invalid", "cursor is malformed")
	}
	return c, nil
}

type signedCursor struct {
	T   string `json:"t"`
	Exp int64  `json:"e"`
}

// ProtectCursor HMAC-wraps EncodeCursor(c) plus an expiry. The key never leaves process memory.
func ProtectCursor(key CursorKey, c Cursor, exp time.Time) (string, error) {
	if len(key) == 0 {
		return "", fieldErr("cursor", "invalid", "cursor key is not configured")
	}
	inner, err := EncodeCursor(c)
	if err != nil {
		return "", err
	}
	if exp.IsZero() {
		return "", fieldErr("cursor", "invalid", "cursor expiry is required")
	}
	body, err := json.Marshal(signedCursor{T: inner, Exp: exp.Unix()})
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(body)
	sum := mac.Sum(nil)
	payload := append(body, sum...)
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

// UnprotectCursor verifies HMAC and expiry, then DecodeCursor. Tamper, expiry,
// or a different process key yield cursor invalid.
func UnprotectCursor(key CursorKey, s string, now time.Time) (Cursor, error) {
	if len(key) == 0 {
		return Cursor{}, fieldErr("cursor", "invalid", "cursor is invalid")
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) < cursorMACSize+2 {
		return Cursor{}, fieldErr("cursor", "invalid", "cursor is invalid")
	}
	body := raw[:len(raw)-cursorMACSize]
	got := raw[len(raw)-cursorMACSize:]
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(body)
	if !hmac.Equal(got, mac.Sum(nil)) {
		return Cursor{}, fieldErr("cursor", "invalid", "cursor is invalid")
	}
	var wrap signedCursor
	if err := json.Unmarshal(body, &wrap); err != nil || wrap.T == "" || wrap.Exp == 0 {
		return Cursor{}, fieldErr("cursor", "invalid", "cursor is invalid")
	}
	if now.IsZero() {
		now = time.Now()
	}
	if !now.Before(time.Unix(wrap.Exp, 0)) {
		return Cursor{}, fieldErr("cursor", "invalid", "cursor is invalid")
	}
	return DecodeCursor(wrap.T)
}
