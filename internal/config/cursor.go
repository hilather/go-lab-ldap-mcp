package config

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

// Cursor is an opaque codec for paged search. HMAC keying lands in T-053.
type Cursor struct {
	Query string `json:"q"`
	Page  string `json:"p"`
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
