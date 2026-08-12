package observability

import (
	"context"
	"crypto/rand"
	"encoding/hex"
)

type requestIDKey struct{}

// NewRequestID returns a 128-bit hex operation ID suitable for HTTP, MCP, and LDAP logs.
func NewRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000000000000000000000000000"
	}
	return hex.EncodeToString(b[:])
}

func WithRequestID(ctx context.Context, id string) context.Context {
	if id == "" {
		id = NewRequestID()
	}
	return context.WithValue(ctx, requestIDKey{}, id)
}

func RequestID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}
