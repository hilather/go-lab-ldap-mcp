package ldapserver

import (
	"context"
	"io"
)

// Codec is the BER encode/decode seam for LDAPMessage. The implementation
// wraps github.com/go-asn1-ber/asn1-ber and lands in T-124; a from-scratch
// BER codec is rejected (ADR-0009 decision 9), and no go-ldap types appear
// here because this package is a server, not a client.
//
// Pre-auth size limits are a codec responsibility (ADR-0009 decision 10):
// ReadMessage must reject an oversized PDU before payload allocation grows
// beyond MaxPDUBytes, because the codec faces unauthenticated network input.
type Codec interface {
	// ReadMessage reads exactly one LDAPMessage from r. It returns io.EOF on
	// a clean connection close and a bounded, secret-free error on malformed
	// or oversized input.
	ReadMessage(ctx context.Context, r io.Reader) (*Message, error)
	// WriteMessage encodes and writes one LDAPMessage to w.
	WriteMessage(ctx context.Context, w io.Writer, m *Message) error
	// MaxPDUBytes is the configured per-PDU size ceiling.
	MaxPDUBytes() int
}
