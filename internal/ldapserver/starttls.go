package ldapserver

import (
	"context"
	"crypto/tls"
	"log/slog"
	"time"
)

// StartTLS (RFC 4511 section 4.14, parity contract C2/C3) upgrades an
// existing cleartext connection to TLS. conn.serve routes OIDStartTLS here
// instead of dispatching it like other operations: after the success
// response the read loop must read TLS records, so no other message may be
// dispatched between the response and the handshake.
//
// Refusal contract (all definite ExtendedResponses; the connection stays
// usable):
//   - AllowStartTLS is false (or no TLSConfig exists): unwillingToPerform.
//   - The connection already runs TLS (LDAPS or a prior StartTLS):
//     unwillingToPerform (389 DS returns the same code for StartTLS-over-TLS).
//   - A request value was supplied: protocolError — RFC 4511 4.14.1 defines
//     the StartTLS request with an absent requestValue.
//
// On success the server sends an ExtendedResponse with resultCode success
// and no responseName, then immediately runs the TLS server handshake. A
// failed handshake closes the connection (RFC 4513 section 3.1.2); the
// client never receives an LDAP error because no LDAP layer remains.
//
// The handshake deadline reuses the connection guards (ADR-0009 decision
// 10): a pre-auth connection gets ReadTimeout, an authenticated one gets
// IdleTimeout. Handshake errors are logged without peer-supplied payload
// and never contain key material.
func (s *Server) handleStartTLS(ctx context.Context, c *conn, m *Message, req *ExtendedRequest) bool {
	if res, ok := s.checkControls(m); !ok {
		c.sendResult(m.ID, &ExtendedResponse{Result: res})
		s.metrics().ObserveOperation("extended", res.Code)
		return true
	}
	refuse := func(code ResultCode, diag string) {
		c.sendResult(m.ID, &ExtendedResponse{Result: Result{Code: code, DiagnosticMessage: diag}})
		s.metrics().ObserveOperation("extended", code)
	}
	if !s.opts.AllowStartTLS || s.opts.TLSConfig == nil {
		refuse(ResultUnwillingToPerform, "StartTLS is not enabled")
		return true
	}
	if len(req.Value) > 0 {
		refuse(ResultProtocolError, "StartTLS request must not carry a value")
		return true
	}
	if c.isTLS {
		refuse(ResultUnwillingToPerform, "connection is already TLS")
		return true
	}
	if err := c.sendResult(m.ID, &ExtendedResponse{Result: Result{Code: ResultSuccess}}); err != nil {
		s.metrics().ObserveOperation("extended", ResultOperationsError)
		return false
	}
	s.metrics().ObserveOperation("extended", ResultSuccess)

	timeout := s.opts.Limits.ReadTimeout
	if !c.subject().Anonymous {
		timeout = s.opts.Limits.IdleTimeout
	}
	if err := c.upgradeTLS(ctx, s.opts.TLSConfig, timeout); err != nil {
		s.opts.Logger.LogAttrs(ctx, slog.LevelWarn, "StartTLS handshake failed; closing connection",
			slog.String("remote", c.remote), slog.String("error", err.Error()))
		return false
	}
	return true
}

// upgradeTLS swaps the cleartext transport for a TLS server connection and
// completes the handshake. The read deadline is cleared afterwards because
// the read loop sets a fresh deadline for every PDU.
//
// c.mu guards the nc swap against send/close on other goroutines. isTLS is
// touched only on the serve goroutine (bind and StartTLS both run inline),
// so it needs no lock; the comment on the field records that invariant.
// In-flight writes from worker goroutines are not awaited: RFC 4513 3.1.2
// makes the client responsible for having no operations pending when it
// issues StartTLS.
func (c *conn) upgradeTLS(ctx context.Context, cfg *tls.Config, timeout time.Duration) error {
	c.mu.Lock()
	tlsConn := tls.Server(c.nc, cfg)
	c.nc = tlsConn
	c.isTLS = true
	c.mu.Unlock()

	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := tlsConn.SetDeadline(deadline); err != nil {
		return err
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return err
	}
	return tlsConn.SetDeadline(time.Time{})
}
