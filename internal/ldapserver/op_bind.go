package ldapserver

import (
	"context"
	"crypto/subtle"
	"errors"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// handleBind processes one simple bind inline on the connection read loop,
// so the read loop observes the new identity before dispatching any later
// request. It reports whether the connection stays open: the pre-auth
// budget (ADR-0009 decision 10) closes it after MaxAuthAttempts failures.
//
// Policy gates, in order (parity contract C3):
//  1. LDAP version must be 3 (protocolError otherwise).
//  2. Anonymous bind (empty name) requires AllowAnonymousBind. When
//     disabled, the failure code is unwillingToPerform (53), matching 389
//     with nsslapd-allow-anonymous-access:off; RFC 4511 suggests
//     inappropriateAuthentication (48) for this case, so the choice is a
//     parity Delta candidate for the T-147 oracle run to adjudicate.
//  3. A non-empty name with an empty password is the RFC 4511
//     "unauthenticated" mechanism; it is folded into the anonymous gate,
//     again per 389-observed behavior.
//  4. Cleartext simple bind (with a password) requires AllowCleartextBind
//     unless the connection is already TLS-protected; otherwise
//     confidentialityRequired (13).
//  5. Credentials: the configured Directory Manager identity authenticates
//     only through Identity.VerifyPassword (constant-time contract; the DM
//     password is never stored raw). Any other DN resolves against the
//     store and compares userPassword in constant time. Unknown user and
//     wrong password both fail invalidCredentials (49) — 389-observed.
//
// A successful DM bind sets Subject.BypassACI (ADR-0009 decision 13); every
// bind attempt first resets the connection to the anonymous identity
// (RFC 4511 section 4.2.1).
func (s *Server) handleBind(ctx context.Context, c *conn, m *Message, req *BindRequest) bool {
	// The password must not outlive authentication; scrub the decoded
	// request regardless of outcome.
	defer ZeroSecrets(m)
	res, ok := s.checkControls(m)
	if ok {
		res, ok = s.authenticate(ctx, c, req)
	}
	if ctx.Err() == nil {
		c.sendResult(m.ID, &BindResponse{Result: res})
	}
	s.metrics().ObserveOperation("bind", res.Code)
	if !ok {
		if c.recordFailedAuth() >= s.opts.Limits.MaxAuthAttempts {
			c.sendNoticeOfDisconnection(ResultUnwillingToPerform, "too many failed bind attempts")
			return false
		}
	}
	return true
}

// authenticate runs the bind policy gates and, on success, installs the
// bound identity on the connection. It reports the LDAPResult and whether
// authentication succeeded (for the failed-attempt budget).
func (s *Server) authenticate(ctx context.Context, c *conn, req *BindRequest) (Result, bool) {
	// Every bind attempt starts from the anonymous identity.
	c.setSubject(Subject{Anonymous: true})

	if req.Version != 3 {
		return Result{Code: ResultProtocolError, DiagnosticMessage: "unsupported LDAP version"}, false
	}
	anonymous := req.Name == "" || len(req.Password) == 0
	if anonymous && !s.opts.AllowAnonymousBind {
		// See the handleBind comment: 53 matches 389; Delta candidate vs
		// RFC 4511's 48.
		return Result{Code: ResultUnwillingToPerform, DiagnosticMessage: "anonymous bind disabled"}, false
	}
	if anonymous {
		return Result{Code: ResultSuccess}, true
	}
	if !c.isTLS && !s.opts.AllowCleartextBind {
		return Result{Code: ResultConfidentialityRequired, DiagnosticMessage: "cleartext bind disabled"}, false
	}

	dn, err := config.ParseDN(req.Name)
	if err != nil {
		// A malformed bind DN is reported as invalidCredentials so the
		// result cannot distinguish "bad syntax" from "unknown user".
		return Result{Code: ResultInvalidCredentials, DiagnosticMessage: "invalid credentials"}, false
	}

	// Directory Manager: compared via Identity.VerifyPassword only; the
	// verifier owns the constant-time contract.
	if s.hasDM && dn.EqualFold(s.dmDN) {
		if s.opts.DirectoryManager.VerifyPassword(req.Password) {
			c.setSubject(Subject{DN: s.dmDN, BypassACI: true})
			return Result{Code: ResultSuccess}, true
		}
		return Result{Code: ResultInvalidCredentials, DiagnosticMessage: "invalid credentials"}, false
	}

	entry, err := s.lookupEntry(ctx, dn)
	if err != nil {
		return Result{Code: ResultInvalidCredentials, DiagnosticMessage: "invalid credentials"}, false
	}
	for _, v := range entry.Values("userPassword") {
		// T-134 replaces this plaintext comparison with scheme-aware hash
		// verification (PBKDF2-SHA256 / SSHA512) behind a password-policy
		// seam; the constant-time comparison discipline stays.
		if subtle.ConstantTimeCompare(v, req.Password) == 1 {
			c.setSubject(Subject{DN: dn})
			return Result{Code: ResultSuccess}, true
		}
	}
	return Result{Code: ResultInvalidCredentials, DiagnosticMessage: "invalid credentials"}, false
}

// lookupEntry reads one entry for the bind path; every failure maps to the
// same condition so bind cannot probe existence.
func (s *Server) lookupEntry(ctx context.Context, dn config.DN) (*Entry, error) {
	var entry *Entry
	err := s.opts.Store.View(ctx, func(tx ReadTx) error {
		e, err := tx.Entry(ctx, dn)
		if err != nil {
			return err
		}
		entry = e
		return nil
	})
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, errors.New("ldapserver: bind lookup returned no entry")
	}
	return entry, nil
}
