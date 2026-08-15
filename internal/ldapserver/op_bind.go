package ldapserver

import (
	"context"
)

// handleBind processes one bind request inline on the connection read loop.
// It reports whether the connection stays open (the pre-auth budget in
// ADR-0009 decision 10 closes it after too many failures).
//
// T-125 stub: the real simple-bind path (store lookup, Directory Manager
// identity, policy gates) lands in T-126.
func (s *Server) handleBind(ctx context.Context, c *conn, m *Message, req *BindRequest) bool {
	// The bind password must not outlive authentication; scrub the decoded
	// request regardless of outcome.
	defer ZeroSecrets(m)
	if res, ok := s.checkControls(m); !ok {
		c.sendResult(m.ID, &BindResponse{Result: res})
		s.metrics().ObserveOperation("bind", res.Code)
		return true
	}
	code := ResultUnwillingToPerform
	if ctx.Err() == nil {
		c.sendResult(m.ID, &BindResponse{Result: Result{
			Code:              code,
			DiagnosticMessage: "bind lands in T-126",
		}})
	}
	s.metrics().ObserveOperation("bind", code)
	return true
}
