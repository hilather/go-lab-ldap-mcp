package ldapserver

import (
	"context"
)

// RFC 4532 WhoAmI extended operation (OIDWhoAmI, T-142; parity contract
// C9/C10: the Root DSE has advertised OIDWhoAmI in supportedExtension
// since T-127, so the handler must exist for the advertisement to be
// true).
//
// The response carries no responseName and a responseValue holding the
// authzId of the currently bound identity: "dn:" followed by the bound
// DN, or an empty (present, zero-length) responseValue for the anonymous
// identity. This matches the 389-observed wire form; if the T-147 oracle
// shows a different rendering (e.g. case-normalized DN or an absent
// responseValue for anonymous), that is a Delta candidate.
//
// The handler reads only the connection's Subject and touches no
// credentials; the authzId echoes the identity the client already proved
// by binding, so no ACI check applies.
func (s *Server) handleWhoAmI(ctx context.Context, c *conn, m *Message, req *ExtendedRequest) ResultCode {
	respond := func(res Result, value []byte) ResultCode {
		if ctx.Err() == nil {
			c.sendResult(m.ID, &ExtendedResponse{Result: res, Value: value})
		}
		return res.Code
	}
	// RFC 4532 section 2: the request has no value field.
	if len(req.Value) != 0 {
		return respond(Result{
			Code:              ResultProtocolError,
			DiagnosticMessage: "whoami request value must be absent",
		}, nil)
	}
	subj := c.subject()
	// Anonymous covers both the pre-bind zero Subject (no DN) and the
	// post-anonymous-bind Subject (Anonymous set). Only a bound,
	// DN-carrying identity yields a "dn:" authzId.
	if subj.Anonymous || subj.DN.String() == "" {
		// Non-nil empty slice so the encoder emits a present, empty
		// responseValue (RFC 4532 section 2: anonymous maps to the empty
		// authzId).
		return respond(Result{Code: ResultSuccess}, []byte{})
	}
	return respond(Result{Code: ResultSuccess}, []byte("dn:"+subj.DN.String()))
}
