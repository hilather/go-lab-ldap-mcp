package ldapserver

import (
	"context"
	"errors"
	"log/slog"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// errDenied marks an ACI denial inside handlers; dispatch maps it to
// insufficientAccessRights. The diagnostic never names a DN, so a denied
// caller cannot use the result to probe entry existence (parity contract
// C8; see the per-op comments).
var errDenied = errors.New("ldapserver: access denied")

// dispatchOp routes one request message to its operation handler. Handlers
// send their own responses and return the result code for metrics. When
// ctx is canceled (abandon or shutdown) the handler skips its response:
// an abandoned operation gets no response PDU (RFC 4511 section 4.11).
func (s *Server) dispatchOp(ctx context.Context, c *conn, m *Message) {
	name := opName(m.Op)
	if res, ok := s.refuseUnauthenticated(c); !ok {
		c.sendResult(m.ID, responseFor(m.Op, res))
		s.metrics().ObserveOperation(name, res.Code)
		return
	}
	if res, ok := s.checkControls(m); !ok {
		c.sendResult(m.ID, responseFor(m.Op, res))
		s.metrics().ObserveOperation(name, res.Code)
		return
	}
	var code ResultCode
	switch op := m.Op.(type) {
	case *SearchRequest:
		code = s.handleSearch(ctx, c, m, op)
	case *AddRequest:
		code = s.handleAdd(ctx, c, m, op)
	case *ModifyRequest:
		code = s.handleModify(ctx, c, m, op)
	case *DeleteRequest:
		code = s.handleDelete(ctx, c, m, op)
	case *ModifyDNRequest:
		code = s.handleModifyDN(ctx, c, m, op)
	case *CompareRequest:
		code = s.handleCompare(ctx, c, m, op)
	case *ExtendedRequest:
		code = s.handleExtended(ctx, c, m, op)
	default:
		// Unreachable for codec-produced messages; defensive only.
		code = ResultProtocolError
		c.sendResult(m.ID, responseFor(m.Op, Result{
			Code:              code,
			DiagnosticMessage: "unsupported operation",
		}))
	}
	s.metrics().ObserveOperation(name, code)
}

// refuseUnauthenticated implements KD-6 / D21 / D24: when
// AllowAnonymousBind is off, unauthenticated directory operations are
// refused with inappropriateAuthentication (48), matching pinned 389.
// That includes Search of the suffix, Root DSE, and subschema; Compare;
// writes; and extended ops other than StartTLS (StartTLS is handled in
// the read loop and never reaches dispatch). WhoAmI on a pre-bind
// connection collapses to the same 48 (D14). Production capability
// inspect uses the bound runtime pool, so bound Root DSE search is
// unaffected.
func (s *Server) refuseUnauthenticated(c *conn) (Result, bool) {
	if s.opts.AllowAnonymousBind {
		return Result{}, true
	}
	if aciAuthenticatedA(c.subject()) {
		return Result{}, true
	}
	return Result{
		Code:              ResultInappropriateAuthentication,
		DiagnosticMessage: "anonymous access disabled",
	}, false
}

// checkControls enforces the critical-control contract (parity contract
// C9): a critical control the engine does not honor must fail the whole
// operation with unavailableCriticalExtension; non-critical unknown
// controls are ignored.
func (s *Server) checkControls(m *Message) (Result, bool) {
	for _, ctrl := range m.Controls {
		switch ctrl.OID {
		case OIDSimplePagedResults:
			// Honored by search (T-127); meaningless elsewhere.
			if _, isSearch := m.Op.(*SearchRequest); isSearch {
				continue
			}
			if ctrl.Critical {
				return Result{
					Code:              ResultUnavailableCriticalExtension,
					DiagnosticMessage: "paged results control is only valid on search",
				}, false
			}
		case OIDAssertion:
			// RFC 4528 assertion control (T-141): honored on Modify at
			// either criticality. On other operations a critical assertion
			// must not be silently ignored (parity contract C9: do not
			// advertise and no-op).
			if _, isModify := m.Op.(*ModifyRequest); isModify {
				continue
			}
			if ctrl.Critical {
				return Result{
					Code:              ResultUnavailableCriticalExtension,
					DiagnosticMessage: "assertion control is only honored on modify",
				}, false
			}
		default:
			if ctrl.Critical {
				return Result{
					Code:              ResultUnavailableCriticalExtension,
					DiagnosticMessage: "unsupported critical control",
				}, false
			}
		}
	}
	return Result{}, true
}

// allowed evaluates one ACI check as the connection's subject inside the
// operation's store transaction. ACI engine errors fail closed.
func (s *Server) allowed(ctx context.Context, tx ReadTx, subj Subject, target config.DN, attr string, perm Permission) bool {
	ok, err := s.opts.ACI.Allowed(ctx, tx, ACICheck{
		Subject:   subj,
		Target:    target,
		Attribute: attr,
		Perm:      perm,
	})
	if err != nil {
		s.opts.Logger.LogAttrs(ctx, slog.LevelWarn, "aci evaluation failed; denying",
			slog.String("error", err.Error()), slog.String("perm", string(perm)))
		return false
	}
	return ok
}

// resultFromError maps store-domain and context errors to LDAP results.
// Handlers pre-validate DNs, so config parse errors should not reach here.
func resultFromError(err error) Result {
	switch {
	case errors.Is(err, errDenied):
		return Result{Code: ResultInsufficientAccessRights, DiagnosticMessage: "insufficient access"}
	case errors.Is(err, ErrNoSuchObject):
		return Result{Code: ResultNoSuchObject, DiagnosticMessage: "no such object"}
	case errors.Is(err, ErrEntryExists):
		return Result{Code: ResultEntryAlreadyExists, DiagnosticMessage: "entry already exists"}
	case errors.Is(err, ErrNotLeaf):
		return Result{Code: ResultNotAllowedOnNonLeaf, DiagnosticMessage: "entry has children"}
	default:
		return Result{Code: ResultOperationsError, DiagnosticMessage: "internal error"}
	}
}

// Extended operations: StartTLS (T-133) is intercepted inline by the
// connection read loop before dispatch (conn.go), so it never reaches
// here; WhoAmI (T-142) is dispatched like any other operation.

func (s *Server) handleExtended(ctx context.Context, c *conn, m *Message, req *ExtendedRequest) ResultCode {
	var code ResultCode
	switch req.Name {
	case OIDWhoAmI:
		return s.handleWhoAmI(ctx, c, m, req)
	case OIDStartTLS:
		// Unreachable: the read loop handles StartTLS inline. Defensive.
		code = ResultUnwillingToPerform
	default:
		// RFC 4511 section 4.12: unrecognized extended request.
		code = ResultProtocolError
	}
	if ctx.Err() == nil {
		c.sendResult(m.ID, &ExtendedResponse{Result: Result{
			Code:              code,
			DiagnosticMessage: "extended operation not implemented",
		}})
	}
	return code
}
