package ldapserver

import (
	"errors"
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// RFC 4528 Assertion control (OIDAssertion), parity contract C9 / Delta
// D7: the control plane relies on it for If-Match-style conditional
// updates, so the control is advertised on the Root DSE *because* it is
// honored — never advertise-and-no-op.
//
// Scope: the control is honored on Modify, where it is evaluated against
// the pre-modification entry inside the same Store.Update transaction as
// the write (T-130's atomic read-then-write), so a concurrent
// modification that falsifies the assertion reliably fails the second
// committer with assertionFailed (122). Add/Delete/ModifyDN are
// deliberately not covered: what an assertion against a not-yet-existing
// (Add) or post-delete entry should mean is unverified against the 389
// oracle, so a critical assertion on those operations fails
// unavailableCriticalExtension rather than guessing (Delta candidate for
// T-147; extend coverage once the oracle answer is recorded).
//
// Failure mapping:
//   - assertion evaluates false → assertionFailed (122), nothing applied.
//   - missing, empty, malformed, or duplicated control value →
//     protocolError (the control value is a BER-encoded SearchFilter, RFC
//     4528 section 2).
//
// Assertion evaluation uses the same per-attribute search authorization and
// Undefined propagation as Search, inside the write transaction. A denied
// assertion never matches, including under NOT; filter content is never logged.
// assertionFailed diagnostics remain static. This is native-only D7
// infrastructure: the pinned 389 build does not implement RFC 4528.

// errAssertionFailed aborts the update transaction when the assertion
// filter does not match the pre-modification entry. mapWriteError
// (op_write.go) translates it to ResultAssertionFailed.
var errAssertionFailed = errors.New("ldapserver: assertion failed")

// parseAssertionFilter extracts the RFC 4528 control from controls. The
// boolean reports whether the control was present. A present control with
// a missing, malformed, or duplicated value fails with protocolError; the
// returned Result is the client-facing response.
func parseAssertionFilter(controls []Control) (Filter, bool, Result, error) {
	fail := func(diag string, err error) (Filter, bool, Result, error) {
		return nil, false, Result{Code: ResultProtocolError, DiagnosticMessage: diag}, err
	}
	var raw []byte
	found := false
	for _, ctrl := range controls {
		if ctrl.OID != OIDAssertion {
			continue
		}
		if found {
			// RFC 4528 section 2: the control must not appear more than
			// once on a request.
			return fail("duplicate assertion control", errors.New("ldapserver: duplicate assertion control"))
		}
		raw, found = ctrl.Value, true
	}
	if !found {
		return nil, false, Result{}, nil
	}
	if len(raw) == 0 {
		return fail("assertion control requires a value", errors.New("ldapserver: assertion control without value"))
	}
	pkt := ber.DecodePacket(raw)
	if pkt == nil {
		return fail("malformed assertion filter", errors.New("ldapserver: assertion filter decode"))
	}
	filter, err := decodeFilter(pkt)
	if err != nil {
		return fail("malformed assertion filter", fmt.Errorf("ldapserver: assertion filter: %w", err))
	}
	return filter, true, Result{}, nil
}
