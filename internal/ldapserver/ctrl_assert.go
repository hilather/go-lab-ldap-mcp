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
// The filter is evaluated against the stored entry as the server sees it,
// after the entry-level write-ACI check. A subject holding write but not
// read on an attribute can therefore probe that attribute's values through
// crafted assertions — the runtime ACI set grants read wherever it grants
// write on an entry, so no additional filtering is applied; 389's exact
// ACI interaction here is a Delta candidate for the T-147 oracle.
// Assertion filter content is never logged and the assertionFailed
// diagnostic is a static string.

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

// assertionMatches evaluates the assertion filter against the
// pre-modification entry with the schema's matching rules (T-131).
func (s *Server) assertionMatches(before *Entry, assertion Filter) bool {
	return matchFilter(before, assertion, s.opts.Schema)
}
