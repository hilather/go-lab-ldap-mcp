package ldapserver

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"
)

// op_attrs.go is the T-137 operational-attribute maintenance (parity
// contract C5): the server — never the client — owns entryUUID,
// createTimestamp, modifyTimestamp, creatorsName, and modifiersName. Add
// stamps all five; Modify and ModifyDN bump modifyTimestamp and
// modifiersName. The write-path plugins (T-135/T-136) deliberately do not
// bump these attributes on the entries they repair; 389's internal
// plugin ops do, which is recorded as a Delta candidate for the T-147
// oracle.
//
// Attributes declared Operational by the schema (these five plus memberOf
// and pwdAccountLockedTime) are rejected when they arrive on a client Add
// or Modify: RFC 4512 NO-USER-MODIFICATION. 389's exact result code for
// this is recorded as a Delta candidate; constraintViolation (19) is used
// here. nsAccountLock is a *user* attribute (the registry deliberately does
// not mark it operational) because disabling an account is a client write
// of nsAccountLock: true — the bind gate below enforces it.

// errOperationalAttr marks client writes carrying server-owned attributes.
var errOperationalAttr = errors.New("ldapserver: operational attribute is not client-modifiable")

// operationalAttrError names the rejected attribute for the client
// diagnostic while mapping to constraintViolation through errOperationalAttr.
type operationalAttrError struct{ attr string }

func (e *operationalAttrError) Error() string {
	return "ldapserver: attribute " + e.attr + ": " + errOperationalAttr.Error()
}
func (e *operationalAttrError) Unwrap() error { return errOperationalAttr }

// now returns the current time from the injected clock (tests) or the
// system clock.
func (s *Server) now() time.Time {
	if s.opts.Clock != nil {
		return s.opts.Clock()
	}
	return time.Now()
}

// newEntryUUID returns the entryUUID for a new entry: the injected
// generator when set (tests), otherwise a random RFC 4122 version 4 UUID.
// 389's entryUUID namespace differs; presence after Add is the Contract
// (C5), format is a recorded Delta candidate.
func (s *Server) newEntryUUID() string {
	if s.opts.NewUUID != nil {
		if id := s.opts.NewUUID(); id != "" {
			return id
		}
	}
	return randomUUID()
}

// randomUUID formats 16 crypto/rand bytes as an RFC 4122 version 4 UUID.
// A crypto/rand failure cannot be recovered into a panic (AGENTS.md); the
// time-derived fallback keeps the value unique enough for a lab directory.
func randomUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("time-%x", time.Now().UnixNano())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// generalizedTime renders t in RFC 4517 Generalized Time (UTC, second
// granularity), matching 389's createTimestamp/modifyTimestamp wire form.
func generalizedTime(t time.Time) string {
	return t.UTC().Format("20060102150405Z")
}

// applyAddOpAttrs stamps the server-maintained attributes on a new entry.
// modifiersName/creatorsName record the bound subject's DN; an anonymous
// subject (possible only under a permissive test ACI) records the empty DN.
func (s *Server) applyAddOpAttrs(e *Entry, subj Subject) {
	ts := []byte(generalizedTime(s.now()))
	who := []byte(subj.DN.String())
	setAttr(e, "entryUUID", []byte(s.newEntryUUID()))
	setAttr(e, "createTimestamp", ts)
	setAttr(e, "modifyTimestamp", ts)
	setAttr(e, "creatorsName", who)
	setAttr(e, "modifiersName", who)
}

// applyModifyOpAttrs bumps the modification markers on a changed entry
// (Modify and ModifyDN). createTimestamp, creatorsName, and entryUUID never
// change.
func (s *Server) applyModifyOpAttrs(e *Entry, subj Subject) {
	setAttr(e, "modifyTimestamp", []byte(generalizedTime(s.now())))
	setAttr(e, "modifiersName", []byte(subj.DN.String()))
}

// clientModifiable reports whether a client write may carry attr. Unknown
// attributes are treated as user attributes; schema-declared Operational
// attributes are server-owned.
func (s *Server) clientModifiable(attr string) bool {
	at, ok := s.opts.Schema.AttributeType(attr)
	if !ok {
		return true
	}
	return !at.Operational
}

// checkClientAttrs rejects server-owned operational attributes in a client
// Add request.
func (s *Server) checkClientAttrs(attrs []Attribute) error {
	for _, a := range attrs {
		if !s.clientModifiable(a.Name) {
			return &operationalAttrError{attr: a.Name}
		}
	}
	return nil
}

// accountLocked reports whether the entry carries nsAccountLock: true
// (caseIgnoreMatch per the registry). The bind path rejects locked accounts
// with unwillingToPerform (53) before any password comparison — 389-observed
// (ADR-0009 decision 18, parity contract C3). The entry itself stays
// searchable; only binds are refused.
func accountLocked(e *Entry) bool {
	for _, v := range e.Values("nsAccountLock") {
		if strings.EqualFold(strings.TrimSpace(string(v)), "true") {
			return true
		}
	}
	return false
}
