package ldapserver

import (
	"context"
	"errors"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// Write operations (T-128). Every write runs inside one Store.Update so
// reads, ACI checks, the mutation, and Plugin.AfterWrite hooks commit
// atomically (ADR-0009 decision 7, parity contract C7). ACI is checked
// before existence where possible, so a denied caller gets
// insufficientAccessRights without learning whether the target exists.
//
// Schema enforcement (T-132, schema_registry.go): when the registry knows
// object classes at all, Add and Modify must leave the entry with
// resolvable objectClass values and every MUST attribute (inherited
// through SUP chains) present; an empty registry permits everything.

// inSuffix reports whether dn is the suffix or a descendant. Writes outside
// the managed suffix fail noSuchObject, matching 389's "no such suffix"
// behavior for out-of-backend targets.
func (s *Server) inSuffix(dn config.DN) bool {
	return dn.Equal(s.suffix) || dn.IsDescendantOf(s.suffix)
}

// parentDN returns the parent of dn. The canonical String form is
// re-parsed at the first unescaped comma so escaped separators inside an
// RDN value cannot split it.
func parentDN(dn config.DN) (config.DN, bool) {
	s := dn.String()
	esc := false
	for i, r := range s {
		if esc {
			esc = false
			continue
		}
		if r == '\\' {
			esc = true
			continue
		}
		if r == ',' {
			parent, err := config.ParseDN(s[i+1:])
			if err != nil {
				return config.DN{}, false
			}
			return parent, true
		}
	}
	return config.DN{}, false
}

// schemaCheckEntry applies the T-132 schema gate (checkEntrySchema in
// schema_registry.go) to the final attribute set of an Add or Modify.
func (s *Server) schemaCheckEntry(e *Entry) error {
	return checkEntrySchema(s.opts.Schema, e)
}

// handleAdd creates one leaf entry.
func (s *Server) handleAdd(ctx context.Context, c *conn, m *Message, req *AddRequest) ResultCode {
	subj := c.subject()
	respond := func(res Result) ResultCode {
		if ctx.Err() == nil {
			c.sendResult(m.ID, &AddResponse{Result: res})
		}
		return res.Code
	}
	dn, err := config.ParseDN(req.DN)
	if err != nil {
		return respond(Result{Code: ResultInvalidDNSyntax, DiagnosticMessage: "invalid entry DN"})
	}
	if !s.inSuffix(dn) {
		return respond(Result{Code: ResultNoSuchObject, DiagnosticMessage: "no such suffix"})
	}
	entry := &Entry{DN: dn.String(), Attributes: req.Attributes}
	err = s.opts.Store.Update(ctx, func(tx UpdateTx) error {
		// ACI before existence: denial must not reveal whether the DN is
		// taken (C8).
		if !s.allowed(ctx, tx, subj, dn, "", PermAdd) {
			return errDenied
		}
		if !dn.Equal(s.suffix) {
			parent, ok := parentDN(dn)
			if !ok {
				return errInvalidDN
			}
			if _, err := tx.Entry(ctx, parent); err != nil {
				return err // ErrNoSuchObject when the parent is absent
			}
		}
		// T-137: server-owned operational attributes are rejected on the
		// client request, then stamped after the schema gate so the check
		// sees the entry as the client sent it.
		if err := s.checkClientAttrs(req.Attributes); err != nil {
			return err
		}
		if err := s.schemaCheckEntry(entry); err != nil {
			return err
		}
		s.applyAddOpAttrs(entry, subj)
		if err := tx.Add(ctx, entry); err != nil {
			return err
		}
		return s.runPlugins(ctx, tx, WriteEvent{Op: WriteAdd, After: entry, Subject: subj})
	})
	if err != nil {
		return respond(mapWriteError(err))
	}
	return respond(Result{Code: ResultSuccess})
}

// errSchemaViolation maps to objectClassViolation; errInvalidDN to
// invalidDNSyntax. schemaViolation (schema_registry.go) wraps
// errSchemaViolation with the client-facing reason.
var (
	errSchemaViolation = errors.New("ldapserver: schema violation")
	errInvalidDN       = errors.New("ldapserver: invalid DN")
)

// mapWriteError extends resultFromError with the write-path conditions.
func mapWriteError(err error) Result {
	switch {
	case errors.Is(err, errSchemaViolation):
		msg := "schema violation"
		var sv *schemaViolation
		if errors.As(err, &sv) {
			msg = sv.reason
		}
		return Result{Code: ResultObjectClassViolation, DiagnosticMessage: msg}
	case errors.Is(err, errInvalidDN):
		return Result{Code: ResultInvalidDNSyntax, DiagnosticMessage: "invalid DN"}
	case errors.Is(err, errNoSuchAttribute):
		return Result{Code: ResultNoSuchAttribute, DiagnosticMessage: "no such attribute or value"}
	case errors.Is(err, errAttributeOrValueExists):
		return Result{Code: ResultAttributeOrValueExists, DiagnosticMessage: "attribute value already exists"}
	case errors.Is(err, errOperationalAttr):
		// Server-owned operational attribute on a client Add/Modify (RFC
		// 4512 NO-USER-MODIFICATION). 389's exact code is a Delta
		// candidate for the T-147 oracle.
		msg := "operational attribute is not client-modifiable"
		var oe *operationalAttrError
		if errors.As(err, &oe) {
			msg = "operational attribute " + oe.attr + " is not client-modifiable"
		}
		return Result{Code: ResultConstraintViolation, DiagnosticMessage: msg}
	case errors.Is(err, errPasswordTooShort):
		// D18: password-policy aborts join errPlugin, so this arm must
		// precede the generic plugin case. 389 answers constraintViolation.
		return Result{Code: ResultConstraintViolation, DiagnosticMessage: "password below minimum length"}
	case errors.Is(err, errPasswordInHistory):
		return Result{Code: ResultConstraintViolation, DiagnosticMessage: "password present in password history"}
	case errors.Is(err, errPlugin):
		// A plugin aborts the whole commit (C7); the client sees an
		// unwillingToPerform, matching 389's plugin-failure surface.
		// Do not globally remap 53: disabled-account, anonymous-off,
		// and other plugin aborts stay unwillingToPerform.
		return Result{Code: ResultUnwillingToPerform, DiagnosticMessage: "write rejected by plugin"}
	case errors.Is(err, errAssertionFailed):
		// RFC 4528: the entry did not match the assertion; nothing was
		// applied. The diagnostic stays static (no filter or attribute
		// content); 389's exact message is a Delta candidate for T-147.
		return Result{Code: ResultAssertionFailed, DiagnosticMessage: "assertion failed"}
	default:
		return resultFromError(err)
	}
}

var (
	errNoSuchAttribute        = errors.New("ldapserver: no such attribute")
	errAttributeOrValueExists = errors.New("ldapserver: attribute or value exists")
	errPlugin                 = errors.New("ldapserver: plugin rejected write")
)

// runPlugins invokes every Plugin.AfterWrite inside the current Update.
func (s *Server) runPlugins(ctx context.Context, tx UpdateTx, ev WriteEvent) error {
	for _, p := range s.opts.Plugins {
		if err := p.AfterWrite(ctx, tx, ev); err != nil {
			return errors.Join(errPlugin, err)
		}
	}
	return nil
}

// handleModify applies RFC 4511 section 4.6 changes to one entry. When the
// request carries the RFC 4528 assertion control (T-141, ctrl_assert.go),
// the assertion filter is evaluated against the pre-modification entry
// inside the same Store.Update transaction as the write, so the check and
// the change commit atomically (parity contract C9; ADR-0009 decision 7).
func (s *Server) handleModify(ctx context.Context, c *conn, m *Message, req *ModifyRequest) ResultCode {
	subj := c.subject()
	respond := func(res Result) ResultCode {
		if ctx.Err() == nil {
			c.sendResult(m.ID, &ModifyResponse{Result: res})
		}
		return res.Code
	}
	assertion, asserted, res, err := parseAssertionFilter(m.Controls)
	if err != nil {
		return respond(res)
	}
	dn, err := config.ParseDN(req.DN)
	if err != nil {
		return respond(Result{Code: ResultInvalidDNSyntax, DiagnosticMessage: "invalid entry DN"})
	}
	err = s.opts.Store.Update(ctx, func(tx UpdateTx) error {
		if !s.allowed(ctx, tx, subj, dn, "", PermWrite) {
			return errDenied
		}
		before, err := tx.Entry(ctx, dn)
		if err != nil {
			return err
		}
		// T-141: a false assertion aborts the transaction; nothing is
		// applied. ACI denial takes precedence over the assertion outcome
		// so a denied caller cannot probe entry state through the codes.
		if asserted && !s.assertionMatches(before, assertion) {
			return errAssertionFailed
		}
		after := cloneEntry(before)
		for _, ch := range req.Changes {
			if !s.allowed(ctx, tx, subj, dn, ch.Attr.Name, PermWrite) {
				return errDenied
			}
			// T-137: operational attributes are server-owned (RFC 4512
			// NO-USER-MODIFICATION); internal writes — the write plugins
			// and the T-134 lockout stamp — go through the store directly
			// and never cross this gate.
			if !s.clientModifiable(ch.Attr.Name) {
				return &operationalAttrError{attr: ch.Attr.Name}
			}
			if err := s.applyChange(after, ch); err != nil {
				return err
			}
		}
		// T-132: the resulting entry must still satisfy schema — deleting
		// a MUST attribute or the last objectClass fails
		// objectClassViolation and rolls the transaction back.
		if err := s.schemaCheckEntry(after); err != nil {
			return err
		}
		s.applyModifyOpAttrs(after, subj)
		if err := tx.Replace(ctx, after); err != nil {
			return err
		}
		return s.runPlugins(ctx, tx, WriteEvent{Op: WriteModify, Before: before, After: after, Subject: subj})
	})
	if err != nil {
		return respond(mapWriteError(err))
	}
	return respond(Result{Code: ResultSuccess})
}

// applyChange applies one RFC 4511 modification. Value matching folds case
// per the attribute's equality rule (the T-131 stub in filter_eval.go).
//
// Semantics follow RFC 4511 section 4.6: add fails attributeOrValueExists
// on a duplicate; delete of a missing attribute or value fails
// noSuchAttribute; replace creates an absent attribute and deletes the
// attribute when given no values. Where 389-observed behavior diverges
// (389 historically tolerates some delete-of-missing cases), this
// implementation follows the RFC; record any 389 divergence found by the
// T-147 oracle as a parity Delta.
func (s *Server) applyChange(e *Entry, ch ModifyChange) error {
	idx := attrIndex(e, ch.Attr.Name)
	fold := foldCase(s.opts.Schema, ch.Attr.Name)
	switch ch.Op {
	case ModifyAdd:
		if idx < 0 {
			e.Attributes = append(e.Attributes, Attribute{Name: ch.Attr.Name, Values: dedupValues(ch.Attr.Values, fold)})
			return nil
		}
		for _, v := range ch.Attr.Values {
			if hasValue(e.Attributes[idx].Values, v, fold) {
				return errAttributeOrValueExists
			}
		}
		e.Attributes[idx].Values = append(e.Attributes[idx].Values, dedupValues(ch.Attr.Values, fold)...)
		return nil
	case ModifyDelete:
		if idx < 0 {
			return errNoSuchAttribute
		}
		if len(ch.Attr.Values) == 0 {
			e.Attributes = append(e.Attributes[:idx], e.Attributes[idx+1:]...)
			return nil
		}
		for _, v := range ch.Attr.Values {
			if !hasValue(e.Attributes[idx].Values, v, fold) {
				return errNoSuchAttribute
			}
		}
		for _, v := range ch.Attr.Values {
			e.Attributes[idx].Values = removeValue(e.Attributes[idx].Values, v, fold)
		}
		if len(e.Attributes[idx].Values) == 0 {
			e.Attributes = append(e.Attributes[:idx], e.Attributes[idx+1:]...)
		}
		return nil
	case ModifyReplace:
		if idx >= 0 {
			e.Attributes = append(e.Attributes[:idx], e.Attributes[idx+1:]...)
		}
		if len(ch.Attr.Values) == 0 {
			return nil
		}
		e.Attributes = append(e.Attributes, Attribute{Name: ch.Attr.Name, Values: dedupValues(ch.Attr.Values, fold)})
		return nil
	default:
		return errInvalidDN // unreachable: the codec bounds the enum
	}
}

func attrIndex(e *Entry, name string) int {
	for i, a := range e.Attributes {
		if strings.EqualFold(a.Name, name) {
			return i
		}
	}
	return -1
}

func hasValue(values [][]byte, v []byte, fold bool) bool {
	for _, x := range values {
		if valueEqual(fold, x, v) {
			return true
		}
	}
	return false
}

func removeValue(values [][]byte, v []byte, fold bool) [][]byte {
	out := values[:0]
	for _, x := range values {
		if !valueEqual(fold, x, v) {
			out = append(out, x)
		}
	}
	return out
}

func dedupValues(values [][]byte, fold bool) [][]byte {
	var out [][]byte
	for _, v := range values {
		if !hasValue(out, v, fold) {
			out = append(out, v)
		}
	}
	return out
}

// handleDelete removes one leaf entry.
func (s *Server) handleDelete(ctx context.Context, c *conn, m *Message, req *DeleteRequest) ResultCode {
	subj := c.subject()
	respond := func(res Result) ResultCode {
		if ctx.Err() == nil {
			c.sendResult(m.ID, &DeleteResponse{Result: res})
		}
		return res.Code
	}
	dn, err := config.ParseDN(req.DN)
	if err != nil {
		return respond(Result{Code: ResultInvalidDNSyntax, DiagnosticMessage: "invalid entry DN"})
	}
	err = s.opts.Store.Update(ctx, func(tx UpdateTx) error {
		if !s.allowed(ctx, tx, subj, dn, "", PermDelete) {
			return errDenied
		}
		before, err := tx.Entry(ctx, dn)
		if err != nil {
			return err
		}
		// The store guards the tree shape: ErrNotLeaf maps to
		// notAllowedOnNonLeaf.
		if err := tx.Delete(ctx, dn); err != nil {
			return err
		}
		return s.runPlugins(ctx, tx, WriteEvent{Op: WriteDelete, Before: before, Subject: subj})
	})
	if err != nil {
		return respond(mapWriteError(err))
	}
	return respond(Result{Code: ResultSuccess})
}

// handleCompare asserts one attribute value (RFC 4511 section 4.10).
func (s *Server) handleCompare(ctx context.Context, c *conn, m *Message, req *CompareRequest) ResultCode {
	subj := c.subject()
	respond := func(res Result) ResultCode {
		if ctx.Err() == nil {
			c.sendResult(m.ID, &CompareResponse{Result: res})
		}
		return res.Code
	}
	dn, err := config.ParseDN(req.DN)
	if err != nil {
		return respond(Result{Code: ResultInvalidDNSyntax, DiagnosticMessage: "invalid entry DN"})
	}
	code := ResultCompareFalse
	err = s.opts.Store.View(ctx, func(tx ReadTx) error {
		// Compare permission is checked before existence so a denial
		// cannot be distinguished from a missing entry (C8).
		if !s.allowed(ctx, tx, subj, dn, req.Attr, PermCompare) {
			return errDenied
		}
		e, err := tx.Entry(ctx, dn)
		if err != nil {
			return err
		}
		fold := foldCase(s.opts.Schema, req.Attr)
		for _, v := range e.Values(req.Attr) {
			if valueEqual(fold, v, req.Value) {
				code = ResultCompareTrue
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return respond(mapWriteError(err))
	}
	return respond(Result{Code: code})
}

// handleModifyDN renames an entry or moves it within the managed suffix
// (RFC 4511 section 4.9). The subtree move is atomic through Store.Rename.
func (s *Server) handleModifyDN(ctx context.Context, c *conn, m *Message, req *ModifyDNRequest) ResultCode {
	subj := c.subject()
	respond := func(res Result) ResultCode {
		if ctx.Err() == nil {
			c.sendResult(m.ID, &ModifyDNResponse{Result: res})
		}
		return res.Code
	}
	dn, err := config.ParseDN(req.DN)
	if err != nil {
		return respond(Result{Code: ResultInvalidDNSyntax, DiagnosticMessage: "invalid entry DN"})
	}
	newRDN, err := config.ParseDN(req.NewRDN)
	if err != nil || newRDN.Depth() != 1 {
		return respond(Result{Code: ResultInvalidDNSyntax, DiagnosticMessage: "invalid new RDN"})
	}
	superior := config.DN{}
	if req.NewSuperior != "" {
		superior, err = config.ParseDN(req.NewSuperior)
		if err != nil {
			return respond(Result{Code: ResultInvalidDNSyntax, DiagnosticMessage: "invalid new superior"})
		}
	} else {
		p, ok := parentDN(dn)
		if !ok {
			// A root-level DN has no parent to rename under.
			return respond(Result{Code: ResultUnwillingToPerform, DiagnosticMessage: "cannot rename the suffix root"})
		}
		superior = p
	}
	if dn.Equal(s.suffix) {
		// Renaming the suffix root itself is outside the lab model.
		return respond(Result{Code: ResultUnwillingToPerform, DiagnosticMessage: "cannot rename the suffix root"})
	}
	if !s.inSuffix(dn) || !s.inSuffix(superior) {
		// Moves outside the managed suffix are refused; 389 answers
		// affectsMultipleDSAs for cross-backend moves — pinned as reserved
		// for parity — so unwillingToPerform stands here (Delta candidate
		// for the T-147 oracle).
		return respond(Result{Code: ResultUnwillingToPerform, DiagnosticMessage: "rename must stay within the managed suffix"})
	}
	newDN := joinDN(newRDN, superior)

	err = s.opts.Store.Update(ctx, func(tx UpdateTx) error {
		if !s.allowed(ctx, tx, subj, dn, "", PermWrite) {
			return errDenied
		}
		// The destination is an add-like check so a caller cannot rename
		// into a subtree where they may not create entries.
		if !s.allowed(ctx, tx, subj, newDN, "", PermAdd) {
			return errDenied
		}
		before, err := tx.Entry(ctx, dn)
		if err != nil {
			return err
		}
		if err := tx.Rename(ctx, dn, newDN); err != nil {
			return err
		}
		after, err := tx.Entry(ctx, newDN)
		if err != nil {
			return err
		}
		// Maintain RDN attributes on the moved entry: add the new RDN
		// value, and drop the old one when deleteoldrdn is set.
		oldAttr, oldVal, _ := dn.Leaf()
		newAttr, newVal, _ := newRDN.Leaf()
		if !hasValue(after.Values(newAttr), []byte(newVal), foldCase(s.opts.Schema, newAttr)) {
			after.Attributes = upsertValue(after, newAttr, []byte(newVal))
		}
		if req.DeleteOldRDN && (oldAttr != newAttr || oldVal != newVal) {
			if idx := attrIndex(after, oldAttr); idx >= 0 {
				after.Attributes[idx].Values = removeValue(after.Attributes[idx].Values, []byte(oldVal), foldCase(s.opts.Schema, oldAttr))
				if len(after.Attributes[idx].Values) == 0 {
					after.Attributes = append(after.Attributes[:idx], after.Attributes[idx+1:]...)
				}
			}
		}
		// A rename is a modification of the entry (T-137).
		s.applyModifyOpAttrs(after, subj)
		if err := tx.Replace(ctx, after); err != nil {
			return err
		}
		return s.runPlugins(ctx, tx, WriteEvent{Op: WriteRename, Before: before, After: after, Subject: subj})
	})
	if err != nil {
		return respond(mapWriteError(err))
	}
	return respond(Result{Code: ResultSuccess})
}

// joinDN concatenates a single-RDN DN with a parent DN.
func joinDN(rdn, parent config.DN) config.DN {
	joined := rdn.String() + "," + parent.String()
	d, err := config.ParseDN(joined)
	if err != nil {
		// Both inputs are parsed DNs, so joining cannot fail; fall back to
		// the parent (the subsequent store lookup will miss safely).
		return parent
	}
	return d
}

// upsertValue appends v to the named attribute, creating it if absent.
func upsertValue(e *Entry, name string, v []byte) []Attribute {
	idx := attrIndex(e, name)
	if idx < 0 {
		return append(e.Attributes, Attribute{Name: name, Values: [][]byte{v}})
	}
	e.Attributes[idx].Values = append(e.Attributes[idx].Values, v)
	return e.Attributes
}
