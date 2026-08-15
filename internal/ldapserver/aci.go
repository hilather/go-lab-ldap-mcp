package ldapserver

import (
	"context"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// Permission is one ACI permission from the LabLDAP compiler subset (parity
// contract C8). The ACI parser (T-138) must reject out-of-grammar
// permissions rather than ignore them.
type Permission string

const (
	PermRead    Permission = "read"
	PermSearch  Permission = "search"
	PermCompare Permission = "compare"
	PermAdd     Permission = "add"
	PermDelete  Permission = "delete"
	PermWrite   Permission = "write"
)

// Subject is the bound identity an operation runs as. The zero DN with
// Anonymous set is the pre-bind identity. BypassACI is exactly the
// Directory Manager property (ADR-0009 decision 13): it is set by the bind
// path when the bound DN is the configured DM identity, and the ACI engine
// itself never grants it.
type Subject struct {
	DN        config.DN
	Anonymous bool
	BypassACI bool
}

// ACICheck is one access question: may Subject perform Perm on Target (and,
// when Attribute is non-empty, on that attribute of the target entry).
// Entry-level operations (add, delete, the search base) leave Attribute
// empty.
type ACICheck struct {
	Subject   Subject
	Target    config.DN
	Attribute string
	Perm      Permission
}

// ACIEngine evaluates the ACI text the LabLDAP compiler emits (parity
// contract C8: the runtime ACI set plus operator ACLs, deny-wins per 389
// observed behavior). Parsing is a separate seam (T-138); evaluation lands
// in T-139.
type ACIEngine interface {
	// Allowed reports whether check is permitted. groupdn clauses are
	// resolved by reading group entries through tx, so callers evaluate
	// inside the same store snapshot as the operation being authorized.
	// Subjects with BypassACI set are allowed without evaluation.
	Allowed(ctx context.Context, tx ReadTx, check ACICheck) (bool, error)
}
