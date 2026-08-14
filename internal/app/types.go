package app

import (
	"github.com/hilather/go-lab-ldap-mcp/internal/config/v1alpha1"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

const (
	KindToken   = "token"
	KindSession = "session"
)

// Principal is the non-secret actor passed from REST or MCP.
type Principal struct {
	Kind   string
	ID     string
	Scopes directory.ScopeSet
}

type CreateUser = directory.UserSpec

// UpdateUser is a user patch plus the If-Match revision.
type UpdateUser struct {
	directory.UserPatch
	Revision directory.Revision `json:"revision"`
}

type Operation struct {
	Name  string
	Scope string
}

var (
	OpUserList       = Operation{Name: "user.list", Scope: v1alpha1.ScopeDirectoryRead}
	OpUserGet        = Operation{Name: "user.get", Scope: v1alpha1.ScopeDirectoryRead}
	OpUserCreate     = Operation{Name: "user.create", Scope: v1alpha1.ScopeDirectoryWrite}
	OpUserUpdate     = Operation{Name: "user.update", Scope: v1alpha1.ScopeDirectoryWrite}
	OpUserDelete     = Operation{Name: "user.delete", Scope: v1alpha1.ScopeDirectoryWrite}
	OpUserSetEnabled = Operation{Name: "user.set_enabled", Scope: v1alpha1.ScopeDirectoryWrite}
	OpUserPassword   = Operation{Name: "user.set_password", Scope: v1alpha1.ScopeDirectoryPassword}

	OpGroupList    = Operation{Name: "group.list", Scope: v1alpha1.ScopeDirectoryRead}
	OpGroupGet     = Operation{Name: "group.get", Scope: v1alpha1.ScopeDirectoryRead}
	OpGroupCreate  = Operation{Name: "group.create", Scope: v1alpha1.ScopeDirectoryWrite}
	OpGroupDelete  = Operation{Name: "group.delete", Scope: v1alpha1.ScopeDirectoryWrite}
	OpGroupMembers = Operation{Name: "group.members", Scope: v1alpha1.ScopeDirectoryWrite}

	OpSearch       = Operation{Name: "search", Scope: v1alpha1.ScopeDirectoryRead}
	OpBindTest     = Operation{Name: "bind_test", Scope: v1alpha1.ScopeDirectoryPassword}
	OpSchemaRead   = Operation{Name: "schema.read", Scope: v1alpha1.ScopeSchemaRead}
	OpCapabilities = Operation{Name: "capabilities", Scope: v1alpha1.ScopeDirectoryRead}
	OpBaseline     = Operation{Name: "baseline", Scope: v1alpha1.ScopeDirectoryRead}
	OpReset        = Operation{Name: "reset", Scope: v1alpha1.ScopeLabReset}
	OpExport       = Operation{Name: "export", Scope: v1alpha1.ScopeLabExport}
	OpAuditRead    = Operation{Name: "audit.read", Scope: v1alpha1.ScopeAuditRead}
)

// Baseline separates compiled expected/control revisions from the applied marker.
type Baseline struct {
	ExpectedRevision string `json:"expectedRevision"`
	AppliedRevision  string `json:"appliedRevision"`
	ControlRevision  string `json:"controlRevision"`
	MarkerDN         string `json:"markerDN,omitempty"`
	ApplyVersion     string `json:"applyVersion,omitempty"`
	AppliedAt        string `json:"appliedAt,omitempty"`
	Match            bool   `json:"match"`
}

// AuditIntent is a secret-free mutation/security event.
type AuditIntent struct {
	RequestID string
	Actor     string
	Action    string
	Target    string
	Result    string
	Before    string
	After     string
}

const (
	AuditSuccess = "success"
	AuditFailure = "failure"
)

// Secret is re-exported so transports do not need observability for passwords.
type Secret = observability.Secret
