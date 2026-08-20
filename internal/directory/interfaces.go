package directory

import (
	"context"
	"io"

	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

// UserRepository is the runtime user surface. Implementations live in ds389.
type UserRepository interface {
	List(ctx context.Context, q UserListQuery) (UserPage, error)
	Get(ctx context.Context, id UserID) (User, error)
	Add(ctx context.Context, u UserSpec) (User, error)
	Modify(ctx context.Context, id UserID, patch UserPatch, rev Revision) (User, error)
	SetEnabled(ctx context.Context, id UserID, enabled bool, rev Revision) (User, error)
	Delete(ctx context.Context, id UserID, rev Revision) error
	SetPassword(ctx context.Context, id UserID, password observability.Secret, rev Revision, mustChange bool) error
	AccountState(ctx context.Context, id UserID) (AccountState, error)
	ExpirePassword(ctx context.Context, id UserID, rev Revision) (AccountState, error)
	ClearPasswordExpiry(ctx context.Context, id UserID, rev Revision) (AccountState, error)
	Lock(ctx context.Context, id UserID, rev Revision) (AccountState, error)
	Unlock(ctx context.Context, id UserID, rev Revision) (AccountState, error)
}

// GroupRepository is list/get/add/delete plus membership. v1 has no Modify/GroupPatch.
type GroupRepository interface {
	List(ctx context.Context, q GroupListQuery) (GroupPage, error)
	Get(ctx context.Context, id GroupID) (Group, error)
	Add(ctx context.Context, g GroupSpec) (Group, error)
	Delete(ctx context.Context, id GroupID, rev Revision) error
	AddMembers(ctx context.Context, id GroupID, members []MemberRef, rev Revision) (MembershipSummary, error)
	RemoveMembers(ctx context.Context, id GroupID, members []MemberRef, rev Revision) (MembershipSummary, error)
	ReplaceMembers(ctx context.Context, id GroupID, members []MemberRef, rev Revision) (MembershipSummary, error)
}

type SearchRepository interface {
	Search(ctx context.Context, q SearchQuery) (SearchPage, error)
}

// EntryRepository is defined in entry.go (ADR-0011 structured entries).

type BindTester interface {
	BindTest(ctx context.Context, identity string, password observability.Secret, t Transport) (BindTestResult, error)
}

type SchemaRepository interface {
	RootDSE(ctx context.Context) (RootDSE, error)
	Schema(ctx context.Context) (Schema, error)
}

type ResetSupport interface {
	Inventory(ctx context.Context) (ManagedInventory, error)
	// DeleteManaged removes one DN under people/groups, or an operator
	// extra under an additional managed suffix. It must refuse the
	// runtime account, required containers, the marker, additional
	// suffix roots, and anything under the primary suffix outside
	// people/groups. Missing entries are success.
	DeleteManaged(ctx context.Context, dn string) error
	Export(ctx context.Context, w io.Writer, opts ExportOptions) error
}

// CapabilityInspector is the runtime inspect surface for the shared Capabilities report.
type CapabilityInspector interface {
	Capabilities(ctx context.Context) (Capabilities, error)
}

type MarkerReader interface {
	ReadMarker(ctx context.Context) (BaselineMarker, error)
}
