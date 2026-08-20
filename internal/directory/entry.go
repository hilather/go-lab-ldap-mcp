package directory

import "context"

// Allowlisted structural classes for the structured entry API (ADR-0011).
// container is an alias of organizationalUnit on both engines.
const (
	ClassDomain             = "domain"
	ClassDCObject           = "dcObject"
	ClassOrganizationalUnit = "organizationalUnit"
	ClassContainer          = "container"
	ClassPerson             = "person"
	ClassInetOrgPerson      = "inetOrgPerson"
	ClassGroupOfNames       = "groupOfNames"
)

// EntryModOp is a structured attribute change. Not a raw LDAP BER modify.
const (
	EntryModReplace = "replace"
	EntryModAdd     = "add"
	EntryModDelete  = "delete"
)

// EntrySpec creates one allowlisted entry under a managed suffix.
type EntrySpec struct {
	DN            string            `json:"dn"`
	ObjectClasses []string          `json:"objectClasses"`
	Attributes    map[string]string `json:"attributes,omitempty"`
}

// EntryPatch is a revisioned attribute change by DN.
type EntryPatch struct {
	DN       string        `json:"dn"`
	Revision Revision      `json:"revision"`
	Changes  []EntryChange `json:"changes"`
}

// EntryChange is one allowlisted attribute replace/add/delete.
type EntryChange struct {
	Op     string   `json:"op"`
	Name   string   `json:"name"`
	Values []string `json:"values,omitempty"`
}

// EntryDelete is a destructive DN delete.
type EntryDelete struct {
	DN        string   `json:"dn"`
	Revision  Revision `json:"revision"`
	Confirm   bool     `json:"confirm"`
	Recursive bool     `json:"recursive,omitempty"`
}

// EntryMove is a rename or re-parent. NewDN must stay under a managed suffix.
type EntryMove struct {
	DN        string   `json:"dn"`
	NewDN     string   `json:"newDN"`
	Revision  Revision `json:"revision"`
	DeleteOld bool     `json:"deleteOldRdn"`
}

// TreeQuery lists one level (or a shallow hierarchy) under a managed base.
type TreeQuery struct {
	Base     string `json:"base"`
	PageSize int    `json:"pageSize,omitempty"`
	Cursor   string `json:"cursor,omitempty"`
}

// TreePage is a hierarchical listing of immediate children.
type TreePage struct {
	Base       string     `json:"base"`
	Nodes      []TreeNode `json:"nodes"`
	NextCursor string     `json:"nextCursor,omitempty"`
}

// TreeNode is one child of a tree listing.
type TreeNode struct {
	DN            string   `json:"dn"`
	RDN           string   `json:"rdn"`
	ObjectClasses []string `json:"objectClasses"`
	HasChildren   bool     `json:"hasChildren"`
	Revision      Revision `json:"revision,omitempty"`
}

// DirectoryEntry is a structured entry read (passwords stripped by the app).
type DirectoryEntry struct {
	DN            string   `json:"dn"`
	ObjectClasses []string `json:"objectClasses"`
	Attributes    []AttrKV `json:"attributes"`
	Revision      Revision `json:"revision"`
}

// SuffixList is the compiled managed suffix set.
type SuffixList struct {
	Primary    string   `json:"primary"`
	Additional []string `json:"additional"`
	All        []string `json:"all"`
}

// EntryRepository is the structured (not raw LDAP) entry surface.
type EntryRepository interface {
	CreateEntry(ctx context.Context, spec EntrySpec) (DirectoryEntry, error)
	UpdateEntry(ctx context.Context, patch EntryPatch) (DirectoryEntry, error)
	DeleteEntry(ctx context.Context, del EntryDelete) error
	MoveEntry(ctx context.Context, move EntryMove) (DirectoryEntry, error)
	ListTree(ctx context.Context, q TreeQuery) (TreePage, error)
	GetEntryMeta(ctx context.Context, dn string) (DirectoryEntry, error)
	ManagedSuffixes() SuffixList
}
