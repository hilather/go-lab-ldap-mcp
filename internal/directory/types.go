package directory

import "github.com/hilather/go-lab-ldap-mcp/internal/observability"

// IDs are compiled object ids, not DNs, at the application boundary.
type UserID string
type GroupID string

// Revision is a lowercase hex sha256 of API-exposed attributes. Never a password.
type Revision string

// AttrKV is one exposed directory attribute. Same shape as config.AttrKV.
type AttrKV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type User struct {
	ID            string    `json:"id"`
	UID           string    `json:"uid"`
	DN            string    `json:"dn"`
	Enabled       bool      `json:"enabled"`
	ObjectClasses []string  `json:"objectClasses"`
	Attributes    []AttrKV  `json:"attributes"`
	Groups        []GroupID `json:"groups,omitempty"`
	Revision      Revision  `json:"revision"`
}

// UserSpec is a create request. Password is required and never appears on User.
// DN and ParentDN are optional placement (ADR-0011). Empty keeps
// uid=<uid>,<peopleDN>.
type UserSpec struct {
	ID         string               `json:"id"`
	UID        string               `json:"uid,omitempty"`
	DN         string               `json:"dn,omitempty"`
	ParentDN   string               `json:"parentDN,omitempty"`
	Enabled    *bool                `json:"enabled,omitempty"`
	Password   observability.Secret `json:"password"`
	Attributes map[string]string    `json:"attributes,omitempty"`
}

// UserPatch replaces named attributes only. Omitted keys are left unchanged.
type UserPatch struct {
	Enabled    *bool             `json:"enabled,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type UserListQuery struct {
	PageSize int    `json:"pageSize,omitempty"`
	Cursor   string `json:"cursor,omitempty"`
	Q        string `json:"q,omitempty"`
}

type UserPage struct {
	Items      []User `json:"items"`
	NextCursor string `json:"nextCursor,omitempty"`
}

type MemberRef struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	DN   string `json:"dn,omitempty"`
}

type Group struct {
	ID       string      `json:"id"`
	DN       string      `json:"dn"`
	Members  []MemberRef `json:"members"`
	Revision Revision    `json:"revision"`
}

// GroupSpec requires at least one member. Empty members is empty_group.
// DN and ParentDN are optional placement (ADR-0011). Empty keeps
// cn=<id>,<groupsDN>.
type GroupSpec struct {
	ID       string      `json:"id"`
	DN       string      `json:"dn,omitempty"`
	ParentDN string      `json:"parentDN,omitempty"`
	Members  []MemberRef `json:"members"`
}

type GroupListQuery struct {
	PageSize int    `json:"pageSize,omitempty"`
	Cursor   string `json:"cursor,omitempty"`
	Q        string `json:"q,omitempty"`
}

type GroupPage struct {
	Items      []Group `json:"items"`
	NextCursor string  `json:"nextCursor,omitempty"`
}

type MembershipSummary struct {
	Added     []MemberRef `json:"added"`
	Removed   []MemberRef `json:"removed"`
	Unchanged []MemberRef `json:"unchanged"`
	Rejected  []MemberRef `json:"rejected"`
	Revision  Revision    `json:"revision"`
}

type SearchPage struct {
	Entries    []SearchEntry `json:"entries"`
	NextCursor string        `json:"nextCursor,omitempty"`
}

type SearchEntry struct {
	DN         string   `json:"dn"`
	Attributes []AttrKV `json:"attributes"`
}

// Transport is the LDAP protection mode. Values match compiled transport names.
type Transport string

const (
	TransportLDAP     Transport = "ldap"
	TransportLDAPS    Transport = "ldaps"
	TransportStartTLS Transport = "starttls"
)

const (
	BindOutcomeSuccess            = "success"
	BindOutcomeInvalidCredentials = "invalid_credentials"
	BindOutcomeLocked             = "locked"
	BindOutcomeDisabled           = "disabled"
	BindOutcomeMustChange         = "must_change"
	BindOutcomeUnavailable        = "unavailable"
)

type BindTestResult struct {
	// Outcome is success | invalid_credentials | locked | disabled |
	// must_change | unavailable. Unknown user and wrong password both
	// map to invalid_credentials.
	Outcome string `json:"outcome"`
}

// AccountState is the QA-visible enable/lock/must-change snapshot.
// It is not part of User.Revision.
type AccountState struct {
	ID         string   `json:"id"`
	Enabled    bool     `json:"enabled"`
	Locked     bool     `json:"locked"`
	MustChange bool     `json:"mustChange"`
	Revision   Revision `json:"revision"`
}

type RootDSE struct {
	NamingContexts    []string `json:"namingContexts"`
	VendorName        string   `json:"vendorName"`
	VendorVersion     string   `json:"vendorVersion"`
	SupportedControls []string `json:"supportedControls"`
	SupportedSASL     []string `json:"supportedSASL"`
}

type ObjectClass struct {
	Name string   `json:"name"`
	OID  string   `json:"oid"`
	Kind string   `json:"kind"`
	Must []string `json:"must"`
	May  []string `json:"may"`
	Sup  []string `json:"sup"`
}

type AttributeType struct {
	Name        string `json:"name"`
	OID         string `json:"oid"`
	Syntax      string `json:"syntax"`
	SingleValue bool   `json:"singleValue"`
}

type Schema struct {
	ObjectClasses []ObjectClass   `json:"objectClasses"`
	Attributes    []AttributeType `json:"attributes"`
}

type ManagedInventory struct {
	Users    []string `json:"users"`
	Groups   []string `json:"groups"`
	Extra    []string `json:"extra"`
	Preserve []string `json:"preserve"`
}

type ExportOptions struct {
	OmitSecrets bool  `json:"omitSecrets"`
	MaxEntries  int   `json:"maxEntries"`
	MaxBytes    int64 `json:"maxBytes"`
}

type BaselineMarker struct {
	DN               string `json:"dn"`
	AppliedRevision  string `json:"appliedRevision"`
	ExpectedRevision string `json:"expectedRevision"`
	ApplyVersion     string `json:"applyVersion"`
	AppliedAt        string `json:"appliedAt"`
}

// ScopeSet is the token/session grant list. Has reports exact membership only.
type ScopeSet []string

func (s ScopeSet) Has(scope string) bool {
	for _, x := range s {
		if x == scope {
			return true
		}
	}
	return false
}
