package config

import (
	"sort"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/config/v1alpha1"
)

const CompilerContract = "labldap.config.v1alpha1.3"

type NormalizedUser struct {
	ID            string
	UID           string
	DN            string
	Enabled       bool
	Password      *ResolvedSecret
	ObjectClasses []string
	Attributes    []AttrKV
}

type AttrKV struct {
	Name  string
	Value string
}

type MemberRef struct {
	Kind string // user | group
	ID   string
	DN   string
}

type NormalizedGroup struct {
	ID      string
	DN      string
	Members []MemberRef
}

type NormalizedPolicy struct {
	MinLength       int
	HistoryCount    int
	MaxAge          time.Duration
	WarningAge      time.Duration
	LockoutEnabled  bool
	MaxFailures     int
	LockoutDuration time.Duration
	StorageScheme   string
}

type NormalizedToken struct {
	ID     string
	Scopes []string
	Secret ResolvedSecret
}

type NamedACI struct {
	ID     string
	Target string
	Text   string
}

type NormalizedRuntime struct {
	ID       string
	DN       string
	Password ResolvedSecret
}

type Normalized struct {
	frozen       bool
	Engine       string
	Suffix       DN
	PeopleDN     DN
	GroupsDN     DN
	NestedGroups bool
	AllowRawACI  bool
	SoftReset    bool
	StorageMode  string
	StartupMode  string
	Name         string
	Runtime      NormalizedRuntime
	Users        []NormalizedUser
	Groups       []NormalizedGroup
	Policy       NormalizedPolicy
	Tokens       []NormalizedToken
	OperatorACLs []v1alpha1.ACL
	Warnings     []string
}

func (n *Normalized) freeze() {
	n.frozen = true
}

func sortUsers(users []NormalizedUser) {
	sort.Slice(users, func(i, j int) bool { return users[i].ID < users[j].ID })
	for i := range users {
		sort.Slice(users[i].Attributes, func(a, b int) bool {
			return users[i].Attributes[a].Name < users[i].Attributes[b].Name
		})
	}
}

func sortGroups(groups []NormalizedGroup) {
	sort.Slice(groups, func(i, j int) bool { return groups[i].ID < groups[j].ID })
	for i := range groups {
		sort.Slice(groups[i].Members, func(a, b int) bool {
			if groups[i].Members[a].Kind != groups[i].Members[b].Kind {
				return groups[i].Members[a].Kind < groups[i].Members[b].Kind
			}
			return groups[i].Members[a].ID < groups[i].Members[b].ID
		})
	}
}
