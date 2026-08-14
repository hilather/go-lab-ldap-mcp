package directory_test

import (
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

func TestRevisionOfUserStableAndSensitive(t *testing.T) {
	t.Parallel()
	base := directory.User{
		ID: "alice", UID: "alice", Enabled: true,
		ObjectClasses: []string{"inetOrgPerson", "person"},
		Attributes:    []directory.AttrKV{{Name: "cn", Value: "Alice"}, {Name: "sn", Value: "Example"}},
		Groups:        []directory.GroupID{"staff"},
	}
	a := directory.RevisionOfUser(base)
	b := directory.RevisionOfUser(base)
	if a == "" || a != b {
		t.Fatalf("unchanged reads must match: %q %q", a, b)
	}
	changed := base
	changed.Attributes = []directory.AttrKV{{Name: "cn", Value: "Alicia"}, {Name: "sn", Value: "Example"}}
	if directory.RevisionOfUser(changed) == a {
		t.Fatal("attribute change must alter revision")
	}
	enabled := base
	enabled.Enabled = false
	if directory.RevisionOfUser(enabled) == a {
		t.Fatal("enablement change must alter revision")
	}
	sameSecret := base
	// Password is not an API-exposed field; hashing User must ignore it.
	if directory.RevisionOfUser(sameSecret) != a {
		t.Fatal("identical exposed fields must not change")
	}
}

func TestRevisionOfGroupMembership(t *testing.T) {
	t.Parallel()
	g := directory.Group{
		ID: "staff",
		Members: []directory.MemberRef{
			{Kind: "user", ID: "alice", DN: "uid=alice,ou=people,dc=example,dc=test"},
		},
	}
	a := directory.RevisionOfGroup(g)
	sameCase := directory.Group{
		ID: "staff",
		Members: []directory.MemberRef{
			{Kind: "user", ID: "alice", DN: "UID=alice,OU=people,DC=example,DC=test"},
		},
	}
	if directory.RevisionOfGroup(sameCase) != a {
		t.Fatal("DN case must not change group revision")
	}
	added := g
	added.Members = append(append([]directory.MemberRef(nil), g.Members...), directory.MemberRef{
		Kind: "user", ID: "bob", DN: "uid=bob,ou=people,dc=example,dc=test",
	})
	if directory.RevisionOfGroup(added) == a {
		t.Fatal("membership change must alter revision")
	}
}

func TestRevisionNeverHashesPasswordLiteral(t *testing.T) {
	t.Parallel()
	u := directory.User{ID: "alice", UID: "alice", Enabled: true}
	rev := string(directory.RevisionOfUser(u))
	if rev == "" {
		t.Fatal("empty revision")
	}
	// The hash is hex of JSON of exposed fields; a password string is not an input.
	if directory.RevisionHash("super-secret") == directory.Revision(rev) {
		t.Fatal("user revision collided with password hash")
	}
}
