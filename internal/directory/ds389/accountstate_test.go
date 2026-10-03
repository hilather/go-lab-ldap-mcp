package ds389

import (
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ldapclient"
)

func TestRetryAccountModifyKeepsControls(t *testing.T) {
	t.Parallel()
	ctl, err := ldapclient.NewControlAssertion("(entryUUID=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee)")
	if err != nil {
		t.Fatal(err)
	}
	ch := ldap.Change{Operation: ldap.ReplaceAttribute, Modification: ldap.PartialAttribute{
		Type: "pwdReset", Vals: []string{"TRUE"},
	}}
	one := retryAccountModify("uid=alice,ou=people,dc=example,dc=test", ch, []ldap.Control{ctl})
	if len(one.Controls) != 1 {
		t.Fatalf("controls = %d, want 1", len(one.Controls))
	}
	if one.Controls[0].GetControlType() != ldapclient.ControlTypeAssertion {
		t.Fatalf("control type %q", one.Controls[0].GetControlType())
	}
	if len(one.Changes) != 1 || one.Changes[0].Modification.Type != "pwdReset" {
		t.Fatalf("changes = %+v", one.Changes)
	}
	dropped := retryAccountModify(one.DN, ch, nil)
	if len(dropped.Controls) != 0 {
		t.Fatalf("nil controls leaked: %d", len(dropped.Controls))
	}
}

func TestUserRevisionIncludesPublicAccountState(t *testing.T) {
	entry := ldap.NewEntry("uid=alice,dc=test", map[string][]string{"uid": {"alice"}, "objectClass": {"inetOrgPerson"}, "cn": {"alice"}, "sn": {"Seed"}})
	initial := userFromEntry(entry, "ou=groups,dc=test")
	entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{Name: "accountUnlockTime", Values: []string{"20380119031407Z"}})
	locked := userFromEntry(entry, "ou=groups,dc=test")
	state := accountStateFromEntry("alice", entry, "ou=groups,dc=test")
	if locked.Revision == initial.Revision || state.Revision != locked.Revision {
		t.Fatal("shared revision missed lock transition")
	}
	entry.Attributes = append(entry.Attributes, &ldap.EntryAttribute{Name: "pwdReset", Values: []string{"TRUE"}})
	expired := userFromEntry(entry, "ou=groups,dc=test")
	if expired.Revision == locked.Revision {
		t.Fatal("shared revision missed expiry transition")
	}
	for _, attr := range expired.Attributes {
		if directory.SecretAttr(attr.Name) {
			t.Fatalf("exposed account stamp %s", attr.Name)
		}
	}
}
