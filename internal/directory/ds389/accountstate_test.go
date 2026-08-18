package ds389

import (
	"testing"

	"github.com/go-ldap/ldap/v3"

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
