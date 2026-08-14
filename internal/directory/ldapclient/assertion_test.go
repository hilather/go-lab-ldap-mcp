package ldapclient

import (
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

func TestNewControlAssertion(t *testing.T) {
	t.Parallel()
	ctl, err := NewControlAssertion("(entryCSN=20240101000000.000000Z#000000#000#000000)")
	if err != nil {
		t.Fatal(err)
	}
	if ctl.GetControlType() != ControlTypeAssertion || ctl.GetControlType() != "1.3.6.1.1.12" {
		t.Fatalf("oid %s", ctl.GetControlType())
	}
	if !ctl.Criticality {
		t.Fatal("assertion must be critical")
	}
	pkt := ctl.Encode()
	if pkt == nil || len(pkt.Children) < 3 {
		t.Fatalf("encode: %+v", pkt)
	}
	if ctl.String() == "" {
		t.Fatal("string")
	}
}

func TestNewControlAssertionRejectsEmpty(t *testing.T) {
	t.Parallel()
	if _, err := NewControlAssertion(""); err == nil {
		t.Fatal("empty filter")
	}
	if _, err := NewControlAssertion("entryCSN=x"); err == nil {
		t.Fatal("unparen filter")
	}
}

func TestAssertionFailedMapsToConflict(t *testing.T) {
	t.Parallel()
	err := MapError(&ldap.Error{ResultCode: ldap.LDAPResultAssertionFailed, Err: errSentinel{}})
	if !hasField(err, directory.FieldConflict) {
		t.Fatalf("want conflict, got %v", err)
	}
}

type errSentinel struct{}

func (errSentinel) Error() string { return "assertion failed" }
