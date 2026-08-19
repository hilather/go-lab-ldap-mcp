package directory_test

import (
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

func TestNormalizeObjectClass(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"container", directory.ClassOrganizationalUnit, true},
		{"CONTAINER", directory.ClassOrganizationalUnit, true},
		{"dcObject", directory.ClassDomain, true},
		{"domain", directory.ClassDomain, true},
		{"organizationalUnit", directory.ClassOrganizationalUnit, true},
		{"inetOrgPerson", directory.ClassInetOrgPerson, true},
		{"groupOfNames", directory.ClassGroupOfNames, true},
		{"extensibleObject", "", false},
	}
	for _, tc := range cases {
		got, ok := directory.NormalizeObjectClass(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Fatalf("%q: got %q %v want %q %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
