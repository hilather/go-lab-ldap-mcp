package ds389

import (
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

func TestDeleteManagedRefusesPrimaryOutsidePeopleGroups(t *testing.T) {
	t.Parallel()
	rt := testRuntime(t)
	if err := rt.DeleteManaged(t.Context(), "cn=outside,dc=example,dc=test"); err == nil || fieldOf(err) != directory.FieldForbidden {
		t.Fatalf("outside primary: %v", err)
	}
	if err := rt.DeleteManaged(t.Context(), "cn=config"); err == nil || fieldOf(err) != directory.FieldForbidden {
		t.Fatalf("unmanaged: %v", err)
	}
	if err := rt.DeleteManaged(t.Context(), "uid=rt,ou=people,dc=example,dc=test"); err == nil || fieldOf(err) != directory.FieldForbidden {
		t.Fatalf("runtime: %v", err)
	}
	if err := rt.DeleteManaged(t.Context(), "dc=example,dc=test"); err == nil || fieldOf(err) != directory.FieldForbidden {
		t.Fatalf("primary suffix root: %v", err)
	}
}

func TestDeleteManagedAllowsPeopleAndAdditionalExtras(t *testing.T) {
	t.Parallel()
	rt := testRuntime(t)
	rt.cfg.AdditionalSuffixes = []string{"dc=region1,dc=example,dc=net"}
	if err := rt.DeleteManaged(t.Context(), "uid=alice,ou=people,dc=example,dc=test"); err == nil || fieldOf(err) == directory.FieldForbidden {
		t.Fatalf("people extra should pass the gate: %v", err)
	}
	if err := rt.DeleteManaged(t.Context(), "ou=Network,dc=region1,dc=example,dc=net"); err == nil || fieldOf(err) == directory.FieldForbidden {
		t.Fatalf("additional extra should pass the gate: %v", err)
	}
	if err := rt.DeleteManaged(t.Context(), "dc=region1,dc=example,dc=net"); err == nil || fieldOf(err) != directory.FieldForbidden {
		t.Fatalf("additional suffix root: %v", err)
	}
	if err := rt.DeleteManaged(t.Context(), "cn=outside,dc=example,dc=test"); err == nil || fieldOf(err) != directory.FieldForbidden {
		t.Fatalf("outside under primary: %v", err)
	}
}
