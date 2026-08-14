package ds389

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

type aciMem struct {
	acis   map[string][]string
	writes int
	addErr error
}

func (m *aciMem) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	vals := m.acis[strings.ToLower(req.BaseDN)]
	e := &ldap.Entry{DN: req.BaseDN}
	if len(vals) > 0 {
		e.Attributes = []*ldap.EntryAttribute{{Name: "aci", Values: append([]string(nil), vals...)}}
	}
	return &ldap.SearchResult{Entries: []*ldap.Entry{e}}, nil
}

func (m *aciMem) Add(*ldap.AddRequest) error { return nil }

func (m *aciMem) Modify(req *ldap.ModifyRequest) error {
	m.writes++
	if m.acis == nil {
		m.acis = map[string][]string{}
	}
	key := strings.ToLower(req.DN)
	cur := append([]string(nil), m.acis[key]...)
	for _, ch := range req.Changes {
		switch ch.Operation {
		case ldap.AddAttribute:
			if m.addErr != nil {
				return m.addErr
			}
			cur = append(cur, ch.Modification.Vals...)
		case ldap.DeleteAttribute:
			drop := map[string]struct{}{}
			for _, v := range ch.Modification.Vals {
				drop[v] = struct{}{}
			}
			var next []string
			for _, v := range cur {
				if _, ok := drop[v]; !ok {
					next = append(next, v)
				}
			}
			cur = next
		}
	}
	m.acis[key] = cur
	return nil
}

func (m *aciMem) Del(*ldap.DelRequest) error { return nil }
func (m *aciMem) Bind(string, string) error  { return nil }
func (m *aciMem) Close() error               { return nil }

func sampleRuntimeACIs() []config.NamedACI {
	return []config.NamedACI{
		{ID: "labldap:runtime-suffix-read", Target: "dc=example,dc=test",
			Text: `(target="ldap:///dc=example,dc=test")(targetattr!="userPassword")(version 3.0; acl "labldap:runtime-suffix-read"; allow (read,search,compare) userdn="ldap:///uid=rt,ou=people,dc=example,dc=test";)`},
		{ID: "labldap:runtime-people-write", Target: "ou=people,dc=example,dc=test",
			Text: `(target="ldap:///ou=people,dc=example,dc=test")(targetattr!="aci")(version 3.0; acl "labldap:runtime-people-write"; allow (add,delete,write,read,search,compare) userdn="ldap:///uid=rt,ou=people,dc=example,dc=test";)`},
	}
}

func TestReconcileACIsApplyAndMatch(t *testing.T) {
	mem := &aciMem{acis: map[string][]string{
		"dc=example,dc=test": {`(targetattr="dc")(version 3.0; acl "Enable anyone domain read"; allow (read) userdn="ldap:///anyone";)`},
	}}
	eng := Engine{TreeDial: func(context.Context, bootstrap.TreeRequest) (treeConn, error) { return mem, nil }}
	res, err := eng.ReconcileACIs(t.Context(), bootstrap.ACIRequest{
		TreeRequest: bootstrap.TreeRequest{Write: true},
		ACIs:        sampleRuntimeACIs(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Applied) != 2 {
		t.Fatalf("applied = %v", res.Applied)
	}
	if !strings.Contains(strings.Join(mem.acis["dc=example,dc=test"], "\n"), "labldap:runtime-suffix-read") {
		t.Fatalf("missing named aci: %v", mem.acis)
	}
	if !strings.Contains(strings.Join(mem.acis["dc=example,dc=test"], "\n"), "Enable anyone domain read") {
		t.Fatal("deleted unmanaged ACI")
	}
	writes := mem.writes
	res2, err := eng.ReconcileACIs(t.Context(), bootstrap.ACIRequest{
		TreeRequest: bootstrap.TreeRequest{Write: true},
		ACIs:        sampleRuntimeACIs(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Matched) < 2 {
		t.Fatalf("expected match on re-apply: %+v", res2)
	}
	if mem.writes != writes {
		t.Fatalf("re-apply wrote again: before=%d after=%d", writes, mem.writes)
	}
}

func TestReconcileACIsRemovesExtraOwned(t *testing.T) {
	extra := `(version 3.0; acl "labldap:old"; allow (read) userdn="ldap:///anyone";)`
	mem := &aciMem{acis: map[string][]string{"dc=example,dc=test": {extra}}}
	eng := Engine{TreeDial: func(context.Context, bootstrap.TreeRequest) (treeConn, error) { return mem, nil }}
	_, err := eng.ReconcileACIs(t.Context(), bootstrap.ACIRequest{
		TreeRequest: bootstrap.TreeRequest{Write: true},
		ACIs:        sampleRuntimeACIs()[:1],
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range mem.acis["dc=example,dc=test"] {
		if strings.Contains(v, "labldap:old") {
			t.Fatalf("left extra owned ACI: %v", mem.acis)
		}
	}
}

func TestReconcileACIsServerReject(t *testing.T) {
	mem := &aciMem{addErr: ldap.NewError(ldap.LDAPResultInvalidAttributeSyntax, errors.New("ACL Syntax Error"))}
	eng := Engine{TreeDial: func(context.Context, bootstrap.TreeRequest) (treeConn, error) { return mem, nil }}
	_, err := eng.ReconcileACIs(t.Context(), bootstrap.ACIRequest{
		TreeRequest: bootstrap.TreeRequest{Write: true},
		ACIs:        sampleRuntimeACIs()[:1],
	})
	if err == nil || !fieldHas(err, "phase.aci", "server_reject") {
		t.Fatalf("%v", err)
	}
	apperr.Assert(t, err).Code(apperr.CodeBootstrap).FieldPath("phase.aci")
	if !strings.Contains(err.Error(), "labldap:runtime-suffix-read") && !strings.Contains(err.Error(), "rejected") {
		t.Fatalf("missing ACL id: %v", err)
	}
}

func TestReconcileACIsValidateNoWrite(t *testing.T) {
	text := sampleRuntimeACIs()[0].Text
	mem := &aciMem{acis: map[string][]string{
		"dc=example,dc=test":           {text},
		"ou=people,dc=example,dc=test": {sampleRuntimeACIs()[1].Text},
	}}
	eng := Engine{TreeDial: func(context.Context, bootstrap.TreeRequest) (treeConn, error) { return mem, nil }}
	if _, err := eng.ReconcileACIs(t.Context(), bootstrap.ACIRequest{
		TreeRequest: bootstrap.TreeRequest{Write: false},
		ACIs:        sampleRuntimeACIs(),
	}); err != nil {
		t.Fatal(err)
	}
	if mem.writes != 0 {
		t.Fatalf("validate wrote: %d", mem.writes)
	}
}

func TestReconcileACIsRejectsMismatchedName(t *testing.T) {
	mem := &aciMem{}
	eng := Engine{TreeDial: func(context.Context, bootstrap.TreeRequest) (treeConn, error) { return mem, nil }}
	_, err := eng.ReconcileACIs(t.Context(), bootstrap.ACIRequest{
		TreeRequest: bootstrap.TreeRequest{Write: true},
		ACIs: []config.NamedACI{{
			ID:     "labldap:raw-bad",
			Target: "dc=example,dc=test",
			Text:   `(version 3.0; acl "other"; allow (read) userdn="ldap:///anyone";)`,
		}},
	})
	if err == nil || !fieldHas(err, "phase.aci", "server_reject") {
		t.Fatalf("%v", err)
	}
	if mem.writes != 0 {
		t.Fatalf("wrote mismatched raw ACI: %d", mem.writes)
	}
}

func TestACINameAndCanon(t *testing.T) {
	id, ok := aciName(`(version 3.0; acl "labldap:runtime-suffix-read"; allow (read) userdn="ldap:///anyone";)`)
	if !ok || id != "labldap:runtime-suffix-read" {
		t.Fatalf("id=%q ok=%v", id, ok)
	}
	if canonACI("a   b\nc") != "a b c" {
		t.Fatalf("canon = %q", canonACI("a   b\nc"))
	}
}
