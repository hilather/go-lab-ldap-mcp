package ds389

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
)

type scriptedExec struct {
	calls [][]string
	list  string
	err   error
}

func (s *scriptedExec) exec(_ context.Context, _ string, args []string) ([]byte, []byte, error) {
	cp := append([]string(nil), args...)
	s.calls = append(s.calls, cp)
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "backend suffix list") {
		return []byte(s.list), nil, s.err
	}
	if strings.Contains(joined, "backend create") {
		if s.err != nil {
			return []byte(`{"desc":"Mapping tree for this suffix exists!"}`), nil, s.err
		}
		return []byte("The database was sucessfully created\n"), nil, nil
	}
	return nil, []byte("unexpected"), errUnexpected
}

var errUnexpected = errString("unexpected dsconf")

type errString string

func (e errString) Error() string { return string(e) }

func TestParseSuffixList(t *testing.T) {
	got, err := parseSuffixList([]byte(`{"type":"list","items":["dc=example,dc=test (userroot)"]}`))
	if err != nil || len(got) != 1 || got[0].Name != "userroot" || got[0].Suffix != "dc=example,dc=test" {
		t.Fatalf("%+v %v", got, err)
	}
	empty, err := parseSuffixList([]byte(`{"type":"list","items":[]}`))
	if err != nil || len(empty) != 0 {
		t.Fatalf("%+v %v", empty, err)
	}
}

func TestReconcileCreateOnEmpty(t *testing.T) {
	sc := &scriptedExec{list: `{"type":"list","items":[]}`}
	eng := Engine{Runner: Runner{Exec: sc.exec}}
	res, err := eng.Reconcile(t.Context(), bootstrap.BackendRequest{
		PasswordFile: "/secret/dm.pw",
		Instance:     "localhost",
		Name:         "userroot",
		Suffix:       "dc=example,dc=test",
		Write:        true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != "created" {
		t.Fatalf("%+v", res)
	}
	if len(sc.calls) != 2 {
		t.Fatalf("calls = %d", len(sc.calls))
	}
	create := strings.Join(sc.calls[1], " ")
	if !strings.Contains(create, "--suffix") || !strings.Contains(create, "dc=example,dc=test") {
		t.Fatalf("create argv = %s", create)
	}
	if strings.Contains(create, "sh") && strings.Contains(create, "-c") {
		t.Fatal("sh -c")
	}
}

func TestReconcileMatchNoCreate(t *testing.T) {
	sc := &scriptedExec{list: `{"type":"list","items":["dc=example,dc=test (userroot)"]}`}
	eng := Engine{Runner: Runner{Exec: sc.exec}}
	res, err := eng.Reconcile(t.Context(), bootstrap.BackendRequest{
		PasswordFile: "/secret/dm.pw",
		Instance:     "localhost",
		Name:         "userroot",
		Suffix:       "dc=example,dc=test",
		Write:        true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Action != "matched" {
		t.Fatalf("%+v", res)
	}
	if len(sc.calls) != 1 {
		t.Fatalf("create was invoked: %+v", sc.calls)
	}
}

func TestReconcileNameConflict(t *testing.T) {
	sc := &scriptedExec{list: `{"type":"list","items":["dc=other,dc=test (userroot)"]}`}
	eng := Engine{Runner: Runner{Exec: sc.exec}}
	_, err := eng.Reconcile(t.Context(), bootstrap.BackendRequest{
		PasswordFile: "/secret/dm.pw",
		Instance:     "localhost",
		Name:         "userroot",
		Suffix:       "dc=example,dc=test",
		Write:        true,
	})
	if err == nil {
		t.Fatal("expected conflict")
	}
	apperr.Assert(t, err).Code(apperr.CodeBootstrap).FieldPath("phase.backend")
	var e *apperr.Error
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("%v", err)
	}
	if errors.As(err, &e) {
		found := false
		for _, f := range e.Fields() {
			if f.Path == "phase.backend" && f.Code == "conflict" {
				found = true
			}
		}
		if !found {
			t.Fatalf("fields = %#v", e.Fields())
		}
	}
	if len(sc.calls) != 1 {
		t.Fatal("must not create on conflict")
	}
}

func TestReconcileValidateDoesNotCreate(t *testing.T) {
	sc := &scriptedExec{list: `{"type":"list","items":[]}`}
	eng := Engine{Runner: Runner{Exec: sc.exec}}
	_, err := eng.Reconcile(t.Context(), bootstrap.BackendRequest{
		PasswordFile: "/secret/dm.pw",
		Instance:     "localhost",
		Name:         "userroot",
		Suffix:       "dc=example,dc=test",
		Write:        false,
	})
	if err == nil {
		t.Fatal("expected missing")
	}
	apperr.Assert(t, err).Code(apperr.CodeBootstrap).FieldPath("phase.backend")
	if len(sc.calls) != 1 {
		t.Fatal("validate must not create")
	}
}
