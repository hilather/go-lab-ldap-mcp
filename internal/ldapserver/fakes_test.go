package ldapserver

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

func mustParseDN(t *testing.T, s string) config.DN {
	t.Helper()
	d, err := config.ParseDN(s)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", s, err)
	}
	return d
}

func TestFakeStoreAddAndRead(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewFakeStore()
	err := s.Update(ctx, func(tx UpdateTx) error {
		if err := tx.Add(ctx, NewEntry("dc=example,dc=test", StringAttribute("objectClass", "top", "domain"))); err != nil {
			return err
		}
		if err := tx.Add(ctx, NewEntry("ou=people,dc=example,dc=test", StringAttribute("objectClass", "top", "organizationalUnit"))); err != nil {
			return err
		}
		return tx.Add(ctx, NewEntry("uid=alice,ou=people,dc=example,dc=test",
			StringAttribute("objectClass", "top", "person"),
			StringAttribute("uid", "alice"),
			StringAttribute("sn", "Alice")))
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	err = s.View(ctx, func(tx ReadTx) error {
		// Lookup folds case: DN casing is presentation, not identity.
		e, err := tx.Entry(ctx, mustParseDN(t, "UID=Alice,OU=People,dc=example,dc=test"))
		if err != nil {
			return err
		}
		if vals := e.Values("SN"); len(vals) != 1 || string(vals[0]) != "Alice" {
			t.Fatalf("sn values = %q", vals)
		}
		kids, err := tx.Children(ctx, mustParseDN(t, "dc=example,dc=test"))
		if err != nil {
			return err
		}
		if len(kids) != 1 || kids[0].DN != "ou=people,dc=example,dc=test" {
			t.Fatalf("children = %v", kids)
		}
		sub, err := tx.Subtree(ctx, mustParseDN(t, "dc=example,dc=test"))
		if err != nil {
			return err
		}
		if len(sub) != 3 {
			t.Fatalf("subtree size = %d", len(sub))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("View: %v", err)
	}
}

func TestFakeStoreErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewFakeStore()
	seed := func() {
		t.Helper()
		err := s.Update(ctx, func(tx UpdateTx) error {
			if err := tx.Add(ctx, NewEntry("dc=example,dc=test")); err != nil {
				return err
			}
			return tx.Add(ctx, NewEntry("ou=people,dc=example,dc=test"))
		})
		if err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	seed()

	missing := mustParseDN(t, "uid=ghost,dc=example,dc=test")
	err := s.View(ctx, func(tx ReadTx) error {
		_, err := tx.Entry(ctx, missing)
		return err
	})
	if !errors.Is(err, ErrNoSuchObject) {
		t.Fatalf("missing entry: %v", err)
	}

	err = s.Update(ctx, func(tx UpdateTx) error {
		return tx.Add(ctx, NewEntry("dc=example,dc=test"))
	})
	if !errors.Is(err, ErrEntryExists) {
		t.Fatalf("duplicate add: %v", err)
	}

	err = s.Update(ctx, func(tx UpdateTx) error {
		return tx.Replace(ctx, NewEntry("uid=ghost,dc=example,dc=test"))
	})
	if !errors.Is(err, ErrNoSuchObject) {
		t.Fatalf("replace missing: %v", err)
	}

	err = s.Update(ctx, func(tx UpdateTx) error {
		return tx.Delete(ctx, mustParseDN(t, "dc=example,dc=test"))
	})
	if !errors.Is(err, ErrNotLeaf) {
		t.Fatalf("delete non-leaf: %v", err)
	}

	err = s.Update(ctx, func(tx UpdateTx) error {
		return tx.Delete(ctx, missing)
	})
	if !errors.Is(err, ErrNoSuchObject) {
		t.Fatalf("delete missing: %v", err)
	}
}

func TestFakeStoreUpdateRollback(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewFakeStore()
	boom := errors.New("boom")
	err := s.Update(ctx, func(tx UpdateTx) error {
		if err := tx.Add(ctx, NewEntry("dc=example,dc=test")); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Update error = %v", err)
	}
	err = s.View(ctx, func(tx ReadTx) error {
		_, err := tx.Entry(ctx, mustParseDN(t, "dc=example,dc=test"))
		return err
	})
	if !errors.Is(err, ErrNoSuchObject) {
		t.Fatalf("rolled-back entry visible: %v", err)
	}
}

func TestFakeStoreCopyOnWrite(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewFakeStore()
	if err := s.Update(ctx, func(tx UpdateTx) error {
		return tx.Add(ctx, NewEntry("dc=example,dc=test", StringAttribute("description", "original")))
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	if err := s.View(ctx, func(tx ReadTx) error {
		e, err := tx.Entry(ctx, mustParseDN(t, "dc=example,dc=test"))
		if err != nil {
			return err
		}
		e.Attributes[0].Values[0][0] = 'X'
		e.DN = "dc=mutated,dc=test"
		return nil
	}); err != nil {
		t.Fatalf("view: %v", err)
	}
	if err := s.View(ctx, func(tx ReadTx) error {
		e, err := tx.Entry(ctx, mustParseDN(t, "dc=example,dc=test"))
		if err != nil {
			return err
		}
		if got := string(e.Values("description")[0]); got != "original" {
			t.Fatalf("stored value mutated: %q", got)
		}
		return nil
	}); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestFakeStoreRenameMovesDescendants(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewFakeStore()
	if err := s.Update(ctx, func(tx UpdateTx) error {
		for _, dn := range []string{
			"dc=example,dc=test",
			"ou=people,dc=example,dc=test",
			"uid=alice,ou=people,dc=example,dc=test",
		} {
			if err := tx.Add(ctx, NewEntry(dn)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	from := mustParseDN(t, "ou=people,dc=example,dc=test")
	to := mustParseDN(t, "ou=users,dc=example,dc=test")
	if err := s.Update(ctx, func(tx UpdateTx) error {
		return tx.Rename(ctx, from, to)
	}); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	err := s.View(ctx, func(tx ReadTx) error {
		if _, err := tx.Entry(ctx, mustParseDN(t, "ou=users,dc=example,dc=test")); err != nil {
			t.Fatalf("renamed parent: %v", err)
		}
		e, err := tx.Entry(ctx, mustParseDN(t, "uid=alice,ou=users,dc=example,dc=test"))
		if err != nil {
			t.Fatalf("renamed child: %v", err)
		}
		if e.DN != "uid=alice,ou=users,dc=example,dc=test" {
			t.Fatalf("child DN = %q", e.DN)
		}
		if _, err := tx.Entry(ctx, from); !errors.Is(err, ErrNoSuchObject) {
			t.Fatalf("old DN still present: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("View: %v", err)
	}
	// Renaming onto a taken DN fails.
	taken := mustParseDN(t, "ou=users,dc=example,dc=test")
	err = s.Update(ctx, func(tx UpdateTx) error {
		return tx.Rename(ctx, mustParseDN(t, "dc=example,dc=test"), taken)
	})
	if !errors.Is(err, ErrEntryExists) {
		t.Fatalf("rename onto existing: %v", err)
	}
}

func TestFakeStoreInvalidEntryDN(t *testing.T) {
	t.Parallel()
	s := NewFakeStore()
	err := s.Update(context.Background(), func(tx UpdateTx) error {
		return tx.Add(context.Background(), NewEntry("not-a-dn"))
	})
	if err == nil || errors.Is(err, ErrEntryExists) {
		t.Fatalf("add invalid DN: %v", err)
	}
}

func TestFakeCodec(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	c := NewFakeCodec()
	if c.MaxPDUBytes() != DefaultLimits().MaxPDUBytes {
		t.Fatalf("MaxPDUBytes = %d", c.MaxPDUBytes())
	}
	c.SetMaxPDUBytes(1024)
	if c.MaxPDUBytes() != 1024 {
		t.Fatalf("MaxPDUBytes after set = %d", c.MaxPDUBytes())
	}
	if _, err := c.ReadMessage(ctx, nil); !errors.Is(err, io.EOF) {
		t.Fatalf("empty read = %v, want io.EOF", err)
	}
	in := &Message{ID: 7, Op: &UnbindRequest{}}
	c.QueueRead(in)
	m, err := c.ReadMessage(ctx, nil)
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	if m != in {
		t.Fatalf("ReadMessage = %p, want queued %p", m, in)
	}
	out := &Message{ID: 7, Op: &BindResponse{Result: Result{Code: ResultSuccess}}}
	if err := c.WriteMessage(ctx, nil, out); err != nil {
		t.Fatalf("WriteMessage: %v", err)
	}
	w := c.Written()
	if len(w) != 1 || w[0] != out {
		t.Fatalf("Written = %v", w)
	}
	boom := errors.New("codec boom")
	c.FailReads(boom)
	if _, err := c.ReadMessage(ctx, nil); !errors.Is(err, boom) {
		t.Fatalf("failed read = %v", err)
	}
	c.FailWrites(boom)
	if err := c.WriteMessage(ctx, nil, out); !errors.Is(err, boom) {
		t.Fatalf("failed write = %v", err)
	}
}

func TestFakeSchema(t *testing.T) {
	t.Parallel()
	s := NewFakeSchema(
		[]ObjectClassDef{{OID: "2.5.6.6", Name: "person", Kind: ObjectClassStructural, Must: []string{"sn", "cn"}}},
		[]AttributeTypeDef{{OID: "2.5.4.3", Name: "cn", Equality: "caseIgnoreMatch"}},
	)
	if _, ok := s.ObjectClass("PERSON"); !ok {
		t.Fatal("case-insensitive name lookup failed")
	}
	if _, ok := s.ObjectClass("2.5.6.6"); !ok {
		t.Fatal("OID lookup failed")
	}
	if _, ok := s.ObjectClass("country"); ok {
		t.Fatal("unknown class resolved")
	}
	at, ok := s.AttributeType("CN")
	if !ok || at.Equality != "caseIgnoreMatch" {
		t.Fatalf("attribute lookup = %+v, %v", at, ok)
	}
	if len(s.ObjectClasses()) != 1 || len(s.AttributeTypes()) != 1 {
		t.Fatal("listings should deduplicate name/OID index entries")
	}
	if got := (ObjectClassDef{Kind: ObjectClassAuxiliary}).Kind.String(); got != "AUXILIARY" {
		t.Fatalf("kind = %q", got)
	}
}

func TestFakeACI(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewFakeStore()
	f := &FakeACI{}
	check := ACICheck{
		Subject: Subject{DN: mustParseDN(t, "uid=bob,ou=people,dc=example,dc=test")},
		Target:  mustParseDN(t, "dc=example,dc=test"),
		Perm:    PermRead,
	}
	var allowed bool
	err := store.View(ctx, func(tx ReadTx) error {
		var err error
		allowed, err = f.Allowed(ctx, tx, check)
		return err
	})
	if err != nil {
		t.Fatalf("View: %v", err)
	}
	if allowed {
		t.Fatal("FakeACI must deny by default")
	}
	if got := f.Checks(); len(got) != 1 || got[0].Perm != PermRead {
		t.Fatalf("checks = %+v", got)
	}
	f.Decide = func(ctx context.Context, tx ReadTx, c ACICheck) (bool, error) {
		return c.Subject.BypassACI, nil
	}
	dm := check
	dm.Subject = Subject{DN: mustParseDN(t, "cn=Directory Manager"), BypassACI: true}
	if ok, err := f.Allowed(ctx, nil, dm); err != nil || !ok {
		t.Fatalf("decide = %v, %v", ok, err)
	}
}

func TestFakePlugin(t *testing.T) {
	t.Parallel()
	p := &FakePlugin{PluginName: "memberof"}
	if p.Name() != "memberof" {
		t.Fatalf("Name = %q", p.Name())
	}
	if (&FakePlugin{}).Name() != "fake" {
		t.Fatal("default name should be fake")
	}
	ev := WriteEvent{Op: WriteAdd, After: NewEntry("cn=g,ou=groups,dc=example,dc=test")}
	if ev.Subject.BypassACI {
		t.Fatal("zero Subject must not be treated as DM")
	}
	if err := p.AfterWrite(context.Background(), nil, ev); err != nil {
		t.Fatalf("AfterWrite: %v", err)
	}
	if got := p.Events(); len(got) != 1 || got[0].Op != WriteAdd || got[0].Subject.BypassACI {
		t.Fatalf("events = %+v", got)
	}
	boom := errors.New("plugin boom")
	p.Err = boom
	if err := p.AfterWrite(context.Background(), nil, ev); !errors.Is(err, boom) {
		t.Fatalf("AfterWrite error = %v", err)
	}
}
