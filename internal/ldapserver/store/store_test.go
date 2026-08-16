package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/ldapserver"
)

func mustParseDN(t *testing.T, s string) config.DN {
	t.Helper()
	d, err := config.ParseDN(s)
	if err != nil {
		t.Fatalf("ParseDN(%q): %v", s, err)
	}
	return d
}

func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "labldapd.bolt")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func seedTree(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	err := s.Update(ctx, func(tx ldapserver.UpdateTx) error {
		entries := []*ldapserver.Entry{
			ldapserver.NewEntry("dc=example,dc=test",
				ldapserver.StringAttribute("objectClass", "top", "domain")),
			ldapserver.NewEntry("ou=people,dc=example,dc=test",
				ldapserver.StringAttribute("objectClass", "top", "organizationalUnit")),
			ldapserver.NewEntry("uid=alice,ou=people,dc=example,dc=test",
				ldapserver.StringAttribute("objectClass", "top", "person"),
				ldapserver.StringAttribute("uid", "alice"),
				ldapserver.StringAttribute("sn", "Alice")),
			ldapserver.NewEntry("uid=bob,ou=people,dc=example,dc=test",
				ldapserver.StringAttribute("objectClass", "top", "person"),
				ldapserver.StringAttribute("uid", "bob")),
		}
		for _, e := range entries {
			if err := tx.Add(ctx, e); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func dnsOf(entries []*ldapserver.Entry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.DN)
	}
	sort.Strings(out)
	return out
}

func TestOpenEmptyPath(t *testing.T) {
	t.Parallel()
	_, err := Open("")
	if !errors.Is(err, ErrEmptyPath) {
		t.Fatalf("Open(\"\") = %v, want ErrEmptyPath", err)
	}
}

func TestOpenBadDirectory(t *testing.T) {
	t.Parallel()
	missing := filepath.Join(t.TempDir(), "no-such-dir", "labldapd.bolt")
	_, err := Open(missing)
	if err == nil {
		t.Fatal("Open in missing directory must fail")
	}
	if !strings.Contains(err.Error(), "store:") {
		t.Fatalf("error must carry the operation context: %v", err)
	}
}

func TestOpenErrorsAreSecretFree(t *testing.T) {
	t.Parallel()
	// A file that is not a bbolt database fails to open; the error must
	// not leak any of the file's bytes.
	secret := "ultra-secret-file-content-9f27b3"
	path := filepath.Join(t.TempDir(), "labldapd.bolt")
	if err := os.WriteFile(path, []byte(secret+strings.Repeat("x", 8192)), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	_, err := Open(path)
	if err == nil {
		t.Fatal("Open of a non-database file must fail")
	}
	if !errors.Is(err, ErrEngineDataMismatch) {
		t.Fatalf("Open non-bbolt = %v, want ErrEngineDataMismatch", err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "xxxx") {
		t.Fatalf("error leaks file contents: %v", err)
	}
}

func TestCheckDataDir389Tree(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "config"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config", "container.inf"), []byte("[General]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := CheckDataDir(dir)
	if !errors.Is(err, ErrEngineDataMismatch) {
		t.Fatalf("CheckDataDir 389 tree = %v", err)
	}
	if strings.Contains(err.Error(), "[General]") {
		t.Fatalf("error leaked marker file content: %v", err)
	}
	_, err = Open(filepath.Join(dir, StoreFileName))
	if !errors.Is(err, ErrEngineDataMismatch) {
		t.Fatalf("Open beside 389 tree = %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, StoreFileName)); !os.IsNotExist(statErr) {
		t.Fatal("Open must not create labldapd.bolt beside a 389 tree")
	}
}

func TestCheckDataDirSlapdLayout(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "slapd-localhost"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := CheckDataDir(dir); !errors.Is(err, ErrEngineDataMismatch) {
		t.Fatalf("CheckDataDir slapd-* = %v", err)
	}
}

func TestCheckDataDirEmptyAndBoltOK(t *testing.T) {
	t.Parallel()
	if err := CheckDataDir(filepath.Join(t.TempDir(), "missing")); err != nil {
		t.Fatalf("missing dir should be ok: %v", err)
	}
	s, path := openTemp(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := CheckDataDir(filepath.Dir(path)); err != nil {
		t.Fatalf("native bolt dir: %v", err)
	}
}

func TestOpenFileMode(t *testing.T) {
	t.Parallel()
	s, path := openTemp(t)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != fileMode {
		t.Fatalf("mode = %o, want %o", got, fileMode)
	}
	// The mode is enforced on reopen of a pre-existing file too.
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod fixture: %v", err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = s2.Close() }()
	info, err = os.Stat(path)
	if err != nil {
		t.Fatalf("stat after reopen: %v", err)
	}
	if got := info.Mode().Perm(); got != fileMode {
		t.Fatalf("mode after reopen = %o, want %o", got, fileMode)
	}
}

func TestReopenReadsPriorEntries(t *testing.T) {
	t.Parallel()
	s, path := openTemp(t)
	seedTree(t, s)
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = s2.Close() }()
	ctx := context.Background()
	err = s2.View(ctx, func(tx ldapserver.ReadTx) error {
		e, err := tx.Entry(ctx, mustParseDN(t, "UID=Alice,OU=People,dc=example,dc=test"))
		if err != nil {
			return err
		}
		if vals := e.Values("sn"); len(vals) != 1 || string(vals[0]) != "Alice" {
			t.Fatalf("sn = %q", vals)
		}
		kids, err := tx.Children(ctx, mustParseDN(t, "ou=people,dc=example,dc=test"))
		if err != nil {
			return err
		}
		if got := dnsOf(kids); fmt.Sprint(got) != fmt.Sprint([]string{
			"uid=alice,ou=people,dc=example,dc=test",
			"uid=bob,ou=people,dc=example,dc=test",
		}) {
			t.Fatalf("children = %v", got)
		}
		sub, err := tx.Subtree(ctx, mustParseDN(t, "dc=example,dc=test"))
		if err != nil {
			return err
		}
		if len(sub) != 4 {
			t.Fatalf("subtree size = %d", len(sub))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("View after reopen: %v", err)
	}
}

func TestStoreAddAndRead(t *testing.T) {
	t.Parallel()
	s, _ := openTemp(t)
	seedTree(t, s)
	ctx := context.Background()
	err := s.View(ctx, func(tx ldapserver.ReadTx) error {
		e, err := tx.Entry(ctx, mustParseDN(t, "uid=alice,ou=people,dc=example,dc=test"))
		if err != nil {
			return err
		}
		if vals := e.Values("UID"); len(vals) != 1 || string(vals[0]) != "alice" {
			t.Fatalf("uid = %q", vals)
		}
		kids, err := tx.Children(ctx, mustParseDN(t, "dc=example,dc=test"))
		if err != nil {
			return err
		}
		if len(kids) != 1 || kids[0].DN != "ou=people,dc=example,dc=test" {
			t.Fatalf("children = %v", dnsOf(kids))
		}
		// A leaf has no children and no error.
		kids, err = tx.Children(ctx, mustParseDN(t, "uid=alice,ou=people,dc=example,dc=test"))
		if err != nil {
			return err
		}
		if len(kids) != 0 {
			t.Fatalf("leaf children = %v", dnsOf(kids))
		}
		sub, err := tx.Subtree(ctx, mustParseDN(t, "ou=people,dc=example,dc=test"))
		if err != nil {
			return err
		}
		if len(sub) != 3 {
			t.Fatalf("subtree = %v", dnsOf(sub))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("View: %v", err)
	}
}

func TestStoreErrors(t *testing.T) {
	t.Parallel()
	s, _ := openTemp(t)
	seedTree(t, s)
	ctx := context.Background()
	missing := mustParseDN(t, "uid=ghost,dc=example,dc=test")

	err := s.View(ctx, func(tx ldapserver.ReadTx) error {
		_, err := tx.Entry(ctx, missing)
		return err
	})
	if !errors.Is(err, ldapserver.ErrNoSuchObject) {
		t.Fatalf("missing entry: %v", err)
	}
	err = s.View(ctx, func(tx ldapserver.ReadTx) error {
		_, err := tx.Children(ctx, missing)
		return err
	})
	if !errors.Is(err, ldapserver.ErrNoSuchObject) {
		t.Fatalf("children of missing: %v", err)
	}
	err = s.View(ctx, func(tx ldapserver.ReadTx) error {
		_, err := tx.Subtree(ctx, missing)
		return err
	})
	if !errors.Is(err, ldapserver.ErrNoSuchObject) {
		t.Fatalf("subtree of missing: %v", err)
	}
	err = s.Update(ctx, func(tx ldapserver.UpdateTx) error {
		return tx.Add(ctx, ldapserver.NewEntry("DC=Example,DC=Test"))
	})
	if !errors.Is(err, ldapserver.ErrEntryExists) {
		t.Fatalf("duplicate add folds case: %v", err)
	}
	err = s.Update(ctx, func(tx ldapserver.UpdateTx) error {
		return tx.Replace(ctx, ldapserver.NewEntry(missing.String()))
	})
	if !errors.Is(err, ldapserver.ErrNoSuchObject) {
		t.Fatalf("replace missing: %v", err)
	}
	err = s.Update(ctx, func(tx ldapserver.UpdateTx) error {
		return tx.Delete(ctx, mustParseDN(t, "ou=people,dc=example,dc=test"))
	})
	if !errors.Is(err, ldapserver.ErrNotLeaf) {
		t.Fatalf("delete non-leaf: %v", err)
	}
	err = s.Update(ctx, func(tx ldapserver.UpdateTx) error {
		return tx.Delete(ctx, missing)
	})
	if !errors.Is(err, ldapserver.ErrNoSuchObject) {
		t.Fatalf("delete missing: %v", err)
	}
	err = s.Update(ctx, func(tx ldapserver.UpdateTx) error {
		return tx.Rename(ctx, missing, mustParseDN(t, "uid=other,dc=example,dc=test"))
	})
	if !errors.Is(err, ldapserver.ErrNoSuchObject) {
		t.Fatalf("rename missing: %v", err)
	}
	err = s.Update(ctx, func(tx ldapserver.UpdateTx) error {
		return tx.Rename(ctx,
			mustParseDN(t, "uid=alice,ou=people,dc=example,dc=test"),
			mustParseDN(t, "UID=Bob,OU=People,dc=example,dc=test"))
	})
	if !errors.Is(err, ldapserver.ErrEntryExists) {
		t.Fatalf("rename onto folded-existing: %v", err)
	}
	err = s.Update(ctx, func(tx ldapserver.UpdateTx) error {
		return tx.Rename(ctx,
			mustParseDN(t, "ou=people,dc=example,dc=test"),
			mustParseDN(t, "ou=people,uid=alice,ou=People,dc=example,dc=test"))
	})
	if !errors.Is(err, ldapserver.ErrRenameIntoSelf) {
		t.Fatalf("rename into mixed-case child: %v, want ErrRenameIntoSelf", err)
	}
	err = s.View(ctx, func(tx ldapserver.ReadTx) error {
		if _, err := tx.Entry(ctx, mustParseDN(t, "uid=alice,ou=people,dc=example,dc=test")); err != nil {
			t.Fatalf("child missing after rejected rename: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("View after rejected rename: %v", err)
	}
}

func TestStoreUpdateRollback(t *testing.T) {
	t.Parallel()
	s, _ := openTemp(t)
	ctx := context.Background()
	boom := errors.New("boom")
	err := s.Update(ctx, func(tx ldapserver.UpdateTx) error {
		if err := tx.Add(ctx, ldapserver.NewEntry("dc=example,dc=test")); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("Update error = %v", err)
	}
	err = s.View(ctx, func(tx ldapserver.ReadTx) error {
		_, err := tx.Entry(ctx, mustParseDN(t, "dc=example,dc=test"))
		return err
	})
	if !errors.Is(err, ldapserver.ErrNoSuchObject) {
		t.Fatalf("rolled-back entry visible: %v", err)
	}
}

func TestStoreRenameMovesDescendants(t *testing.T) {
	t.Parallel()
	s, _ := openTemp(t)
	seedTree(t, s)
	ctx := context.Background()
	from := mustParseDN(t, "ou=people,dc=example,dc=test")
	to := mustParseDN(t, "ou=users,dc=example,dc=test")
	if err := s.Update(ctx, func(tx ldapserver.UpdateTx) error {
		return tx.Rename(ctx, from, to)
	}); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	err := s.View(ctx, func(tx ldapserver.ReadTx) error {
		if _, err := tx.Entry(ctx, from); !errors.Is(err, ldapserver.ErrNoSuchObject) {
			t.Fatalf("old DN still present: %v", err)
		}
		e, err := tx.Entry(ctx, mustParseDN(t, "uid=alice,ou=users,dc=example,dc=test"))
		if err != nil {
			t.Fatalf("renamed child: %v", err)
		}
		if e.DN != "uid=alice,ou=users,dc=example,dc=test" {
			t.Fatalf("child DN = %q", e.DN)
		}
		kids, err := tx.Children(ctx, to)
		if err != nil {
			t.Fatalf("children of renamed: %v", err)
		}
		if len(kids) != 2 {
			t.Fatalf("children of renamed = %v", dnsOf(kids))
		}
		kids, err = tx.Children(ctx, mustParseDN(t, "dc=example,dc=test"))
		if err != nil {
			return err
		}
		if len(kids) != 1 || kids[0].DN != "ou=users,dc=example,dc=test" {
			t.Fatalf("suffix children after rename = %v", dnsOf(kids))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("View: %v", err)
	}
}

func TestStoreRenameAcrossParents(t *testing.T) {
	t.Parallel()
	s, _ := openTemp(t)
	seedTree(t, s)
	ctx := context.Background()
	if err := s.Update(ctx, func(tx ldapserver.UpdateTx) error {
		return tx.Add(ctx, ldapserver.NewEntry("ou=other,dc=example,dc=test"))
	}); err != nil {
		t.Fatalf("add target parent: %v", err)
	}
	// Moving changes the root's parent link; descendants keep their ids
	// and relative shape.
	if err := s.Update(ctx, func(tx ldapserver.UpdateTx) error {
		return tx.Rename(ctx,
			mustParseDN(t, "ou=people,dc=example,dc=test"),
			mustParseDN(t, "ou=staff,ou=other,dc=example,dc=test"))
	}); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	err := s.View(ctx, func(tx ldapserver.ReadTx) error {
		kids, err := tx.Children(ctx, mustParseDN(t, "ou=other,dc=example,dc=test"))
		if err != nil {
			return err
		}
		if len(kids) != 1 || kids[0].DN != "ou=staff,ou=other,dc=example,dc=test" {
			t.Fatalf("new parent children = %v", dnsOf(kids))
		}
		sub, err := tx.Subtree(ctx, mustParseDN(t, "ou=staff,ou=other,dc=example,dc=test"))
		if err != nil {
			return err
		}
		if len(sub) != 3 {
			t.Fatalf("moved subtree = %v", dnsOf(sub))
		}
		kids, err = tx.Children(ctx, mustParseDN(t, "dc=example,dc=test"))
		if err != nil {
			return err
		}
		if got := dnsOf(kids); fmt.Sprint(got) != fmt.Sprint([]string{"ou=other,dc=example,dc=test"}) {
			t.Fatalf("old parent children = %v", got)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("View: %v", err)
	}
}

func TestStoreRenameDescendantClash(t *testing.T) {
	t.Parallel()
	s, _ := openTemp(t)
	ctx := context.Background()
	// cn=c,ou=z is added before its parent exists (the store does not
	// require parent presence; dispatch does). Renaming ou=a onto ou=z
	// would collide with the orphan, so the whole rename must fail
	// before any write.
	err := s.Update(ctx, func(tx ldapserver.UpdateTx) error {
		for _, dn := range []string{
			"dc=example,dc=test",
			"ou=a,dc=example,dc=test",
			"cn=c,ou=a,dc=example,dc=test",
			"cn=c,ou=z,dc=example,dc=test",
		} {
			if err := tx.Add(ctx, ldapserver.NewEntry(dn)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	err = s.Update(ctx, func(tx ldapserver.UpdateTx) error {
		return tx.Rename(ctx,
			mustParseDN(t, "ou=a,dc=example,dc=test"),
			mustParseDN(t, "ou=z,dc=example,dc=test"))
	})
	if !errors.Is(err, ldapserver.ErrEntryExists) {
		t.Fatalf("rename with descendant clash = %v, want ErrEntryExists", err)
	}
	// Nothing moved: the source subtree is intact.
	err = s.View(ctx, func(tx ldapserver.ReadTx) error {
		if _, err := tx.Entry(ctx, mustParseDN(t, "cn=c,ou=a,dc=example,dc=test")); err != nil {
			t.Fatalf("source child lost: %v", err)
		}
		if _, err := tx.Entry(ctx, mustParseDN(t, "ou=a,dc=example,dc=test")); err != nil {
			t.Fatalf("source root lost: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("View: %v", err)
	}
}

func TestStoreOrphanChildAdopted(t *testing.T) {
	t.Parallel()
	s, _ := openTemp(t)
	ctx := context.Background()
	// Add the child before the parent; once the parent exists, Children
	// and Subtree must find the child (FakeStore structural parity).
	err := s.Update(ctx, func(tx ldapserver.UpdateTx) error {
		if err := tx.Add(ctx, ldapserver.NewEntry("dc=example,dc=test")); err != nil {
			return err
		}
		return tx.Add(ctx, ldapserver.NewEntry("cn=c,ou=z,dc=example,dc=test"))
	})
	if err != nil {
		t.Fatalf("add orphan: %v", err)
	}
	err = s.View(ctx, func(tx ldapserver.ReadTx) error {
		_, err := tx.Children(ctx, mustParseDN(t, "ou=z,dc=example,dc=test"))
		return err
	})
	if !errors.Is(err, ldapserver.ErrNoSuchObject) {
		t.Fatalf("children of missing parent: %v", err)
	}
	err = s.Update(ctx, func(tx ldapserver.UpdateTx) error {
		return tx.Add(ctx, ldapserver.NewEntry("ou=z,dc=example,dc=test"))
	})
	if err != nil {
		t.Fatalf("add parent: %v", err)
	}
	err = s.View(ctx, func(tx ldapserver.ReadTx) error {
		kids, err := tx.Children(ctx, mustParseDN(t, "ou=z,dc=example,dc=test"))
		if err != nil {
			return err
		}
		if len(kids) != 1 || kids[0].DN != "cn=c,ou=z,dc=example,dc=test" {
			t.Fatalf("adopted children = %v", dnsOf(kids))
		}
		sub, err := tx.Subtree(ctx, mustParseDN(t, "dc=example,dc=test"))
		if err != nil {
			return err
		}
		if len(sub) != 3 {
			t.Fatalf("subtree = %v", dnsOf(sub))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("View: %v", err)
	}
}

func TestStoreCopyOnRead(t *testing.T) {
	t.Parallel()
	s, _ := openTemp(t)
	ctx := context.Background()
	if err := s.Update(ctx, func(tx ldapserver.UpdateTx) error {
		return tx.Add(ctx, ldapserver.NewEntry("dc=example,dc=test",
			ldapserver.StringAttribute("description", "original")))
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	// Mutating a returned entry must not corrupt stored state.
	if err := s.View(ctx, func(tx ldapserver.ReadTx) error {
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
	if err := s.View(ctx, func(tx ldapserver.ReadTx) error {
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

func TestStoreReplace(t *testing.T) {
	t.Parallel()
	s, _ := openTemp(t)
	seedTree(t, s)
	ctx := context.Background()
	err := s.Update(ctx, func(tx ldapserver.UpdateTx) error {
		// Replace swaps all attributes and canonicalizes the DN casing.
		return tx.Replace(ctx, ldapserver.NewEntry("UID=Alice,OU=People,dc=example,dc=test",
			ldapserver.StringAttribute("objectClass", "top", "person"),
			ldapserver.StringAttribute("sn", "Changed")))
	})
	if err != nil {
		t.Fatalf("Replace: %v", err)
	}
	err = s.View(ctx, func(tx ldapserver.ReadTx) error {
		e, err := tx.Entry(ctx, mustParseDN(t, "uid=alice,ou=people,dc=example,dc=test"))
		if err != nil {
			return err
		}
		// Canonical form lowercases attribute names; value case is
		// presentation and is preserved (matches FakeStore).
		if e.DN != "uid=Alice,ou=People,dc=example,dc=test" {
			t.Fatalf("DN = %q", e.DN)
		}
		if vals := e.Values("uid"); len(vals) != 0 {
			t.Fatalf("uid should be gone after replace: %q", vals)
		}
		if got := string(e.Values("sn")[0]); got != "Changed" {
			t.Fatalf("sn = %q", got)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("View: %v", err)
	}
}

func TestStoreInvalidEntryDN(t *testing.T) {
	t.Parallel()
	s, _ := openTemp(t)
	err := s.Update(context.Background(), func(tx ldapserver.UpdateTx) error {
		return tx.Add(context.Background(), ldapserver.NewEntry("not-a-dn"))
	})
	if err == nil || errors.Is(err, ldapserver.ErrEntryExists) || errors.Is(err, ldapserver.ErrNoSuchObject) {
		t.Fatalf("add invalid DN: %v", err)
	}
}

func TestStoreClosed(t *testing.T) {
	t.Parallel()
	s, _ := openTemp(t)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	ctx := context.Background()
	err := s.View(ctx, func(tx ldapserver.ReadTx) error { return nil })
	if !errors.Is(err, ldapserver.ErrStoreClosed) {
		t.Fatalf("View after close = %v", err)
	}
	err = s.Update(ctx, func(tx ldapserver.UpdateTx) error { return nil })
	if !errors.Is(err, ldapserver.ErrStoreClosed) {
		t.Fatalf("Update after close = %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close = %v, want nil (idempotent)", err)
	}
}

func TestStoreContextCancelled(t *testing.T) {
	t.Parallel()
	s, _ := openTemp(t)
	seedTree(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.View(ctx, func(tx ldapserver.ReadTx) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("View with cancelled ctx = %v", err)
	}
	if err := s.Update(ctx, func(tx ldapserver.UpdateTx) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("Update with cancelled ctx = %v", err)
	}
}

func TestStoreBinaryAndEmptyValues(t *testing.T) {
	t.Parallel()
	s, _ := openTemp(t)
	ctx := context.Background()
	binary := []byte{0x00, 0x01, 0xff, 0xfe, 0x00}
	err := s.Update(ctx, func(tx ldapserver.UpdateTx) error {
		return tx.Add(ctx, &ldapserver.Entry{
			DN: "cn=bin,dc=example,dc=test",
			Attributes: []ldapserver.Attribute{
				{Name: "objectClass", Values: [][]byte{[]byte("top")}},
				{Name: "userCertificate;binary", Values: [][]byte{binary, {}}},
				{Name: "description", Values: [][]byte{}},
			},
		})
	})
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	err = s.View(ctx, func(tx ldapserver.ReadTx) error {
		e, err := tx.Entry(ctx, mustParseDN(t, "cn=bin,dc=example,dc=test"))
		if err != nil {
			return err
		}
		vals := e.Values("usercertificate;binary")
		if len(vals) != 2 || !equalBytes(vals[0], binary) || len(vals[1]) != 0 {
			t.Fatalf("binary values = %v", vals)
		}
		if vals := e.Values("description"); len(vals) != 0 {
			t.Fatalf("empty attribute = %v", vals)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("View: %v", err)
	}
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestStoreConcurrentReadWrite hammers one writer with many concurrent
// readers under -race. Readers must observe either the pre- or
// post-commit snapshot, never a partial write or a decode failure (bbolt
// MVCC). The writer adds and deletes a marker entry in each transaction;
// readers walk the subtree and check structural consistency.
func TestStoreConcurrentReadWrite(t *testing.T) {
	t.Parallel()
	s, _ := openTemp(t)
	seedTree(t, s)
	ctx := context.Background()

	done := make(chan struct{})
	errCh := make(chan error, 16)

	// One writer (bbolt serializes writers; the Store contract is one
	// writer at a time through the dispatch layer).
	var writer sync.WaitGroup
	writer.Add(1)
	go func() {
		defer writer.Done()
		defer close(done)
		for i := 0; i < 200; i++ {
			marker := fmt.Sprintf("cn=marker-%d,ou=people,dc=example,dc=test", i%10)
			err := s.Update(ctx, func(tx ldapserver.UpdateTx) error {
				dn, err := config.ParseDN(marker)
				if err != nil {
					return err
				}
				if _, err := tx.Entry(ctx, dn); err == nil {
					return tx.Delete(ctx, dn)
				}
				return tx.Add(ctx, ldapserver.NewEntry(marker,
					ldapserver.StringAttribute("objectClass", "top", "device"),
					ldapserver.StringAttribute("cn", fmt.Sprintf("marker-%d", i%10))))
			})
			if err != nil {
				errCh <- fmt.Errorf("writer: %w", err)
				return
			}
		}
	}()

	var readers sync.WaitGroup
	for r := 0; r < 8; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-done:
					return
				default:
				}
				err := s.View(ctx, func(tx ldapserver.ReadTx) error {
					sub, err := tx.Subtree(ctx, mustParseDN(t, "dc=example,dc=test"))
					if err != nil {
						return err
					}
					for _, e := range sub {
						// Every entry in the subtree must decode and its
						// DN must parse; a torn write would break one of
						// these invariants.
						if _, err := config.ParseDN(e.DN); err != nil {
							return fmt.Errorf("bad stored DN %q: %w", e.DN, err)
						}
						if len(e.Values("objectClass")) == 0 {
							return fmt.Errorf("entry %q missing objectClass", e.DN)
						}
					}
					// Entry and Children agree within the snapshot.
					kids, err := tx.Children(ctx, mustParseDN(t, "ou=people,dc=example,dc=test"))
					if err != nil {
						return err
					}
					for _, k := range kids {
						dn, err := config.ParseDN(k.DN)
						if err != nil {
							return fmt.Errorf("bad child DN %q: %w", k.DN, err)
						}
						if _, err := tx.Entry(ctx, dn); err != nil {
							return fmt.Errorf("child %q not readable: %w", k.DN, err)
						}
					}
					return nil
				})
				if err != nil {
					errCh <- fmt.Errorf("reader: %w", err)
					return
				}
			}
		}()
	}

	writer.Wait()
	readers.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}

	// After the dust settles the tree is readable and consistent.
	err := s.View(ctx, func(tx ldapserver.ReadTx) error {
		sub, err := tx.Subtree(ctx, mustParseDN(t, "dc=example,dc=test"))
		if err != nil {
			return err
		}
		if len(sub) < 4 {
			t.Fatalf("subtree after churn = %v", dnsOf(sub))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("final View: %v", err)
	}
}
