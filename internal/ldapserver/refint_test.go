package ldapserver

import (
	"context"
	"slices"
	"testing"
)

// refIntOptions seeds the standard tree and registers the referential
// integrity plugin (optionally followed by memberOf in the same order
// cmd/labldapd wires them: referint repairs forward references before
// memberOf recomputes derived ones).
func refIntOptions(t *testing.T, withMemberOf bool, mutate func(*Options)) Options {
	t.Helper()
	ri, err := NewRefIntPlugin("dc=example,dc=test")
	if err != nil {
		t.Fatalf("NewRefIntPlugin: %v", err)
	}
	return schemaWireOptions(t, func(o *Options) {
		o.Plugins = append(o.Plugins, ri)
		if withMemberOf {
			mo, err := NewMemberOfPlugin("dc=example,dc=test", true)
			if err != nil {
				t.Fatalf("NewMemberOfPlugin: %v", err)
			}
			o.Plugins = append(o.Plugins, mo)
		}
		if mutate != nil {
			mutate(o)
		}
	})
}

func groupMembers(t *testing.T, opts Options, dn, attr string) []string {
	t.Helper()
	e, err := fetchEntry(t, opts, dn)
	if err != nil {
		t.Fatalf("fetch %s: %v", dn, err)
	}
	var out []string
	for _, v := range e.Values(attr) {
		out = append(out, string(v))
	}
	slices.Sort(out)
	return out
}

// TestRefIntDeleteRemovesMember: deleting a user repairs the group's member
// list in the same commit (update-delay 0, C7).
func TestRefIntDeleteRemovesMember(t *testing.T) {
	t.Parallel()
	opts := refIntOptions(t, false, nil)
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	group := "cn=admins,ou=groups,dc=example,dc=test"
	alice := "uid=alice,ou=people,dc=example,dc=test"
	bob := "uid=bob,ou=people,dc=example,dc=test"

	res := roundTrip(t, cl, &ModifyRequest{DN: group, Changes: []ModifyChange{
		{Op: ModifyAdd, Attr: StringAttribute("member", bob)},
	}})
	if res.Code != ResultSuccess {
		t.Fatalf("add member = %v", res)
	}
	res = roundTrip(t, cl, &DeleteRequest{DN: alice})
	if res.Code != ResultSuccess {
		t.Fatalf("delete = %v", res)
	}
	if got := groupMembers(t, opts, group, "member"); !slices.Equal(got, []string{bob}) {
		t.Fatalf("members after delete = %v, want [%s]", got, bob)
	}
}

// TestRefIntDeleteLastMemberKeepsGroup: 389-observed — the reference is
// removed even when it is the last member; the groupOfNames persists with
// no member attribute because the plugin-internal repair bypasses the
// schema MUST gate (Delta candidate for the T-147 oracle).
func TestRefIntDeleteLastMemberKeepsGroup(t *testing.T) {
	t.Parallel()
	opts := refIntOptions(t, false, nil)
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	group := "cn=admins,ou=groups,dc=example,dc=test"
	alice := "uid=alice,ou=people,dc=example,dc=test"

	res := roundTrip(t, cl, &DeleteRequest{DN: alice})
	if res.Code != ResultSuccess {
		t.Fatalf("delete = %v", res)
	}
	e, err := fetchEntry(t, opts, group)
	if err != nil {
		t.Fatalf("group must survive last-member delete: %v", err)
	}
	if got := e.Values("member"); len(got) != 0 {
		t.Fatalf("member after last-member delete = %q, want attribute gone", got)
	}
}

// TestRefIntDeleteOutsideSuffix: a delete outside the managed suffix is out
// of scope — neither out-of-suffix ("foreign") entries nor in-suffix groups
// referencing the foreign DN are rewritten (no foreign entries in v1).
func TestRefIntDeleteOutsideSuffix(t *testing.T) {
	t.Parallel()
	opts := refIntOptions(t, false, nil)
	ctx := context.Background()
	// Plant a foreign sub-tree directly (the LDAP write path is
	// suffix-gated): a foreign entry, a foreign group referencing it, and an
	// in-suffix group with a foreign member value.
	if err := opts.Store.Update(ctx, func(tx UpdateTx) error {
		for _, e := range []*Entry{
			NewEntry("dc=other,dc=test",
				StringAttribute("objectClass", "top", "domain"),
				StringAttribute("dc", "other")),
			NewEntry("uid=x,dc=other,dc=test",
				StringAttribute("objectClass", "top", "person"),
				StringAttribute("cn", "X"), StringAttribute("sn", "X")),
			NewEntry("cn=g,dc=other,dc=test",
				StringAttribute("objectClass", "top", "groupOfNames"),
				StringAttribute("cn", "g"),
				StringAttribute("member", "uid=x,dc=other,dc=test")),
			NewEntry("cn=mixed,ou=groups,dc=example,dc=test",
				StringAttribute("objectClass", "top", "groupOfNames"),
				StringAttribute("cn", "mixed"),
				StringAttribute("member",
					"uid=alice,ou=people,dc=example,dc=test",
					"uid=x,dc=other,dc=test")),
		} {
			if err := tx.Add(ctx, e); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("plant foreign tree: %v", err)
	}
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)

	res := roundTrip(t, cl, &DeleteRequest{DN: "uid=x,dc=other,dc=test"})
	if res.Code != ResultSuccess {
		t.Fatalf("delete foreign entry = %v", res)
	}
	// The foreign group keeps its (now dangling) member value.
	if got := groupMembers(t, opts, "cn=g,dc=other,dc=test", "member"); !slices.Equal(got, []string{"uid=x,dc=other,dc=test"}) {
		t.Fatalf("foreign group rewritten: %v", got)
	}
	// The in-suffix group is untouched too: the deleted DN was out of scope.
	want := []string{"uid=alice,ou=people,dc=example,dc=test", "uid=x,dc=other,dc=test"}
	if got := groupMembers(t, opts, "cn=mixed,ou=groups,dc=example,dc=test", "member"); !slices.Equal(got, want) {
		t.Fatalf("in-suffix group after foreign delete = %v, want %v", got, want)
	}
}

// TestRefIntRenameRewritesMember: renaming an entry rewrites forward
// references in the same commit (389 refint modrdn parity), preserving the
// RFC 4519 '#' suffix on uniqueMember values.
func TestRefIntRenameRewritesMember(t *testing.T) {
	t.Parallel()
	opts := refIntOptions(t, false, nil)
	ctx := context.Background()
	if err := opts.Store.Update(ctx, func(tx UpdateTx) error {
		return tx.Add(ctx, NewEntry("cn=elite,ou=groups,dc=example,dc=test",
			StringAttribute("objectClass", "top", "groupOfUniqueNames"),
			StringAttribute("cn", "elite"),
			StringAttribute("uniqueMember", "uid=bob,ou=people,dc=example,dc=test#'0101'B")))
	}); err != nil {
		t.Fatalf("seed uniqueMember group: %v", err)
	}
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	bob := "uid=bob,ou=people,dc=example,dc=test"

	res := roundTrip(t, cl, &ModifyDNRequest{DN: "cn=admins,ou=groups,dc=example,dc=test", NewRDN: "cn=administrators"})
	if res.Code != ResultSuccess {
		t.Fatalf("rename group = %v", res)
	}
	res = roundTrip(t, cl, &ModifyDNRequest{DN: bob, NewRDN: "uid=robert", DeleteOldRDN: true})
	if res.Code != ResultSuccess {
		t.Fatalf("rename user = %v", res)
	}
	if got := groupMembers(t, opts, "cn=elite,ou=groups,dc=example,dc=test", "uniqueMember"); !slices.Equal(got, []string{"uid=robert,ou=people,dc=example,dc=test#'0101'B"}) {
		t.Fatalf("uniqueMember after rename = %v", got)
	}
}

// TestRefIntFixup: the bootstrap/reset sweep drops references to missing
// in-suffix entries, keeps live and out-of-suffix references, and only
// repairs groups inside the managed suffix.
func TestRefIntFixup(t *testing.T) {
	t.Parallel()
	ri, err := NewRefIntPlugin("dc=example,dc=test")
	if err != nil {
		t.Fatalf("NewRefIntPlugin: %v", err)
	}
	opts := refIntOptions(t, false, nil)
	ctx := context.Background()
	// A group with a live member, a dangling in-suffix member, a foreign
	// member, and an unparseable member value; plus a foreign group with a
	// dangling reference that must survive the sweep.
	if err := opts.Store.Update(ctx, func(tx UpdateTx) error {
		for _, e := range []*Entry{
			NewEntry("cn=stale,ou=groups,dc=example,dc=test",
				StringAttribute("objectClass", "top", "groupOfNames"),
				StringAttribute("cn", "stale"),
				StringAttribute("member",
					"uid=alice,ou=people,dc=example,dc=test",
					"uid=ghost,ou=people,dc=example,dc=test",
					"uid=x,dc=other,dc=test",
					"not a dn")),
			NewEntry("dc=other,dc=test",
				StringAttribute("objectClass", "top", "domain"),
				StringAttribute("dc", "other")),
			NewEntry("cn=g,dc=other,dc=test",
				StringAttribute("objectClass", "top", "groupOfNames"),
				StringAttribute("cn", "g"),
				StringAttribute("member", "uid=ghost,dc=other,dc=test")),
		} {
			if err := tx.Add(ctx, e); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("plant: %v", err)
	}

	if err := ri.Fixup(ctx, opts.Store); err != nil {
		t.Fatalf("fixup: %v", err)
	}
	want := []string{"not a dn", "uid=alice,ou=people,dc=example,dc=test", "uid=x,dc=other,dc=test"}
	if got := groupMembers(t, opts, "cn=stale,ou=groups,dc=example,dc=test", "member"); !slices.Equal(got, want) {
		t.Fatalf("after fixup = %v, want %v", got, want)
	}
	if got := groupMembers(t, opts, "cn=g,dc=other,dc=test", "member"); !slices.Equal(got, []string{"uid=ghost,dc=other,dc=test"}) {
		t.Fatalf("foreign group touched by fixup: %v", got)
	}
}

// TestRefIntWithMemberOfGroupDelete: both plugins on one delete (C7): the
// deleted group disappears from its members' memberOf — including the
// transitive grant — and from the parent group's forward references, all in
// the same commit.
func TestRefIntWithMemberOfGroupDelete(t *testing.T) {
	t.Parallel()
	opts := refIntOptions(t, true, nil)
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	bob := "uid=bob,ou=people,dc=example,dc=test"
	inner := "cn=inner,ou=groups,dc=example,dc=test"
	outer := "cn=outer,ou=groups,dc=example,dc=test"

	addGroup(t, cl, inner, "inner", "member", bob)
	addGroup(t, cl, outer, "outer", "member", inner, "uid=alice,ou=people,dc=example,dc=test")
	if got := searchAttrValues(t, cl, bob, "memberOf"); !slices.Equal(got, []string{inner, outer}) {
		t.Fatalf("memberOf before delete = %v", got)
	}

	res := roundTrip(t, cl, &DeleteRequest{DN: inner})
	if res.Code != ResultSuccess {
		t.Fatalf("delete inner = %v", res)
	}
	if got := searchAttrValues(t, cl, bob, "memberOf"); len(got) != 0 {
		t.Fatalf("memberOf after delete = %v, want gone", got)
	}
	if got := groupMembers(t, opts, outer, "member"); !slices.Equal(got, []string{"uid=alice,ou=people,dc=example,dc=test"}) {
		t.Fatalf("outer member after delete = %v", got)
	}
}
