package ldapserver

import (
	"context"
	"slices"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// memberOfOptions seeds the standard tree (alice, bob, cn=admins with
// member alice — seeded directly, so memberOf starts un-derived) and
// registers the MemberOf plugin with the given nested-groups flag against
// the contract schema (T-132).
func memberOfOptions(t *testing.T, nested bool, mutate func(*Options)) Options {
	t.Helper()
	mo, err := NewMemberOfPlugin("dc=example,dc=test", nested)
	if err != nil {
		t.Fatalf("NewMemberOfPlugin: %v", err)
	}
	return schemaWireOptions(t, func(o *Options) {
		o.Plugins = append(o.Plugins, mo)
		if mutate != nil {
			mutate(o)
		}
	})
}

// searchAttrValues returns one attribute's values from a base-object search
// over the wire.
func searchAttrValues(t *testing.T, cl *ldapTestClient, dn, attr string) []string {
	t.Helper()
	entries, done := search(t, cl, &SearchRequest{
		BaseDN: dn, Scope: ScopeBaseObject,
		Filter: &FilterPresent{Attr: "objectClass"}, Attributes: []string{attr},
	})
	if done.Result.Code != ResultSuccess || len(entries) != 1 {
		t.Fatalf("search %s %s = %v, %d entries", dn, attr, done.Result, len(entries))
	}
	return dseAttr(entries[0], attr)
}

func addGroup(t *testing.T, cl *ldapTestClient, dn, cn, memberAttr string, members ...string) {
	t.Helper()
	oc := "groupOfNames"
	if memberAttr == "uniqueMember" {
		oc = "groupOfUniqueNames"
	}
	res := roundTrip(t, cl, &AddRequest{
		DN: dn,
		Attributes: []Attribute{
			StringAttribute("objectClass", "top", oc),
			StringAttribute("cn", cn),
			StringAttribute(memberAttr, members...),
		},
	})
	if res.Code != ResultSuccess {
		t.Fatalf("add group %s = %v", dn, res)
	}
}

// TestMemberOfAddGroupSameCommit: adding a group makes memberOf visible on
// its members in a search issued right after the write on the same client
// (same-commit, C7), and nsmemberof rides along (ADR-0009 decision 20).
func TestMemberOfAddGroupSameCommit(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, memberOfOptions(t, false, nil), nil)
	cl := dialTestClient(t, addr)

	addGroup(t, cl, "cn=staff,ou=groups,dc=example,dc=test", "staff", "member",
		"uid=alice,ou=people,dc=example,dc=test",
		"uid=bob,ou=people,dc=example,dc=test")

	// alice was seeded into cn=admins before any plugin ran; touching her
	// membership recomputes the whole set, so she self-heals to both groups.
	for u, want := range map[string][]string{
		"uid=alice,ou=people,dc=example,dc=test": {"cn=admins,ou=groups,dc=example,dc=test", "cn=staff,ou=groups,dc=example,dc=test"},
		"uid=bob,ou=people,dc=example,dc=test":   {"cn=staff,ou=groups,dc=example,dc=test"},
	} {
		got := searchAttrValues(t, cl, u, "memberOf")
		if !slices.Equal(got, want) {
			t.Fatalf("memberOf %s = %v, want %v", u, got, want)
		}
		ocs := searchAttrValues(t, cl, u, "objectClass")
		if !slices.Contains(ocs, "nsmemberof") {
			t.Fatalf("objectClass %s = %v, want nsmemberof", u, ocs)
		}
	}
	// memberOf is operational: a default selection must not return it.
	entries, _ := search(t, cl, &SearchRequest{
		BaseDN: "uid=alice,ou=people,dc=example,dc=test", Scope: ScopeBaseObject,
		Filter: &FilterPresent{Attr: "objectClass"},
	})
	for _, a := range entries[0].Attributes {
		if a.Name == "memberOf" {
			t.Fatalf("default selection leaked operational memberOf: %+v", entries[0].Attributes)
		}
	}
}

// TestMemberOfModifyAddRemoveMember: member add grants memberOf and
// nsmemberof; member delete drops memberOf, but leftover nsmemberof is
// retained after the last membership (D26 / 389).
func TestMemberOfModifyAddRemoveMember(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, memberOfOptions(t, false, nil), nil)
	cl := dialTestClient(t, addr)
	group := "cn=admins,ou=groups,dc=example,dc=test"
	bob := "uid=bob,ou=people,dc=example,dc=test"

	res := roundTrip(t, cl, &ModifyRequest{DN: group, Changes: []ModifyChange{
		{Op: ModifyAdd, Attr: StringAttribute("member", bob)},
	}})
	if res.Code != ResultSuccess {
		t.Fatalf("add member = %v", res)
	}
	if got := searchAttrValues(t, cl, bob, "memberOf"); !slices.Equal(got, []string{group}) {
		t.Fatalf("memberOf after add = %v", got)
	}
	if ocs := searchAttrValues(t, cl, bob, "objectClass"); !slices.Contains(ocs, "nsmemberof") {
		t.Fatalf("nsmemberof missing after grant: %v", ocs)
	}

	res = roundTrip(t, cl, &ModifyRequest{DN: group, Changes: []ModifyChange{
		{Op: ModifyDelete, Attr: StringAttribute("member", bob)},
	}})
	if res.Code != ResultSuccess {
		t.Fatalf("remove member = %v", res)
	}
	if got := searchAttrValues(t, cl, bob, "memberOf"); len(got) != 0 {
		t.Fatalf("memberOf after remove = %v, want gone", got)
	}
	if ocs := searchAttrValues(t, cl, bob, "objectClass"); !slices.Contains(ocs, "nsmemberof") {
		t.Fatalf("nsmemberof must remain after last memberOf removal: %v", ocs)
	}
}

// TestMemberOfReplaceMembers: a wholesale member replace moves memberOf from
// the old set to the new one in one commit.
func TestMemberOfReplaceMembers(t *testing.T) {
	t.Parallel()
	mo, err := NewMemberOfPlugin("dc=example,dc=test", false)
	if err != nil {
		t.Fatalf("NewMemberOfPlugin: %v", err)
	}
	opts := memberOfOptions(t, false, nil)
	// Sync the seeded skew first: admins lists alice but alice has no
	// memberOf yet (the seed bypasses the write path).
	if err := mo.Fixup(context.Background(), opts.Store); err != nil {
		t.Fatalf("fixup: %v", err)
	}
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	alice := "uid=alice,ou=people,dc=example,dc=test"
	bob := "uid=bob,ou=people,dc=example,dc=test"
	group := "cn=admins,ou=groups,dc=example,dc=test"

	if got := searchAttrValues(t, cl, alice, "memberOf"); !slices.Equal(got, []string{group}) {
		t.Fatalf("memberOf after fixup = %v", got)
	}
	res := roundTrip(t, cl, &ModifyRequest{DN: group, Changes: []ModifyChange{
		{Op: ModifyReplace, Attr: StringAttribute("member", bob)},
	}})
	if res.Code != ResultSuccess {
		t.Fatalf("replace members = %v", res)
	}
	if got := searchAttrValues(t, cl, alice, "memberOf"); len(got) != 0 {
		t.Fatalf("alice memberOf after replace = %v, want gone", got)
	}
	if got := searchAttrValues(t, cl, bob, "memberOf"); !slices.Equal(got, []string{group}) {
		t.Fatalf("bob memberOf after replace = %v", got)
	}
}

// TestMemberOfNestedGroups: with the nestedGroups flag on, membership
// propagates transitively; with it off, only the direct group earns
// memberOf on the user (the nested group entry itself still records its own
// direct membership).
func TestMemberOfNestedGroups(t *testing.T) {
	t.Parallel()
	user := "uid=bob,ou=people,dc=example,dc=test"
	inner := "cn=inner,ou=groups,dc=example,dc=test"
	outer := "cn=outer,ou=groups,dc=example,dc=test"

	setup := func(t *testing.T, nested bool) *ldapTestClient {
		_, addr := serveTestServerFrom(t, memberOfOptions(t, nested, nil), nil)
		cl := dialTestClient(t, addr)
		addGroup(t, cl, inner, "inner", "member", user)
		addGroup(t, cl, outer, "outer", "member", inner)
		return cl
	}

	t.Run("enabled", func(t *testing.T) {
		t.Parallel()
		cl := setup(t, true)
		got := searchAttrValues(t, cl, user, "memberOf")
		want := []string{inner, outer}
		if !slices.Equal(got, want) {
			t.Fatalf("nested memberOf = %v, want %v", got, want)
		}
		if got := searchAttrValues(t, cl, inner, "memberOf"); !slices.Equal(got, []string{outer}) {
			t.Fatalf("inner memberOf = %v", got)
		}
		// Keep a second member on outer so the modify cannot empty the
		// group (groupOfNames member is MUST; emptying is refused).
		res := roundTrip(t, cl, &ModifyRequest{DN: outer, Changes: []ModifyChange{
			{Op: ModifyAdd, Attr: StringAttribute("member", "uid=alice,ou=people,dc=example,dc=test")},
		}})
		if res.Code != ResultSuccess {
			t.Fatalf("pad outer = %v", res)
		}
		// Removing the nesting edge retracts the transitive grant only.
		res = roundTrip(t, cl, &ModifyRequest{DN: outer, Changes: []ModifyChange{
			{Op: ModifyDelete, Attr: StringAttribute("member", inner)},
		}})
		if res.Code != ResultSuccess {
			t.Fatalf("unnest = %v", res)
		}
		if got := searchAttrValues(t, cl, user, "memberOf"); !slices.Equal(got, []string{inner}) {
			t.Fatalf("memberOf after unnest = %v", got)
		}
	})

	t.Run("disabled", func(t *testing.T) {
		t.Parallel()
		cl := setup(t, false)
		if got := searchAttrValues(t, cl, user, "memberOf"); !slices.Equal(got, []string{inner}) {
			t.Fatalf("flat memberOf = %v, want only %s", got, inner)
		}
		if got := searchAttrValues(t, cl, inner, "memberOf"); !slices.Equal(got, []string{outer}) {
			t.Fatalf("inner memberOf = %v", got)
		}
	})
}

// TestMemberOfNestedMultiPath: with nesting, removing one path to a group
// must not drop memberOf while another path still reaches it.
func TestMemberOfNestedMultiPath(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, memberOfOptions(t, true, nil), nil)
	cl := dialTestClient(t, addr)
	user := "uid=bob,ou=people,dc=example,dc=test"
	g1 := "cn=g1,ou=groups,dc=example,dc=test"
	g2 := "cn=g2,ou=groups,dc=example,dc=test"
	top := "cn=top,ou=groups,dc=example,dc=test"

	addGroup(t, cl, g1, "g1", "member", user)
	addGroup(t, cl, g2, "g2", "member", user)
	// alice pads top so removing nested paths never empties the group
	// (groupOfNames member is MUST; the schema gate refuses emptying).
	addGroup(t, cl, top, "top", "member", g1, g2, "uid=alice,ou=people,dc=example,dc=test")

	if got := searchAttrValues(t, cl, user, "memberOf"); !slices.Equal(got, []string{g1, g2, top}) {
		t.Fatalf("memberOf = %v", got)
	}
	// Remove g1 from top: g2 still reaches top.
	res := roundTrip(t, cl, &ModifyRequest{DN: top, Changes: []ModifyChange{
		{Op: ModifyDelete, Attr: StringAttribute("member", g1)},
	}})
	if res.Code != ResultSuccess {
		t.Fatalf("remove path = %v", res)
	}
	if got := searchAttrValues(t, cl, user, "memberOf"); !slices.Equal(got, []string{g1, g2, top}) {
		t.Fatalf("memberOf after one path removed = %v", got)
	}
	// Remove the last path: top drops off.
	res = roundTrip(t, cl, &ModifyRequest{DN: top, Changes: []ModifyChange{
		{Op: ModifyDelete, Attr: StringAttribute("member", g2)},
	}})
	if res.Code != ResultSuccess {
		t.Fatalf("remove last path = %v", res)
	}
	if got := searchAttrValues(t, cl, user, "memberOf"); !slices.Equal(got, []string{g1, g2}) {
		t.Fatalf("memberOf after last path removed = %v", got)
	}
}

// TestMemberOfDeleteGroupRevokes: deleting a group removes its memberOf
// from every member in the same commit.
func TestMemberOfDeleteGroupRevokes(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, memberOfOptions(t, true, nil), nil)
	cl := dialTestClient(t, addr)
	user := "uid=bob,ou=people,dc=example,dc=test"
	g2 := "cn=g2,ou=groups,dc=example,dc=test"
	g1 := "cn=g1,ou=groups,dc=example,dc=test"
	addGroup(t, cl, g2, "g2", "member", user)
	addGroup(t, cl, g1, "g1", "member", g2)

	res := roundTrip(t, cl, &DeleteRequest{DN: g2})
	if res.Code != ResultSuccess {
		t.Fatalf("delete group = %v", res)
	}
	if got := searchAttrValues(t, cl, user, "memberOf"); len(got) != 0 {
		t.Fatalf("memberOf after group delete = %v, want gone (incl. transitive g1)", got)
	}
}

// TestMemberOfGroupRenameRewritesValues: renaming a group rewrites the
// stored memberOf values to the new DN in the same commit.
func TestMemberOfGroupRenameRewritesValues(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, memberOfOptions(t, false, nil), nil)
	cl := dialTestClient(t, addr)
	user := "uid=bob,ou=people,dc=example,dc=test"
	addGroup(t, cl, "cn=staff,ou=groups,dc=example,dc=test", "staff", "member", user)

	res := roundTrip(t, cl, &ModifyDNRequest{
		DN: "cn=staff,ou=groups,dc=example,dc=test", NewRDN: "cn=crew", DeleteOldRDN: true,
	})
	if res.Code != ResultSuccess {
		t.Fatalf("rename = %v", res)
	}
	got := searchAttrValues(t, cl, user, "memberOf")
	if !slices.Equal(got, []string{"cn=crew,ou=groups,dc=example,dc=test"}) {
		t.Fatalf("memberOf after group rename = %v", got)
	}
}

// TestMemberOfUniqueMember: groupOfUniqueNames uniqueMember drives memberOf
// the same way, including RFC 4519 '#' suffix tolerance.
func TestMemberOfUniqueMember(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, memberOfOptions(t, false, nil), nil)
	cl := dialTestClient(t, addr)
	user := "uid=bob,ou=people,dc=example,dc=test"
	grp := "cn=elite,ou=groups,dc=example,dc=test"
	addGroup(t, cl, grp, "elite", "uniqueMember", user+"#'0101'B")

	if got := searchAttrValues(t, cl, user, "memberOf"); !slices.Equal(got, []string{grp}) {
		t.Fatalf("memberOf via uniqueMember = %v", got)
	}
}

// TestMemberOfSkipsDanglingAndForeign: member values that do not resolve
// inside the suffix are ignored without failing the write.
func TestMemberOfSkipsDanglingAndForeign(t *testing.T) {
	t.Parallel()
	opts := memberOfOptions(t, false, nil)
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	grp := "cn=mixed,ou=groups,dc=example,dc=test"

	addGroup(t, cl, grp, "mixed", "member",
		"uid=bob,ou=people,dc=example,dc=test",
		"uid=ghost,ou=people,dc=example,dc=test",
		"uid=foreign,dc=other,dc=test")

	if got := searchAttrValues(t, cl, "uid=bob,ou=people,dc=example,dc=test", "memberOf"); !slices.Equal(got, []string{grp}) {
		t.Fatalf("bob memberOf = %v", got)
	}
	// The group entry itself never gains memberOf from its own member list.
	if got := searchAttrValues(t, cl, grp, "memberOf"); len(got) != 0 {
		t.Fatalf("group memberOf = %v, want none", got)
	}
}

// TestMemberOfFixup: the bootstrap/reset sweep converges the whole suffix —
// granting missing memberOf and nsmemberof, stripping stale memberOf
// values. Leftover nsmemberof on an entry whose computed set is empty is
// retained (D26).
func TestMemberOfFixup(t *testing.T) {
	t.Parallel()
	mo, err := NewMemberOfPlugin("dc=example,dc=test", false)
	if err != nil {
		t.Fatalf("NewMemberOfPlugin: %v", err)
	}
	opts := memberOfOptions(t, false, nil)
	// Corrupt the store directly: stale memberOf + nsmemberof on bob, who no
	// group lists; alice is listed by admins but lacks memberOf.
	ctx := context.Background()
	if err := opts.Store.Update(ctx, func(tx UpdateTx) error {
		bobDN, _ := config.ParseDN("uid=bob,ou=people,dc=example,dc=test")
		e, err := tx.Entry(ctx, bobDN)
		if err != nil {
			return err
		}
		setAttr(e, "memberOf", []byte("cn=bogus,ou=groups,dc=example,dc=test"))
		ensureObjectClass(e, "nsmemberof")
		return tx.Replace(ctx, e)
	}); err != nil {
		t.Fatalf("corrupt: %v", err)
	}

	if err := mo.Fixup(ctx, opts.Store); err != nil {
		t.Fatalf("fixup: %v", err)
	}

	alice, err := fetchEntry(t, opts, "uid=alice,ou=people,dc=example,dc=test")
	if err != nil {
		t.Fatalf("fetch alice: %v", err)
	}
	if got := alice.Values("memberOf"); len(got) != 1 || string(got[0]) != "cn=admins,ou=groups,dc=example,dc=test" {
		t.Fatalf("alice memberOf after fixup = %q", got)
	}
	if !hasObjectClass(alice, "nsmemberof") {
		t.Fatal("alice missing nsmemberof after fixup")
	}
	bob, err := fetchEntry(t, opts, "uid=bob,ou=people,dc=example,dc=test")
	if err != nil {
		t.Fatalf("fetch bob: %v", err)
	}
	if got := bob.Values("memberOf"); len(got) != 0 {
		t.Fatalf("bob stale memberOf survived fixup: %q", got)
	}
	if !hasObjectClass(bob, "nsmemberof") {
		t.Fatal("bob leftover nsmemberof must survive fixup with empty memberOf")
	}
	// The suffix root is untouched (not a member of anything).
	root, err := fetchEntry(t, opts, "dc=example,dc=test")
	if err != nil {
		t.Fatalf("fetch root: %v", err)
	}
	if got := root.Values("memberOf"); len(got) != 0 {
		t.Fatalf("root memberOf = %q, want none", got)
	}
}
