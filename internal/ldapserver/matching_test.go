package ldapserver

import (
	"strings"
	"testing"
)

// matchingSchema registers equality rules by name so schema-driven
// resolution is exercised separately from the attribute registry.
func matchingSchema() *FakeSchema {
	return NewFakeSchema(nil, []AttributeTypeDef{
		{OID: "2.5.4.3", Name: "cn", Equality: "caseIgnoreMatch"},
		{OID: "2.5.4.4", Name: "sn", Equality: "caseIgnoreMatch"},
		{OID: "0.9.2342.19200300.100.1.1", Name: "uid", Equality: "caseIgnoreMatch"},
		{OID: "0.9.2342.19200300.100.1.3", Name: "mail", Equality: "caseIgnoreIA5Match"},
		{OID: "2.5.4.31", Name: "member", Equality: "distinguishedNameMatch"},
		{OID: "2.5.4.50", Name: "uniqueMember", Equality: "uniqueMemberMatch"},
		{OID: "2.5.4.0", Name: "objectClass", Equality: "objectIdentifierMatch"},
		{OID: "1.2.3.4", Name: "x-bin", Equality: "octetStringMatch"},
		{OID: "1.2.3.5", Name: "x-ia5exact", Equality: "caseExactIA5Match"},
		{OID: "1.2.3.6", Name: "x-unknownrule", Equality: "someUnimplementedMatch"},
	})
}

// TestRuleMatcherEqualityGolden is the golden-pair table for equality
// rules (T-131 acceptance: uid=Alice matches uid=alice under
// case-ignore).
func TestRuleMatcherEqualityGolden(t *testing.T) {
	t.Parallel()
	m := NewRuleMatcher(matchingSchema())
	for _, tc := range []struct {
		name   string
		attr   string
		value  string
		assert string
		want   bool
	}{
		// caseIgnoreMatch (schema-declared and registry-resolved).
		{"uid case fold", "uid", "Alice", "alice", true},
		{"uid exact", "uid", "alice", "alice", true},
		{"uid distinct", "uid", "alice", "bob", false},
		{"uid surrounding spaces", "uid", "  alice ", "alice", true},
		{"cn space collapse", "cn", "Alice  Adams", "alice adams", true},
		{"cn interior space matters", "cn", "AliceAdams", "alice adams", false},
		{"sn via schema", "sn", "ADAMS", "adams", true},
		// caseIgnoreIA5Match.
		{"mail IA5 fold", "mail", "Alice@Example.COM", "alice@example.com", true},
		{"mail IA5 distinct", "mail", "alice@example.com", "bob@example.com", false},
		// caseExactIA5Match: no case folding.
		{"IA5 exact fold is not applied", "x-ia5exact", "Enabled", "enabled", false},
		{"IA5 exact equal", "x-ia5exact", "Enabled", "Enabled", true},
		// objectIdentifierMatch: descriptors compare case-insensitively.
		{"objectClass fold", "objectClass", "groupOfNames", "GROUPOFNAMES", true},
		// octetStringMatch and fallbacks are byte-exact.
		{"octet no fold", "x-bin", "blob", "BLOB", false},
		{"octet equal", "x-bin", "blob", "blob", true},
		{"unimplemented declared rule is octet", "x-unknownrule", "Blob", "blob", false},
		{"unknown attribute is octet", "x-not-registered", "Blob", "blob", false},
		{"unknown attribute equal", "x-not-registered", "blob", "blob", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := m.Equal(tc.attr, []byte(tc.value), []byte(tc.assert)); got != tc.want {
				t.Fatalf("Equal(%s, %q, %q) = %v, want %v", tc.attr, tc.value, tc.assert, got, tc.want)
			}
		})
	}
}

// TestRuleMatcherRegistryFallback proves the Contract attribute registry
// resolves rules when the Schema does not declare the attribute.
func TestRuleMatcherRegistryFallback(t *testing.T) {
	t.Parallel()
	m := NewRuleMatcher(NewFakeSchema(nil, nil))
	for _, tc := range []struct {
		attr   string
		value  string
		assert string
		want   bool
	}{
		{"uid", "Alice", "ALICE", true},
		{"mail", "Alice@Example.COM", "alice@example.com", true},
		{"description", "Lab  User", "lab user", true},
		{"dc", "Example", "example", true},
		{"userPassword", "hashA", "hasha", false},
		{"nsAccountLock", "true", "TRUE", true},
		{"entryUUID", "ABC-123", "abc-123", true},
	} {
		if got := m.Equal(tc.attr, []byte(tc.value), []byte(tc.assert)); got != tc.want {
			t.Errorf("registry Equal(%s, %q, %q) = %v, want %v", tc.attr, tc.value, tc.assert, got, tc.want)
		}
	}
}

// TestRuleMatcherDNEquality is the T-131 acceptance proof that DN equality
// is structural (canonical DN), never string-suffix matching.
func TestRuleMatcherDNEquality(t *testing.T) {
	t.Parallel()
	m := NewRuleMatcher(matchingSchema())
	const jdoe = "uid=jdoe,ou=people,dc=example,dc=test"
	for _, tc := range []struct {
		name   string
		attr   string
		value  string
		assert string
		want   bool
	}{
		{"identical", "member", jdoe, jdoe, true},
		{"attribute name case", "member", jdoe, "UID=jdoe,OU=People,DC=EXAMPLE,DC=TEST", true},
		{"value case", "member", jdoe, "uid=JDoe,ou=PEOPLE,dc=example,dc=test", true},
		{"space variants", "member", jdoe, "uid=jdoe, ou=people ,  dc=example,dc=test", true},
		{"string suffix is not a match", "member", jdoe, "ou=people,dc=example,dc=test", false},
		{"string prefix is not a match", "member", jdoe, "uid=jdoe,ou=people", false},
		{"sibling leaf", "member", jdoe, "uid=jdoe2,ou=people,dc=example,dc=test", false},
		{"different container", "member", jdoe, "uid=jdoe,ou=other,dc=example,dc=test", false},
		{"escaped comma folds", "member", `cn=Doe\, John,ou=people,dc=example,dc=test`, `cn=doe\, john,OU=People,dc=example,dc=test`, true},
		{"memberOf via registry", "memberOf", "cn=admins,ou=groups,dc=example,dc=test", "CN=Admins, OU=Groups,dc=example,dc=test", true},
		{"malformed stored value", "member", "not-a-dn", jdoe, false},
		{"malformed assertion", "member", jdoe, "not-a-dn", false},
		{"both malformed", "member", "not-a-dn", "not-a-dn", false},
		{"empty assertion", "member", jdoe, "", false},
		{"uniqueMember bit suffix ignored", "uniqueMember", jdoe + "#0101", "UID=JDOE,ou=people,dc=example,dc=test", true},
		{"uniqueMember differing bits still DN-equal", "uniqueMember", jdoe + "#0101", jdoe + "#1111", true},
		{"uniqueMember escaped hash is data", "uniqueMember", `cn=a\#b,ou=groups,dc=example,dc=test`, `cn=A\#B,ou=groups,dc=example,dc=test`, true},
		{"uniqueMember distinct DN", "uniqueMember", jdoe + "#0101", "uid=jdoe2,ou=people,dc=example,dc=test", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := m.Equal(tc.attr, []byte(tc.value), []byte(tc.assert)); got != tc.want {
				t.Fatalf("Equal(%s, %q, %q) = %v, want %v", tc.attr, tc.value, tc.assert, got, tc.want)
			}
		})
	}
}

// TestRuleMatcherOrdering covers >= and <= preparation, including the
// octet and DN fallback paths.
func TestRuleMatcherOrdering(t *testing.T) {
	t.Parallel()
	m := NewRuleMatcher(matchingSchema())
	sign := func(n int) int {
		switch {
		case n < 0:
			return -1
		case n > 0:
			return 1
		default:
			return 0
		}
	}
	for _, tc := range []struct {
		name   string
		attr   string
		value  string
		assert string
		want   int
	}{
		{"caseIgnore folds order", "uid", "bob", "B", 1},
		{"caseIgnore equal", "uid", "alice", "ALICE", 0},
		{"caseIgnore less", "uid", "alice", "b", -1},
		{"caseIgnore spaces collapse", "cn", "Alice  Adams", "alice adams", 0},
		{"octet is byte order", "x-bin", "BLOB", "blob", -1},
		{"DN fallback orders canonical keys", "member", "uid=alice,ou=people,dc=example,dc=test", "uid=BOB,ou=people,dc=example,dc=test", -1},
		{"DN fallback malformed does not panic", "member", "not-a-dn", "uid=a,dc=x", -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sign(m.Compare(tc.attr, []byte(tc.value), []byte(tc.assert))); got != tc.want {
				t.Fatalf("Compare(%s, %q, %q) sign = %d, want %d", tc.attr, tc.value, tc.assert, got, tc.want)
			}
		})
	}
}

// TestRuleMatcherSubstrings covers RFC 4511 substring assertions under the
// resolved rule's preparation.
func TestRuleMatcherSubstrings(t *testing.T) {
	t.Parallel()
	m := NewRuleMatcher(matchingSchema())
	strs := func(in ...string) [][]byte {
		var out [][]byte
		for _, s := range in {
			out = append(out, []byte(s))
		}
		return out
	}
	for _, tc := range []struct {
		name    string
		attr    string
		value   string
		initial string
		final   string
		any     [][]byte
		want    bool
	}{
		{"initial folded", "cn", "Alice Adams", "ALI", "", nil, true},
		{"any folded", "cn", "Alice Adams", "", "", strs("ADAM"), true},
		{"final folded", "cn", "Alice Adams", "", "AMS", nil, true},
		{"ordered any-runs", "cn", "Alice Bob Carol", "", "", strs("alice", "carol"), true},
		{"out-of-order any-runs", "cn", "Alice Bob Carol", "", "", strs("carol", "alice"), false},
		{"initial miss", "cn", "Alice Adams", "bob", "", nil, false},
		{"final miss", "cn", "Alice Adams", "", "bob", nil, false},
		{"spaces collapse in value", "cn", "Alice  Adams", "alice adams", "", nil, true},
		{"spaces collapse in assertion", "cn", "Alice Adams", "alice  ad", "", nil, true},
		{"IA5 mail any", "mail", "alice@example.com", "", "", strs("@EXAMPLE."), true},
		{"octet case sensitive", "x-bin", "blobdata", "", "", strs("BLOB"), false},
		{"octet raw match", "x-bin", "blobdata", "", "", strs("obda"), true},
		{"DN folded substring", "member", "uid=alice,ou=people,dc=example,dc=test", "", "", strs("OU=PEOPLE"), true},
		{"empty any run is neutral", "cn", "Alice", "", "", strs(""), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var initial, final []byte
			if tc.initial != "" {
				initial = []byte(tc.initial)
			}
			if tc.final != "" {
				final = []byte(tc.final)
			}
			if got := m.Substrings(tc.attr, []byte(tc.value), initial, final, tc.any); got != tc.want {
				t.Fatalf("Substrings(%s, %q, init=%q final=%q any=%q) = %v, want %v",
					tc.attr, tc.value, tc.initial, tc.final, tc.any, got, tc.want)
			}
		})
	}
}

// TestRuleMatcherSchemaOverride proves the declared schema rule wins over
// the registry, and that a nil Schema is safe.
func TestRuleMatcherSchemaOverride(t *testing.T) {
	t.Parallel()
	schema := NewFakeSchema(nil, []AttributeTypeDef{
		{Name: "uid", Equality: "caseExactMatch"},
	})
	m := NewRuleMatcher(schema)
	if m.Equal("uid", []byte("Alice"), []byte("alice")) {
		t.Fatal("schema caseExactMatch must override the uid registry entry")
	}
	if !m.Equal("uid", []byte("Alice"), []byte("Alice")) {
		t.Fatal("caseExactMatch equality failed")
	}
	nilMatcher := NewRuleMatcher(nil)
	if !nilMatcher.Equal("cn", []byte("Alice"), []byte("alice")) {
		t.Fatal("nil schema must resolve through the registry")
	}
}

// TestMatchFilterWithMatcher exercises the full filter tree against an
// entry, proving Search-visible behavior flows through the Matcher seam.
func TestMatchFilterWithMatcher(t *testing.T) {
	t.Parallel()
	m := NewRuleMatcher(matchingSchema())
	entry := NewEntry("uid=alice,ou=people,dc=example,dc=test",
		StringAttribute("objectClass", "top", "person"),
		StringAttribute("uid", "alice"),
		StringAttribute("cn", "Alice Adams"),
		StringAttribute("mail", "Alice@Example.COM"),
		StringAttribute("member", "cn=admins,ou=groups,dc=example,dc=test"),
	)
	for _, tc := range []struct {
		name string
		f    Filter
		want bool
	}{
		{"equality case fold", &FilterEquality{Attr: "uid", Value: []byte("ALICE")}, true},
		{"equality miss", &FilterEquality{Attr: "uid", Value: []byte("bob")}, false},
		{"mail IA5 fold", &FilterEquality{Attr: "mail", Value: []byte("alice@example.com")}, true},
		{"member DN case/space variant", &FilterEquality{Attr: "member", Value: []byte("CN=Admins, OU=Groups,DC=example,dc=test")}, true},
		{"member DN suffix trap", &FilterEquality{Attr: "member", Value: []byte("ou=groups,dc=example,dc=test")}, false},
		{"member DN malformed assertion", &FilterEquality{Attr: "member", Value: []byte("not-a-dn")}, false},
		{"approx folds to equality", &FilterApproxMatch{Attr: "cn", Value: []byte("alice adams")}, true},
		{"greater-or-equal", &FilterGreaterOrEqual{Attr: "uid", Value: []byte("A")}, true},
		{"less-or-equal", &FilterLessOrEqual{Attr: "uid", Value: []byte("alice")}, true},
		{"less-or-equal miss", &FilterLessOrEqual{Attr: "uid", Value: []byte("a")}, false},
		{"substring folded", &FilterSubstrings{Attr: "cn", Any: [][]byte{[]byte("ADAM")}}, true},
		{"present", &FilterPresent{Attr: "uid"}, true},
		{"present miss", &FilterPresent{Attr: "sn"}, false},
		{"and", &FilterAnd{Children: []Filter{
			&FilterEquality{Attr: "objectClass", Value: []byte("PERSON")},
			&FilterEquality{Attr: "uid", Value: []byte("alice")},
		}}, true},
		{"not", &FilterNot{Child: &FilterEquality{Attr: "uid", Value: []byte("bob")}}, true},
		{"nil filter node is non-matching", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchFilterM(entry, tc.f, m); got != tc.want {
				t.Fatalf("matchFilterM(%T) = %v, want %v", tc.f, got, tc.want)
			}
		})
	}
	// The Schema-typed entry point used by Search dispatch.
	if !matchFilter(entry, &FilterEquality{Attr: "uid", Value: []byte("aLiCe")}, matchingSchema()) {
		t.Fatal("matchFilter must resolve through the matching rules")
	}
}

// TestRuleMatcherMalformedValues proves no panics on hostile values: NULs,
// dangling escapes, empty inputs, and binary garbage all evaluate as
// non-matching rather than crashing (fuzz-adjacent; T-149).
func TestRuleMatcherMalformedValues(t *testing.T) {
	t.Parallel()
	m := NewRuleMatcher(matchingSchema())
	nasty := [][]byte{
		{},
		{0},
		[]byte("uid=a\x00,dc=x"),
		[]byte("cn=\\"),
		{0xff, 0xfe, '\\'},
		[]byte(strings.Repeat("a", 4096)),
	}
	for _, v := range nasty {
		for _, attr := range []string{"member", "uniqueMember", "uid", "mail", "x-bin"} {
			_ = m.Equal(attr, v, v)
			_ = m.Equal(attr, v, []byte("uid=a,dc=x"))
			_ = m.Compare(attr, v, v)
			_ = m.Substrings(attr, v, v, v, [][]byte{v})
		}
	}
}

// TestSearchUsesMatchingRules is the over-the-wire proof that T-127's stub
// equality is replaced: Search evaluates DN-structured and case-ignore
// equality through the Matcher.
func TestSearchUsesMatchingRules(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, searchOptions(t, nil), nil)
	cl := dialTestClient(t, addr)
	count := func(f Filter) int {
		t.Helper()
		entries, done := search(t, cl, &SearchRequest{
			BaseDN: "dc=example,dc=test", Scope: ScopeWholeSubtree, Filter: f,
		})
		if done.Result.Code != ResultSuccess {
			t.Fatalf("search: %v", done.Result)
		}
		return len(entries)
	}
	// Structural DN equality: case and space variants of the member DN
	// match; a bare string-suffix assertion does not.
	if n := count(&FilterEquality{Attr: "member", Value: []byte("UID=ALICE, OU=People,DC=example,dc=test")}); n != 1 {
		t.Fatalf("member DN equality = %d, want 1", n)
	}
	if n := count(&FilterEquality{Attr: "member", Value: []byte("ou=people,dc=example,dc=test")}); n != 0 {
		t.Fatalf("member suffix assertion = %d, want 0", n)
	}
	// Case-ignore equality with insignificant-space handling.
	if n := count(&FilterEquality{Attr: "cn", Value: []byte("alice  adams")}); n != 1 {
		t.Fatalf("cn space-collapsed equality = %d, want 1", n)
	}
}

// TestSearchMatchingRegistryFallback proves Search still resolves Contract
// attribute rules when the Schema registry does not declare the attribute
// (pre-T-132 configurations).
func TestSearchMatchingRegistryFallback(t *testing.T) {
	t.Parallel()
	opts := searchOptions(t, func(o *Options) { o.Schema = NewFakeSchema(nil, nil) })
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	entries, done := search(t, cl, &SearchRequest{
		BaseDN: "dc=example,dc=test", Scope: ScopeWholeSubtree,
		Filter: &FilterEquality{Attr: "uid", Value: []byte("ALICE")},
	})
	if done.Result.Code != ResultSuccess || len(entries) != 1 {
		t.Fatalf("registry-fallback search: %v, %d entries", done.Result, len(entries))
	}
	entries, done = search(t, cl, &SearchRequest{
		BaseDN: "dc=example,dc=test", Scope: ScopeWholeSubtree,
		Filter: &FilterEquality{Attr: "member", Value: []byte("uid=Alice, OU=PEOPLE,dc=example,dc=test")},
	})
	if done.Result.Code != ResultSuccess || len(entries) != 1 {
		t.Fatalf("registry-fallback DN search: %v, %d entries", done.Result, len(entries))
	}
}
