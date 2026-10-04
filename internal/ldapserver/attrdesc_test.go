package ldapserver

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// Oracle evidence for every row below: test/parity/testdata/
// filter-attr-oracle-probes.txt (pinned 389 image, probes 1-7).

// parseTestFilter parses the RFC 4515 subset these tests use: & | ! and
// =, =*, substrings with *, >=, <= (no escapes). Test-only; the server
// receives BER filters.
func parseTestFilter(t *testing.T, s string) Filter {
	t.Helper()
	f, rest := parseTestFilterAt(t, s)
	if rest != "" {
		t.Fatalf("filter %q: trailing %q", s, rest)
	}
	return f
}

func parseTestFilterAt(t *testing.T, s string) (Filter, string) {
	t.Helper()
	if !strings.HasPrefix(s, "(") {
		t.Fatalf("filter %q: want (", s)
	}
	s = s[1:]
	switch s[0] {
	case '&', '|':
		op := s[0]
		s = s[1:]
		var kids []Filter
		for strings.HasPrefix(s, "(") {
			var k Filter
			k, s = parseTestFilterAt(t, s)
			kids = append(kids, k)
		}
		if op == '&' {
			return &FilterAnd{Children: kids}, strings.TrimPrefix(s, ")")
		}
		return &FilterOr{Children: kids}, strings.TrimPrefix(s, ")")
	case '!':
		k, rest := parseTestFilterAt(t, s[1:])
		return &FilterNot{Child: k}, strings.TrimPrefix(rest, ")")
	}
	end := strings.IndexByte(s, ')')
	item, rest := s[:end], s[end+1:]
	switch {
	case strings.Contains(item, ">="):
		a, v, _ := strings.Cut(item, ">=")
		return &FilterGreaterOrEqual{Attr: a, Value: []byte(v)}, rest
	case strings.Contains(item, "<="):
		a, v, _ := strings.Cut(item, "<=")
		return &FilterLessOrEqual{Attr: a, Value: []byte(v)}, rest
	}
	a, v, _ := strings.Cut(item, "=")
	if v == "*" {
		return &FilterPresent{Attr: a}, rest
	}
	if strings.Contains(v, "*") {
		parts := strings.Split(v, "*")
		sub := &FilterSubstrings{Attr: a}
		if parts[0] != "" {
			sub.Initial = []byte(parts[0])
		}
		if last := parts[len(parts)-1]; last != "" {
			sub.Final = []byte(last)
		}
		for _, p := range parts[1 : len(parts)-1] {
			sub.Any = append(sub.Any, []byte(p))
		}
		return sub, rest
	}
	return &FilterEquality{Attr: a, Value: []byte(v)}, rest
}

func standardSchemaT(t *testing.T) Schema {
	t.Helper()
	s, err := StandardSchema()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// descEntries mirrors the probe 1/2/7 entries (alice, bob, carol).
func descEntries() map[string]*Entry {
	oc := StringAttribute("objectClass", "top", "person", "organizationalPerson", "inetOrgPerson")
	return map[string]*Entry{
		"alice": NewEntry("uid=alice,ou=people,dc=example,dc=test", oc,
			StringAttribute("uid", "alice"), StringAttribute("cn", "Alice"), StringAttribute("sn", "A")),
		"bob": NewEntry("uid=bob,ou=people,dc=example,dc=test", oc,
			StringAttribute("uid", "bob"), StringAttribute("cn", "Bob"), StringAttribute("sn", "B"),
			StringAttribute("uid;x-test", "bobtag"), StringAttribute("description;lang-en", "hello"),
			StringAttribute("userPassword;x-b", "probe-secret-b")),
		"carol": NewEntry("uid=carol,ou=people,dc=example,dc=test", oc,
			StringAttribute("uid", "carol"), StringAttribute("cn", "Carol"), StringAttribute("sn", "C"),
			StringAttribute("description;lang-en;x-foo", "multi"), StringAttribute("cn;lang-en", "Karla")),
	}
}

func matchingNames(t *testing.T, entries map[string]*Entry, eval func(*Entry) bool) string {
	t.Helper()
	var out []string
	for name, e := range entries {
		if eval(e) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return strings.Join(out, ",")
}

func TestFilterAttributeDescriptions(t *testing.T) {
	t.Parallel()
	s := standardSchemaT(t)
	entries := descEntries()
	const all = "alice,bob,carol"
	for _, tc := range []struct{ filter, want string }{
		// probe 1
		{"(UID=alice)", "alice"},
		{"(uid;x-test=alice)", ""},
		{"(uid;lang-en=alice)", ""},
		{"(0.9.2342.19200300.100.1.1=alice)", "alice"},
		{"(!(uid;x-test=alice))", all},
		{"(!(0.9.2342.19200300.100.1.1=alice))", "bob,carol"},
		{"(uid;x-test=*)", "bob"},
		{"(uid=bobtag)", "bob"},
		{"(uid;x-test=bobtag)", "bob"},
		{"(description=hello)", "bob"},
		{"(description;lang-en=hello)", "bob"},
		{"(description;lang-en=HELLO)", "bob"},
		{"(2.5.4.13=hello)", "bob"},
		{"(2.5.4.13;lang-en=hello)", ""},
		{"(0.9.2342.19200300.100.1.1;x-test=bobtag)", ""},
		{"(description;lang-fr=hello)", ""},
		{"(cn;lang-en=Alice)", ""},
		{"(uid;x-test=al*)", ""},
		{"(!(description;lang-en=hello))", "alice,carol"},
		{"(uid;x-test>=a)", "bob"},
		// probe 2
		{"(userid=alice)", "alice"},
		{"(!(userid=alice))", "bob,carol"},
		{"(commonName=Alice)", "alice"},
		{"(2.5.4.0=inetOrgPerson)", all},
		{"(!(2.5.4.0=inetOrgPerson))", ""},
		{"(2.5.4.3=Alice)", "alice"},
		{"(description=multi)", "carol"},
		{"(description;lang-en=multi)", "carol"},
		{"(description;x-foo=multi)", "carol"},
		{"(description;x-foo;lang-en=multi)", "carol"},
		{"(description;LANG-EN=multi)", "carol"},
		{"(description;lang-en=MULTI)", "carol"},
		{"(description;lang-en;x-bar=multi)", ""},
		{"(description;lang-=multi)", ""},
		{"(userPassword=*)", "bob"},
		{"(userPassword;x-b=*)", "bob"},
		{"(!(userPassword=*))", "alice,carol"},
		{"(uid;X-TEST=bobtag)", "bob"},
		{"(description=hel*)", "bob"},
		{"(description;lang-en>=a)", "bob,carol"},
		// probe 3 (DM rows)
		{"(!(2.5.4.13;lang-en=hello))", all},
		{"(2.5.4.13;lang-en=*)", ""},
		{"(!(0.9.2342.19200300.100.1.1;x-test=bobtag))", all},
		{"(2.5.4.13;lang-en=hel*)", ""},
		{"(!(description;lang-=multi))", all},
		// probes 4/6: a second descriptor with options is unresolved (False)
		{"(userid;x-test=bobtag)", ""},
		{"(!(userid;x-test=bobtag))", all},
		{"(userid;x-test=*)", ""},
		// probe 7
		{"(commonName;lang-en=Karla)", ""},
		{"(!(commonName;lang-en=Karla))", all},
		{"(cn;lang-en=Karla)", "carol"},
		{"(cn=Karla)", "carol"},
		{"(commonName=Karla)", "carol"},
		{"(2.5.4.3;lang-en=Karla)", ""},
		{"(surname;x-a=A)", ""},
		{"(!(surname;x-a=A))", all},
	} {
		f := parseTestFilter(t, tc.filter)
		if got := matchingNames(t, entries, func(e *Entry) bool { return matchFilter(e, f, s) }); got != tc.want {
			t.Errorf("%s: matched [%s], oracle [%s]", tc.filter, got, tc.want)
		}
	}
}

func TestFilterAttributeDescriptionsWithoutSchema(t *testing.T) {
	t.Parallel()
	entries := descEntries()
	for _, tc := range []struct{ filter, want string }{
		{"(userid=alice)", "alice"},                    // config alias table
		{"(2.5.4.0=inetOrgPerson)", "alice,bob,carol"}, // protected OID
		{"(uid=bobtag)", "bob"},                        // subtype values
		{"(userid;x-test=bobtag)", ""},
	} {
		f := parseTestFilter(t, tc.filter)
		got := matchingNames(t, entries, func(e *Entry) bool { return matchFilterM(e, f, NewRuleMatcher(nil)) })
		if got != tc.want {
			t.Errorf("nil schema %s: matched [%s], want [%s]", tc.filter, got, tc.want)
		}
		if got2 := matchingNames(t, entries, func(e *Entry) bool { return matchFilter(e, f, nil) }); got2 != got {
			t.Errorf("matchFilter(nil) %s = [%s], matchFilterM = [%s]", tc.filter, got2, got)
		}
	}
}

func TestParseAttrDesc(t *testing.T) {
	t.Parallel()
	s := standardSchemaT(t)
	for _, tc := range []struct {
		in, typ, name string
		opts          []string
		resolved      bool
	}{
		{"uid", "uid", "uid", nil, true},
		// Native-only: surrounding spaces are trimmed (RFC 4512 descriptions
		// cannot contain them; no oracle row). Permission and matching use
		// the same resolved name, so this cannot widen access.
		{" UID ", "uid", "uid", nil, true},
		{"userid", "uid", "uid", nil, true},
		{"0.9.2342.19200300.100.1.1", "uid", "uid", nil, true},
		{"uid;X-Test", "uid", "uid", []string{"x-test"}, true},
		{"userid;x-test", "userid", "userid", []string{"x-test"}, false},
		{"0.9.2342.19200300.100.1.1;x-test", "0.9.2342.19200300.100.1.1", "0.9.2342.19200300.100.1.1", []string{"x-test"}, false},
		{"description;lang-en;x-foo", "description", "description", []string{"lang-en", "x-foo"}, true},
		{"unknownAttr;x-a", "unknownattr", "unknownattr", []string{"x-a"}, true},
		{"2.5.4.0", "objectclass", "objectClass", nil, true},
		{"userPassword;x-b", "userpassword", "userPassword", []string{"x-b"}, true},
	} {
		d := parseAttrDesc(s, tc.in)
		if d.typ != tc.typ || d.name != tc.name || d.resolved != tc.resolved || !slices.Equal(d.opts, tc.opts) {
			t.Errorf("parseAttrDesc(%q) = %+v, want typ=%s name=%s opts=%v resolved=%v", tc.in, d, tc.typ, tc.name, tc.opts, tc.resolved)
		}
	}
}

// The bbolt index keys postings with AttrTypeKey(StandardSchema); for the
// indexed types and their spellings it must agree with the type a filter
// description resolves to, or an indexed search could miss entries.
func TestIndexKeyAgreesWithFilterResolution(t *testing.T) {
	t.Parallel()
	s := standardSchemaT(t)
	for _, name := range []string{"uid", "userid", "0.9.2342.19200300.100.1.1", "cn", "commonName", "2.5.4.3", "objectClass", "2.5.4.0", "member", "uniqueMember"} {
		if got, want := AttrTypeKey(s, name), parseAttrDesc(s, name).typ; got != want {
			t.Errorf("%s: index key %q, filter type %q", name, got, want)
		}
		if got := AttrTypeKey(s, name+";x-a"); got != parseAttrDesc(s, name).typ {
			t.Errorf("%s;x-a: index key %q must post to the type", name, got)
		}
	}
}

// probe6ACIs are the probe-6 rawACI texts verbatim (also used by the parity
// fixture): single-attribute targetattr with a target clause, the shape both
// engines accept.
func probe6ACIs() []string {
	const b = "ou=probe-fattr,dc=example,dc=test"
	var out []string
	for _, a := range [][2]string{
		{"fa_allow_uid", `(targetattr="uid")`},
		{"fa_allow_userid", `(targetattr="userid")`},
		{"fa_deny_uid", `(targetattr!="uid")`},
		{"fa_deny_userid", `(targetattr!="userid")`},
	} {
		out = append(out, `(target="ldap:///`+b+`")`+a[1]+`(version 3.0; acl "labldap:`+a[0]+`"; allow (read,search,compare) userdn="ldap:///uid=`+a[0]+`,ou=people,dc=example,dc=test";)`)
	}
	return out
}

// TestFilterLeafSearchIdentityMatchesOracle runs the probe-6 ACI rows
// through matchSearchFilter. Rows that fail on main: fa_deny_uid
// (userid=fa_bob) and its NOT (main checked the literal userid, so the leaf
// was allowed and False); fa_allow_uid userid/OID rows (main: False);
// fa_deny_uid (!(OID;x-test=bobtag)) (main resolved OID;x-test to uid:
// Undefined, oracle False so its NOT returns all three); fa_allow_userid
// (!(userid;x-test=bobtag)) (CAND-31: main returned all three).
func TestFilterLeafSearchIdentityMatchesOracle(t *testing.T) {
	t.Parallel()
	const base = "ou=probe-fattr,dc=example,dc=test"
	oc := StringAttribute("objectClass", "top", "person", "organizationalPerson", "inetOrgPerson")
	entries := map[string]*Entry{
		"fa_alice": NewEntry("uid=fa_alice,"+base, oc, StringAttribute("uid", "fa_alice"), StringAttribute("cn", "fa_alice"), StringAttribute("sn", "S")),
		"fa_bob": NewEntry("uid=fa_bob,"+base, oc, StringAttribute("uid", "fa_bob"), StringAttribute("cn", "fa_bob"), StringAttribute("sn", "S"),
			StringAttribute("uid;x-test", "bobtag"), StringAttribute("description;lang-en", "hello")),
		"fa_carol": NewEntry("uid=fa_carol,"+base, oc, StringAttribute("uid", "fa_carol"), StringAttribute("cn", "fa_carol"), StringAttribute("sn", "S"),
			StringAttribute("description;lang-en;x-foo", "multi")),
	}
	opts := testOptions()
	opts.Schema = standardSchemaT(t)
	opts.ACI = nil
	opts.ACITexts = probe6ACIs()
	srv, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	const all, notBob, none = "fa_alice,fa_bob,fa_carol", "fa_alice,fa_carol", ""
	const oid = "0.9.2342.19200300.100.1.1"
	resolvedUID := map[string]string{
		"(uid=fa_bob)": "fa_bob", "(!(uid=fa_bob))": notBob, "(userid=fa_bob)": "fa_bob", "(!(userid=fa_bob))": notBob,
		"(" + oid + "=fa_bob)": "fa_bob", "(!(" + oid + "=fa_bob))": notBob, "(uid;x-test=bobtag)": "fa_bob", "(!(uid;x-test=bobtag))": notBob,
	}
	other := map[string]string{"(cn=fa_bob)": "fa_bob", "(!(cn=fa_bob))": notBob, "(description=hello)": "fa_bob", "(!(description=hello))": notBob}
	unresolved := []string{"(userid;x-test=bobtag)", "(!(userid;x-test=bobtag))", "(" + oid + ";x-test=bobtag)", "(!(" + oid + ";x-test=bobtag))"}
	want := map[string]map[string]string{}
	for _, subj := range []string{"fa_allow_uid", "fa_allow_userid", "fa_deny_uid", "fa_deny_userid"} {
		rows := map[string]string{}
		for f, v := range resolvedUID {
			switch subj {
			case "fa_allow_uid", "fa_deny_userid":
				rows[f] = v
			default:
				rows[f] = none
			}
		}
		for f, v := range other {
			switch subj {
			case "fa_deny_uid", "fa_deny_userid":
				rows[f] = v
			default:
				rows[f] = none
			}
		}
		for _, f := range unresolved {
			rows[f] = none
		}
		want[subj] = rows
	}
	want["fa_deny_uid"]["(!(userid;x-test=bobtag))"] = all
	want["fa_deny_uid"]["(!("+oid+";x-test=bobtag))"] = all
	want["fa_deny_userid"]["(!("+oid+";x-test=bobtag))"] = all
	// CAND-31 (resolved as Contract): fa_allow_userid can read no attribute
	// the entries hold, so 389 returns none even for the True NOT row; the
	// entry-level visibility check (searchEntryVisible) matches that.

	ctx := context.Background()
	for subj, rows := range want {
		s := Subject{DN: mustDNA(t, "uid="+subj+",ou=people,dc=example,dc=test")}
		for filter, w := range rows {
			f := parseTestFilter(t, filter)
			var got string
			if err := opts.Store.View(ctx, func(tx ReadTx) error {
				got = matchingNames(t, entries, func(e *Entry) bool {
					dn := mustDNA(t, e.DN)
					return srv.searchEntryVisible(ctx, tx, s, dn, e) && srv.matchSearchFilter(ctx, tx, s, dn, e, f) == filterTrue
				})
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if got != w {
				t.Errorf("%s %s: matched [%s], oracle [%s]", subj, filter, got, w)
			}
		}
	}
}

// Write and read checks keep attributeIdentity (the filter-leaf resolution
// is search-only): a deny on userPassword still covers subtype and
// OID-with-options spellings.
func TestWriteIdentityStillCoversPasswordVariants(t *testing.T) {
	t.Parallel()
	opts := testOptions()
	opts.Schema = standardSchemaT(t)
	opts.ACI = nil
	opts.ACITexts = []string{
		`(target="ldap:///ou=people,dc=example,dc=test")(targetattr="*")(version 3.0; acl "w-all"; allow (write) userdn="ldap:///all";)`,
		`(target="ldap:///ou=people,dc=example,dc=test")(targetattr="userPassword")(version 3.0; acl "w-pw"; deny (write) userdn="ldap:///all";)`,
	}
	srv, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	subj := Subject{DN: mustDNA(t, "uid=alice,ou=people,dc=example,dc=test")}
	target := mustDNA(t, "uid=bob,ou=people,dc=example,dc=test")
	ctx := context.Background()
	if err := opts.Store.View(ctx, func(tx ReadTx) error {
		for attr, want := range map[string]bool{
			"description": true, "userPassword": false, "userPassword;x-b": false,
			"2.5.4.35": false, "2.5.4.35;x-b": false,
		} {
			if got := srv.allowed(ctx, tx, subj, target, attr, PermWrite); got != want {
				t.Errorf("write %s allowed=%v, want %v", attr, got, want)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
