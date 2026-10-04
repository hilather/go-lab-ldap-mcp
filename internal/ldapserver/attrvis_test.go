package ldapserver

import (
	"context"
	"testing"
)

// visProbeACIs are the oracle probe 8 and 10 subjects (pinned image;
// transcripts in test/parity/testdata/filter-attr-oracle-probes.txt):
// targetattr spelling and permission set per ACI.
var visProbeACIs = map[string][][2]string{
	"p_userid":          {{`(targetattr="userid")`, "read,search,compare"}},
	"p_userid_sn":       {{`(targetattr="userid")`, "read,search,compare"}, {`(targetattr="sn")`, "read,search,compare"}},
	"p_userid_snsearch": {{`(targetattr="userid")`, "read,search,compare"}, {`(targetattr="sn")`, "search"}},
	"p_userid_snread":   {{`(targetattr="userid")`, "read,search,compare"}, {`(targetattr="sn")`, "read"}},
	"p_star_search":     {{`(targetattr="*")`, "search"}},
	"p_star_read":       {{`(targetattr="*")`, "read"}},
	"p_list":            {{`(targetattr="uid || sn")`, "read,search,compare"}},
	"p_list_nospace":    {{`(targetattr="uid||sn")`, "read,search,compare"}},
	"p_list_case":       {{`(targetattr="UID || Sn")`, "read,search,compare"}},
	"p_oid_sn":          {{`(targetattr="2.5.4.4 || uid")`, "read,search,compare"}},
	"p_oid_only":        {{`(targetattr="0.9.2342.19200300.100.1.1")`, "read,search,compare"}},
	"p_deny_oid":        {{`(targetattr!="0.9.2342.19200300.100.1.1")`, "read,search,compare"}},
	"p_deny_list":       {{`(targetattr!="uid || description")`, "read,search,compare"}},
	"q_oc":              {{`(targetattr="userid")`, "read,search,compare"}, {`(targetattr="objectClass")`, "read"}},
	"q_entryuuid":       {{`(targetattr="userid")`, "read,search,compare"}, {`(targetattr="entryUUID")`, "read"}},
	// Probe 12 (options inside targetattr) is replayed by
	// TestTargetAttrOptionsMatchProbe12 (resolved CAND-34).
}

// visProbeRows are the probe 8/10 one-level search rows, generated from the
// transcripts (expected DN sets are 389's).
var visProbeRows = map[string][]struct{ filter, want string }{
	"p_userid": {
		{`(!(userid;x-test=bobtag))`, ""},
		{`(!(0.9.2342.19200300.100.1.1;x-test=bobtag))`, ""},
		{`(sn=S)`, ""},
		{`(!(sn=X))`, ""},
		{`(uid=fa_bob)`, ""},
		{`(!(uid=fa_bob))`, ""},
		{`(cn=fa_bob)`, ""},
		{`(!(cn=fa_bob))`, ""},
		{`(2.5.4.4=S)`, ""},
		{`(description=hello)`, ""},
		{`(!(description=hello))`, ""},
	},
	"p_userid_sn": {
		{`(!(userid;x-test=bobtag))`, "fa_alice,fa_bob,fa_carol"},
		{`(!(0.9.2342.19200300.100.1.1;x-test=bobtag))`, ""},
		{`(sn=S)`, "fa_alice,fa_bob,fa_carol"},
		{`(!(sn=X))`, "fa_alice,fa_bob,fa_carol"},
		{`(uid=fa_bob)`, ""},
		{`(!(uid=fa_bob))`, ""},
		{`(cn=fa_bob)`, ""},
		{`(!(cn=fa_bob))`, ""},
		{`(2.5.4.4=S)`, "fa_alice,fa_bob,fa_carol"},
		{`(description=hello)`, ""},
		{`(!(description=hello))`, ""},
	},
	"p_userid_snsearch": {
		{`(!(userid;x-test=bobtag))`, ""},
		{`(!(0.9.2342.19200300.100.1.1;x-test=bobtag))`, ""},
		{`(sn=S)`, ""},
		{`(!(sn=X))`, ""},
		{`(uid=fa_bob)`, ""},
		{`(!(uid=fa_bob))`, ""},
		{`(cn=fa_bob)`, ""},
		{`(!(cn=fa_bob))`, ""},
		{`(2.5.4.4=S)`, ""},
		{`(description=hello)`, ""},
		{`(!(description=hello))`, ""},
	},
	"p_userid_snread": {
		{`(!(userid;x-test=bobtag))`, "fa_alice,fa_bob,fa_carol"},
		{`(!(0.9.2342.19200300.100.1.1;x-test=bobtag))`, ""},
		{`(sn=S)`, ""},
		{`(!(sn=X))`, ""},
		{`(uid=fa_bob)`, ""},
		{`(!(uid=fa_bob))`, ""},
		{`(cn=fa_bob)`, ""},
		{`(!(cn=fa_bob))`, ""},
		{`(2.5.4.4=S)`, ""},
		{`(description=hello)`, ""},
		{`(!(description=hello))`, ""},
	},
	"p_star_search": {
		{`(!(userid;x-test=bobtag))`, ""},
		{`(!(0.9.2342.19200300.100.1.1;x-test=bobtag))`, ""},
		{`(sn=S)`, ""},
		{`(!(sn=X))`, ""},
		{`(uid=fa_bob)`, ""},
		{`(!(uid=fa_bob))`, ""},
		{`(cn=fa_bob)`, ""},
		{`(!(cn=fa_bob))`, ""},
		{`(2.5.4.4=S)`, ""},
		{`(description=hello)`, ""},
		{`(!(description=hello))`, ""},
	},
	"p_star_read": {
		{`(!(userid;x-test=bobtag))`, ""},
		{`(!(0.9.2342.19200300.100.1.1;x-test=bobtag))`, ""},
		{`(sn=S)`, ""},
		{`(!(sn=X))`, ""},
		{`(uid=fa_bob)`, ""},
		{`(!(uid=fa_bob))`, ""},
		{`(cn=fa_bob)`, ""},
		{`(!(cn=fa_bob))`, ""},
		{`(2.5.4.4=S)`, ""},
		{`(description=hello)`, ""},
		{`(!(description=hello))`, ""},
	},
	"p_list": {
		{`(!(userid;x-test=bobtag))`, ""},
		{`(!(0.9.2342.19200300.100.1.1;x-test=bobtag))`, ""},
		{`(sn=S)`, "fa_alice,fa_bob,fa_carol"},
		{`(!(sn=X))`, "fa_alice,fa_bob,fa_carol"},
		{`(uid=fa_bob)`, "fa_bob"},
		{`(!(uid=fa_bob))`, "fa_alice,fa_carol"},
		{`(cn=fa_bob)`, ""},
		{`(!(cn=fa_bob))`, ""},
		{`(2.5.4.4=S)`, "fa_alice,fa_bob,fa_carol"},
		{`(description=hello)`, ""},
		{`(!(description=hello))`, ""},
	},
	"p_list_nospace": {
		{`(!(userid;x-test=bobtag))`, ""},
		{`(!(0.9.2342.19200300.100.1.1;x-test=bobtag))`, ""},
		{`(sn=S)`, "fa_alice,fa_bob,fa_carol"},
		{`(!(sn=X))`, "fa_alice,fa_bob,fa_carol"},
		{`(uid=fa_bob)`, "fa_bob"},
		{`(!(uid=fa_bob))`, "fa_alice,fa_carol"},
		{`(cn=fa_bob)`, ""},
		{`(!(cn=fa_bob))`, ""},
		{`(2.5.4.4=S)`, "fa_alice,fa_bob,fa_carol"},
		{`(description=hello)`, ""},
		{`(!(description=hello))`, ""},
	},
	"p_list_case": {
		{`(!(userid;x-test=bobtag))`, ""},
		{`(!(0.9.2342.19200300.100.1.1;x-test=bobtag))`, ""},
		{`(sn=S)`, "fa_alice,fa_bob,fa_carol"},
		{`(!(sn=X))`, "fa_alice,fa_bob,fa_carol"},
		{`(uid=fa_bob)`, "fa_bob"},
		{`(!(uid=fa_bob))`, "fa_alice,fa_carol"},
		{`(cn=fa_bob)`, ""},
		{`(!(cn=fa_bob))`, ""},
		{`(2.5.4.4=S)`, "fa_alice,fa_bob,fa_carol"},
		{`(description=hello)`, ""},
		{`(!(description=hello))`, ""},
	},
	"p_oid_sn": {
		{`(!(userid;x-test=bobtag))`, ""},
		{`(!(0.9.2342.19200300.100.1.1;x-test=bobtag))`, ""},
		{`(sn=S)`, ""},
		{`(!(sn=X))`, ""},
		{`(uid=fa_bob)`, "fa_bob"},
		{`(!(uid=fa_bob))`, "fa_alice,fa_carol"},
		{`(cn=fa_bob)`, ""},
		{`(!(cn=fa_bob))`, ""},
		{`(2.5.4.4=S)`, ""},
		{`(description=hello)`, ""},
		{`(!(description=hello))`, ""},
	},
	"p_oid_only": {
		{`(!(userid;x-test=bobtag))`, ""},
		{`(!(0.9.2342.19200300.100.1.1;x-test=bobtag))`, ""},
		{`(sn=S)`, ""},
		{`(!(sn=X))`, ""},
		{`(uid=fa_bob)`, ""},
		{`(!(uid=fa_bob))`, ""},
		{`(cn=fa_bob)`, ""},
		{`(!(cn=fa_bob))`, ""},
		{`(2.5.4.4=S)`, ""},
		{`(description=hello)`, ""},
		{`(!(description=hello))`, ""},
	},
	"p_deny_oid": {
		{`(!(userid;x-test=bobtag))`, "fa_alice,fa_bob,fa_carol"},
		{`(!(0.9.2342.19200300.100.1.1;x-test=bobtag))`, ""},
		{`(sn=S)`, "fa_alice,fa_bob,fa_carol"},
		{`(!(sn=X))`, "fa_alice,fa_bob,fa_carol"},
		{`(uid=fa_bob)`, "fa_bob"},
		{`(!(uid=fa_bob))`, "fa_alice,fa_carol"},
		{`(cn=fa_bob)`, "fa_bob"},
		{`(!(cn=fa_bob))`, "fa_alice,fa_carol"},
		{`(2.5.4.4=S)`, "fa_alice,fa_bob,fa_carol"},
		{`(description=hello)`, "fa_bob"},
		{`(!(description=hello))`, "fa_alice,fa_carol"},
	},
	"p_deny_list": {
		{`(!(userid;x-test=bobtag))`, "fa_alice,fa_bob,fa_carol"},
		{`(!(0.9.2342.19200300.100.1.1;x-test=bobtag))`, "fa_alice,fa_bob,fa_carol"},
		{`(sn=S)`, "fa_alice,fa_bob,fa_carol"},
		{`(!(sn=X))`, "fa_alice,fa_bob,fa_carol"},
		{`(uid=fa_bob)`, ""},
		{`(!(uid=fa_bob))`, ""},
		{`(cn=fa_bob)`, "fa_bob"},
		{`(!(cn=fa_bob))`, "fa_alice,fa_carol"},
		{`(2.5.4.4=S)`, "fa_alice,fa_bob,fa_carol"},
		{`(description=hello)`, ""},
		{`(!(description=hello))`, ""},
	},
	"q_oc": {
		{`(!(userid;x-test=bobtag))`, "fa_alice,fa_bob,fa_carol"},
		{`(sn=S)`, ""},
		{`(uid=fa_bob)`, ""},
	},
	"q_entryuuid": {
		{`(!(userid;x-test=bobtag))`, ""},
		{`(sn=S)`, ""},
		{`(uid=fa_bob)`, ""},
	},
}

func TestSearchEntryVisibilityMatchesOracle(t *testing.T) {
	t.Parallel()
	const base = "ou=probe-fattr,dc=example,dc=test"
	oc := StringAttribute("objectClass", "top", "person", "organizationalPerson", "inetOrgPerson")
	ops := func(n string) []Attribute {
		return []Attribute{StringAttribute("entryUUID", "uuid-"+n), StringAttribute("createTimestamp", "20261004000000Z")}
	}
	entries := map[string]*Entry{
		"fa_alice": NewEntry("uid=fa_alice,"+base, append([]Attribute{oc, StringAttribute("uid", "fa_alice"), StringAttribute("cn", "fa_alice"), StringAttribute("sn", "S")}, ops("a")...)...),
		"fa_bob": NewEntry("uid=fa_bob,"+base, append([]Attribute{oc, StringAttribute("uid", "fa_bob"), StringAttribute("cn", "fa_bob"), StringAttribute("sn", "S"),
			StringAttribute("uid;x-test", "bobtag"), StringAttribute("description;lang-en", "hello")}, ops("b")...)...),
		"fa_carol": NewEntry("uid=fa_carol,"+base, append([]Attribute{oc, StringAttribute("uid", "fa_carol"), StringAttribute("cn", "fa_carol"), StringAttribute("sn", "S"),
			StringAttribute("description;lang-en;x-foo", "multi")}, ops("c")...)...),
	}
	var texts []string
	for subj, acis := range visProbeACIs {
		for i, a := range acis {
			texts = append(texts, `(target="ldap:///`+base+`")`+a[0]+`(version 3.0; acl "labldap:`+subj+`-`+string(rune('0'+i))+`"; allow (`+a[1]+`) userdn="ldap:///uid=`+subj+`,ou=people,dc=example,dc=test";)`)
		}
	}
	opts := testOptions()
	opts.Schema = standardSchemaT(t)
	opts.ACI = nil
	opts.ACITexts = texts
	srv, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if len(visProbeRows) != len(visProbeACIs) {
		t.Fatalf("rows for %d subjects, ACIs for %d", len(visProbeRows), len(visProbeACIs))
	}
	for subj, rows := range visProbeRows {
		s := Subject{DN: mustDNA(t, "uid="+subj+",ou=people,dc=example,dc=test")}
		for _, r := range rows {
			f := parseTestFilter(t, r.filter)
			var got string
			if err := opts.Store.View(ctx, func(tx ReadTx) error {
				got = matchingNames(t, entries, func(e *Entry) bool {
					dn := mustDNA(t, e.DN)
					return srv.searchResultVisible(ctx, tx, s, dn, e, f, filterHasAbsoluteSet(f))
				})
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if got != r.want {
				t.Errorf("%s %s: matched [%s], oracle [%s]", subj, r.filter, got, r.want)
			}
		}
	}
}

// TestSearchVisibilityOperationalOverridesMatchOracle pins probe 13: with
// userid (matches nothing) plus read on one more attribute, 389 returns the
// entry for memberOf (a user attribute there) but not for nsAccountLock
// (directoryOperation). passwordHistory is operational on 389 too
// (directoryOperation), and so is aci (probe 15). pwdChangedTime is a
// native-only stamp: 389's schema has no such type, so no ACI can name it
// (CAND-33, probe 17); v_p still stores it and must not count.
func TestSearchVisibilityOperationalOverridesMatchOracle(t *testing.T) {
	t.Parallel()
	const base = "ou=probe-vis13,dc=example,dc=test"
	oc := StringAttribute("objectClass", "top", "person", "organizationalPerson", "inetOrgPerson")
	entries := map[string]*Entry{
		"v_m": NewEntry("uid=v_m,"+base, oc, StringAttribute("uid", "v_m"), StringAttribute("cn", "v_m"), StringAttribute("sn", "S"), StringAttribute("memberOf", "cn=g,dc=example,dc=test")),
		"v_l": NewEntry("uid=v_l,"+base, oc, StringAttribute("uid", "v_l"), StringAttribute("cn", "v_l"), StringAttribute("sn", "S"), StringAttribute("nsAccountLock", "true"), StringAttribute("2.16.840.1.113730.3.1.610", "true")),
		"v_p": NewEntry("uid=v_p,"+base, oc, StringAttribute("uid", "v_p"), StringAttribute("cn", "v_p"), StringAttribute("sn", "S"),
			StringAttribute("pwdChangedTime", "20261004000000Z"), StringAttribute("passwordHistory", "x"),
			StringAttribute("aci", `(targetattr="cn")(version 3.0; acl "x"; allow (read) userdn="ldap:///anyone";)`)),
	}
	subjects := map[string]struct{ attr, want string }{
		"q_userid_memberof": {"memberOf", "v_m"},
		"q_userid_acctlock": {"nsAccountLock", ""},
		"q_userid_pwdhist":  {"passwordHistory", ""},
		"q_userid_aci":      {"aci", ""},
		// v_l also stores nsAccountLock under its OID spelling (a direct
		// LDAP write keeps the spelling); it must not count either.
		"q_userid_acctoid": {"nsAccountLock", ""},
	}
	var texts []string
	for subj, c := range subjects {
		for i, a := range [][2]string{{`(targetattr="userid")`, "read,search,compare"}, {`(targetattr="` + c.attr + `")`, "read"}} {
			texts = append(texts, `(target="ldap:///`+base+`")`+a[0]+`(version 3.0; acl "labldap:`+subj+`-`+string(rune('0'+i))+`"; allow (`+a[1]+`) userdn="ldap:///uid=`+subj+`,ou=people,dc=example,dc=test";)`)
		}
	}
	opts := testOptions()
	opts.Schema = standardSchemaT(t)
	opts.ACI = nil
	opts.ACITexts = texts
	srv, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	f := parseTestFilter(t, "(!(userid;x-test=x))")
	for subj, c := range subjects {
		s := Subject{DN: mustDNA(t, "uid="+subj+",ou=people,dc=example,dc=test")}
		var got string
		if err := opts.Store.View(ctx, func(tx ReadTx) error {
			got = matchingNames(t, entries, func(e *Entry) bool {
				dn := mustDNA(t, e.DN)
				return srv.searchResultVisible(ctx, tx, s, dn, e, f, filterHasAbsoluteSet(f))
			})
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("%s: matched [%s], oracle [%s]", subj, got, c.want)
		}
	}
}
