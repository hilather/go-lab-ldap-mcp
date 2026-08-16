package parity

import (
	"strconv"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

// caseCtx carries one engine under test through a Contract case.
type caseCtx struct {
	t  *testing.T
	fx *fixture
	e  engine
}

// contractCase is one Contract-tier behavior: the SAME LDAP operation
// sequence executed against both engines, compared outcome-for-outcome.
// Any mismatch that is not a ledger-logged Delta fails the build.
type contractCase struct {
	id   string // contract row(s), e.g. "C3"
	name string
	run  func(c *caseCtx) []opOutcome
}

// contractCases is the fixed, ordered case list. Order matters: cases
// mutate dedicated fixture entries and later cases observe earlier state,
// so both engines always see the identical sequence (contract section 5
// rule 2).
var contractCases = []contractCase{
	{"C2/C3", "transport-bind-matrix", caseTransportBindMatrix},
	{"C3", "unknown-vs-wrong-password", caseBindIndistinguishable},
	{"C3", "account-disable-lock", caseAccountDisable},
	{"C10/D1/D6", "root-dse", caseRootDSE},
	{"C10", "subschema-publication", caseSubschema},
	{"C6", "search-scopes", caseSearchScopes},
	{"C6", "filter-equality-matching", caseFilters},
	{"C6", "client-size-limit", caseClientSizeLimit},
	{"C6/C9", "paged-results", casePagedResults},
	{"C9", "unknown-critical-control", caseUnknownControls},
	// C9's assertion-control row is not dual-engine Contract: the pinned
	// 389 build does not implement RFC 4528 (CAND-25/CAND-26 evidence;
	// contract D7 anticipated this). Native's honor-and-advertise
	// behavior is locked via the native ledger columns of CAND-19/26.
	{"C5/C7", "memberof-derivation", caseMemberOf},
	{"C7", "group-rename", caseGroupRename},
	{"C7", "referential-integrity", caseReferentialIntegrity},
	{"C5", "add-error-codes", caseAddErrors},
	{"C1", "modify-compare-semantics", caseModifyCompare},
	{"C1", "modifydn-semantics", caseModifyDN},
	{"C8", "runtime-aci-matrix", caseRuntimeACIMatrix},
	{"C4", "password-policy-effects", casePasswordPolicy},
	{"C4", "bind-lockout", caseLockout},
	{"C5", "tree-shape-objectclasses", caseTreeShape},
	{"C1", "whoami-contract", caseWhoAmI},
}

// caseTransportBindMatrix covers C2 transports and the C3 bind gates:
// LDAPS, cleartext rejection, StartTLS upgrade, anonymous/unauthenticated
// rejection, wrong-password and unknown-user codes, and fail-closed trust.
func caseTransportBindMatrix(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	dmPass := e.dmSecret()
	return []opOutcome{
		// LDAPS binds.
		dialCode(t, e, dialSpec{ldaps: true, bindDN: dmDN, bindPass: dmPass}),
		dialCode(t, e, userSpec(userDN("alice"), userPasswords["alice"])),
		// Cleartext simple bind is refused before credentials matter (13).
		dialCode(t, e, dialSpec{bindDN: dmDN, bindPass: dmPass}),
		dialCode(t, e, dialSpec{bindDN: userDN("alice"), bindPass: userPasswords["alice"]}),
		// StartTLS upgrades make the same binds legal.
		dialCode(t, e, dialSpec{startTLS: true, bindDN: dmDN, bindPass: dmPass}),
		dialCode(t, e, dialSpec{startTLS: true, bindDN: userDN("alice"), bindPass: userPasswords["alice"]}),
		// Wrong password and unknown user: both 49 (C3).
		dialCode(t, e, userSpec(userDN("alice"), "parity-alice-WRONG-00")),
		dialCode(t, e, userSpec(userDN("nosuchuser"), "parity-nope-secret-1")),
		// Malformed-DN, anonymous, and unauthenticated binds are CAND-21 /
		// CAND-1 raw-wire probes (go-ldap refuses some of them client-side,
		// and the exact codes are adjudicated deltas).
		// Trust fails closed: wrong CA, wrong server name.
		dialCode(t, e, dialSpec{ldaps: true, badCA: true, bindDN: dmDN, bindPass: dmPass}),
		dialCode(t, e, dialSpec{ldaps: true, badName: true, bindDN: dmDN, bindPass: dmPass}),
		dialCode(t, e, dialSpec{startTLS: true, badCA: true, bindDN: dmDN, bindPass: dmPass}),
	}
}

// caseBindIndistinguishable pins C3: unknown user and wrong password
// return the same direct-LDAP code.
func caseBindIndistinguishable(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	wrong := dialCode(t, e, userSpec(userDN("carol"), "parity-carol-WRONG-0"))
	unknown := dialCode(t, e, userSpec(userDN("ghost"), "parity-ghost-secret1"))
	ok := dialCode(t, e, userSpec(userDN("carol"), userPasswords["carol"]))
	return []opOutcome{wrong, unknown, ok}
}

// caseAccountDisable covers C3: nsAccountLock=true blocks the bind with
// unwillingToPerform; removing the lock restores it. Uses the dedicated
// pwprobe account.
func caseAccountDisable(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	dm := e.dm(t)
	defer dm.Close()

	dn := userDN("pwprobe")
	out := []opOutcome{dialCode(t, e, userSpec(dn, userPasswords["pwprobe"]))}

	set := ldap.NewModifyRequest(dn, nil)
	set.Replace("nsAccountLock", []string{"true"})
	out = append(out, codeOutcome(dm.Modify(set)))
	out = append(out, dialCode(t, e, userSpec(dn, userPasswords["pwprobe"])))

	clear := ldap.NewModifyRequest(dn, nil)
	clear.Delete("nsAccountLock", []string{"true"})
	out = append(out, codeOutcome(dm.Modify(clear)))
	out = append(out, dialCode(t, e, userSpec(dn, userPasswords["pwprobe"])))
	// Post-state: the attribute is gone again.
	out = append(out, readOutcome(dm, dn, "nsAccountLock"))
	return out
}

// caseRootDSE covers C10 publication on an authenticated connection
// (pre-bind DSE access is CAND-22: 389's anonymous-access-off policy
// refuses it before ACI evaluation, native evaluates the anyone-ACI
// path). Vendor values are presence-only (D1: identity differs
// intentionally; the inequality assertion lives in the dual-engine
// runner); 389-specific extras are not requested (D6).
func caseRootDSE(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	conn := mustDial(t, e, userSpec(userDN("alice"), userPasswords["alice"]))
	defer conn.Close()

	// supportedLDAPVersion: Contract is "v3 is served" (C10); the exact
	// advertised set is CAND-25 (389 still lists the historical "2").
	ver := readOutcome(conn, "", "supportedLDAPVersion")
	verOut := opOutcome{Code: ver.Code, Value: "v3-missing"}
	for _, en := range ver.Entries {
		for _, v := range en.Attrs["supportedldapversion"] {
			if v == "3" {
				verOut.Value = "v3-advertised"
			}
		}
	}

	// supportedControl: Contract is "paged results is advertised" (C9's
	// paged case exercises it); the full published set is engine-specific
	// honest advertisement (D6), and the assertion control advertisement
	// is CAND-25's second step (389 evaluates no assertion requests and
	// does not advertise the OID).
	ctrl := readOutcome(conn, "", "supportedControl")
	ctrlOut := opOutcome{Code: ctrl.Code, Value: "paged-missing"}
	for _, en := range ctrl.Entries {
		for _, v := range en.Attrs["supportedcontrol"] {
			if v == oidPagedResults {
				ctrlOut.Value = "paged-advertised"
			}
		}
	}

	// supportedExtension: Contract is "StartTLS and WhoAmI are
	// advertised" (C10; both are exercised elsewhere). The full set is
	// D6 honest advertisement (389 lists its own extras); the raw read
	// is CAND-25's third step.
	ext := readOutcome(conn, "", "supportedExtension")
	have := map[string]bool{}
	for _, en := range ext.Entries {
		for _, v := range en.Attrs["supportedextension"] {
			have[v] = true
		}
	}
	extOut := opOutcome{Code: ext.Code, Value: "starttls=" + strconv.FormatBool(have[oidStartTLS]) + ",whoami=" + strconv.FormatBool(have[oidWhoAmI])}

	return []opOutcome{
		readOutcome(conn, "", "namingContexts"),
		verOut,
		ctrlOut,
		extOut,
		readOutcome(conn, "", "vendorName", "vendorVersion"),
	}
}

// caseSubschema covers C10: the subschema subentry advertised in the
// root DSE is searchable and carries the object classes and attributes
// of C5. The advertised DN is discovered per engine (the alias DN
// "cn=subschema" is a 389-ism; native publishes the canonical
// "cn=schema"). Presence booleans keep the outcome engine-neutral (389
// publishes its full schema).
func caseSubschema(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	conn := e.dm(t)
	defer conn.Close()

	dse, err := conn.Search(ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"subschemaSubentry"}, nil))
	if err != nil || len(dse.Entries) == 0 {
		t.Fatalf("parity: %s subschemaSubentry discovery: %v", e.name(), err)
	}
	subDN := ""
	for _, a := range dse.Entries[0].Attributes {
		if strings.EqualFold(a.Name, "subschemaSubentry") && len(a.Values) > 0 {
			subDN = a.Values[0]
		}
	}
	if subDN == "" {
		t.Fatalf("parity: %s root DSE carries no subschemaSubentry", e.name())
	}

	res := readOutcome(conn, subDN, "objectClasses", "attributeTypes")
	oc := map[string]bool{}
	at := map[string]bool{}
	for _, entry := range res.Entries {
		for _, v := range entry.Attrs["objectclasses"] {
			oc[v] = true
		}
		for _, v := range entry.Attrs["attributetypes"] {
			at[v] = true
		}
	}
	have := func(set map[string]bool, name string) bool {
		for v := range set {
			if schemaValueNamed(v, name) {
				return true
			}
		}
		return false
	}
	presence := opOutcome{Code: res.Code}
	for _, name := range []string{"person", "inetOrgPerson", "groupOfNames", "device", "domain", "organizationalUnit"} {
		if have(oc, name) {
			presence.Entries = append(presence.Entries, canonEntry{DN: "oc:" + name})
		}
	}
	for _, name := range []string{"uid", "cn", "sn", "givenName", "mail", "displayName", "description", "userPassword", "member", "memberOf", "nsAccountLock", "aci", "entryUUID", "createTimestamp", "modifyTimestamp", "modifiersName"} {
		if have(at, name) {
			presence.Entries = append(presence.Entries, canonEntry{DN: "at:" + name})
		}
	}
	// pwdAccountLockedTime publication is CAND-28's question: native
	// publishes it, the pinned 389 schema does not.
	return []opOutcome{presence}
}

// schemaValueNamed reports whether an RFC 4512 schema description names
// the given object class / attribute type in its NAME clause, either as
// NAME 'x' or inside a NAME ( 'x' 'y' ) list. Case-insensitive: 389
// lowercases some names.
func schemaValueNamed(desc, name string) bool {
	upper := strings.ToUpper(desc)
	idx := strings.Index(upper, "NAME")
	if idx < 0 {
		return false
	}
	rest := desc[idx+4:]
	want := strings.ToLower(name)
	for _, tok := range strings.FieldsFunc(rest, func(r rune) bool {
		return r == ' ' || r == '(' || r == ')' || r == '\'' || r == '\t'
	}) {
		if strings.ToLower(tok) == want {
			return true
		}
	}
	return false
}

// caseSearchScopes covers C6 base/one/sub scopes plus noSuchObject.
func caseSearchScopes(c *caseCtx) []opOutcome {
	e := c.e
	dm := e.dm(c.t)
	defer dm.Close()
	return []opOutcome{
		searchOutcome(dm, peopleDN, ldap.ScopeBaseObject, 0, "(objectClass=*)", []string{"ou"}),
		searchOutcome(dm, peopleDN, ldap.ScopeSingleLevel, 0, "(uid=*)", []string{"uid"}),
		searchOutcome(dm, suffixDN, ldap.ScopeWholeSubtree, 0, "(objectClass=groupOfNames)", []string{"cn"}),
		searchOutcome(dm, "ou=nothere,"+suffixDN, ldap.ScopeWholeSubtree, 0, "(objectClass=*)", []string{"cn"}),
		searchOutcome(dm, "dc=other,dc=test", ldap.ScopeWholeSubtree, 0, "(objectClass=*)", []string{"cn"}),
	}
}

// caseFilters covers C6 matching: caseIgnoreMatch folding, substrings,
// presence, boolean combinators, and structural DN equality.
func caseFilters(c *caseCtx) []opOutcome {
	e := c.e
	dm := e.dm(c.t)
	defer dm.Close()
	sub := func(filter string, attrs ...string) opOutcome {
		return searchOutcome(dm, suffixDN, ldap.ScopeWholeSubtree, 0, filter, attrs)
	}
	return []opOutcome{
		sub("(uid=ALICE)", "uid"),        // case-folded equality
		sub("(cn=alice anderson)", "cn"), // caseIgnoreMatch, full value
		sub("(cn=*Ander*)", "cn"),        // substring
		sub("(mail=*)", "uid"),           // presence
		sub("(&(objectClass=inetOrgPerson)(sn=Evans))", "uid"),
		sub("(|(uid=alice)(uid=bob))", "uid"),
		sub("(&(uid=*)(!(mail=*)))", "uid"),                          // users without mail
		sub("(uid=zz-nomatch)", "uid"),                               // empty result
		sub("(member=UID=ALICE,OU=PEOPLE,DC=EXAMPLE,DC=TEST)", "cn"), // DN equality is structural
		sub("(memberOf=cn=staff,ou=groups,dc=example,dc=test)", "uid"),
	}
}

// caseClientSizeLimit covers C6: a smaller client-requested size limit
// wins; the partial result carries sizeLimitExceeded. Only the code and
// the entry count are compared (result order is not Contract).
func caseClientSizeLimit(c *caseCtx) []opOutcome {
	e := c.e
	dm := e.dm(c.t)
	defer dm.Close()
	return []opOutcome{
		countOutcome(dm, peopleDN, ldap.ScopeSingleLevel, 3, "(uid=*)", []string{"uid"}),
		countOutcome(dm, peopleDN, ldap.ScopeSingleLevel, 0, "(uid=*)", []string{"uid"}),
	}
}

// casePagedResults walks ou=people in pages of 4 via the Simple Paged
// Results control (C6/C9), then again with page size 64 (single page).
// Page composition is engine-order-dependent, so pages are aggregated:
// the per-page code sequence and the union of all entries are compared.
func casePagedResults(c *caseCtx) []opOutcome {
	e := c.e
	dm := e.dm(c.t)
	defer dm.Close()
	return []opOutcome{
		pagedWalk(dm, peopleDN, "(objectClass=inetOrgPerson)", 4, 8),
		pagedWalk(dm, peopleDN, "(objectClass=inetOrgPerson)", 64, 8),
	}
}

// caseUnknownControls covers C9: a critical control the engine does not
// honor fails the operation with unavailableCriticalExtension; a
// non-critical unknown control is ignored.
func caseUnknownControls(c *caseCtx) []opOutcome {
	e := c.e
	dm := e.dm(c.t)
	defer dm.Close()
	crit := ldap.NewControlString("1.3.6.1.4.1.99999.1", true, "")
	nonCrit := ldap.NewControlString("1.3.6.1.4.1.99999.1", false, "")
	return []opOutcome{
		searchOutcome(dm, peopleDN, ldap.ScopeBaseObject, 0, "(objectClass=*)", []string{"ou"}, crit),
		searchOutcome(dm, peopleDN, ldap.ScopeBaseObject, 0, "(objectClass=*)", []string{"ou"}, nonCrit),
		// Paged results on a non-search op, critical.
		codeOutcome(dm.Modify(withControls(
			replaceAttr(userDN("bob"), "description", "cc-bob"),
			crit))),
	}
}

// caseMemberOf covers C5/C7: membership writes derive memberOf in the
// same commit. The auxiliary object class the derivation adds
// (nsmemberof on 389, none on native) is CAND-24, so the readbacks here
// request memberOf only.
func caseMemberOf(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	dm := e.dm(t)
	defer dm.Close()

	add := ldap.NewAddRequest(userDN("zoe"), nil)
	add.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"})
	add.Attribute("uid", []string{"zoe"})
	add.Attribute("cn", []string{"Zoe Zimmer"})
	add.Attribute("sn", []string{"Zimmer"})
	add.Attribute("userPassword", []string{"parity-zoe-secret-001"})

	var out []opOutcome
	out = append(out, codeOutcome(dm.Add(add)))
	out = append(out, readOutcome(dm, userDN("zoe"), "memberOf"))

	grp := ldap.NewAddRequest(groupDN("zapgroup"), nil)
	grp.Attribute("objectClass", []string{"top", "groupOfNames"})
	grp.Attribute("cn", []string{"zapgroup"})
	grp.Attribute("member", []string{userDN("zoe")})
	out = append(out, codeOutcome(dm.Add(grp)))
	out = append(out, readOutcome(dm, userDN("zoe"), "memberOf"))

	// Extend membership: alice joins zapgroup.
	mod := ldap.NewModifyRequest(groupDN("zapgroup"), nil)
	mod.Replace("member", []string{userDN("zoe"), userDN("alice")})
	out = append(out, codeOutcome(dm.Modify(mod)))
	out = append(out, readOutcome(dm, userDN("alice"), "memberOf"))

	// Remove zoe from the group: memberOf retracts in the same commit.
	mod2 := ldap.NewModifyRequest(groupDN("zapgroup"), nil)
	mod2.Replace("member", []string{userDN("alice")})
	out = append(out, codeOutcome(dm.Modify(mod2)))
	out = append(out, readOutcome(dm, userDN("zoe"), "memberOf"))
	out = append(out, readOutcome(dm, groupDN("zapgroup"), "member"))
	return out
}

// caseGroupRename covers C7: renaming a group rewrites memberOf values on
// the members in the same commit.
func caseGroupRename(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	dm := e.dm(t)
	defer dm.Close()

	var out []opOutcome
	out = append(out, readOutcome(dm, userDN("carol"), "memberOf"))
	out = append(out, codeOutcome(dm.ModifyDN(ldap.NewModifyDNRequest(groupDN("ops"), "cn=ops-renamed", true, ""))))
	out = append(out, readOutcome(dm, userDN("carol"), "memberOf"))
	out = append(out, readOutcome(dm, groupDN("ops-renamed"), "member"))
	out = append(out, readOutcome(dm, groupDN("ops"), "cn")) // gone: 32
	return out
}

// caseReferentialIntegrity covers C7: deleting a user repairs member
// references (update-delay 0, suffix-scoped).
func caseReferentialIntegrity(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	dm := e.dm(t)
	defer dm.Close()

	var out []opOutcome
	out = append(out, readOutcome(dm, groupDN("staff"), "member"))
	out = append(out, codeOutcome(dm.Del(ldap.NewDelRequest(userDN("bob"), nil))))
	out = append(out, readOutcome(dm, groupDN("staff"), "member"))
	out = append(out, readOutcome(dm, userDN("bob"), "uid")) // gone: 32
	return out
}

// caseAddErrors pins the C1/C5 add-path result codes.
func caseAddErrors(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	dm := e.dm(t)
	defer dm.Close()

	dup := ldap.NewAddRequest(userDN("alice"), nil)
	dup.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"})
	dup.Attribute("uid", []string{"alice"})
	dup.Attribute("cn", []string{"Alice Anderson"})
	dup.Attribute("sn", []string{"Anderson"})

	noMUST := ldap.NewAddRequest(userDN("broken"), nil)
	noMUST.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"})
	noMUST.Attribute("uid", []string{"broken"})
	noMUST.Attribute("cn", []string{"No Surname"})
	// sn deliberately missing (person MUST sn).

	orphan := ldap.NewAddRequest("uid=orphan,ou=missing,"+suffixDN, nil)
	orphan.Attribute("objectClass", []string{"top", "person"})
	orphan.Attribute("cn", []string{"Orphan"})
	orphan.Attribute("sn", []string{"Orphan"})

	outside := ldap.NewAddRequest("dc=elsewhere,dc=test", nil)
	outside.Attribute("objectClass", []string{"top", "domain"})
	outside.Attribute("dc", []string{"elsewhere"})

	badDN := ldap.NewAddRequest("not a dn at all", nil)
	badDN.Attribute("objectClass", []string{"top", "device"})
	badDN.Attribute("cn", []string{"x"})

	return []opOutcome{
		codeOutcome(dm.Add(dup)),     // entryAlreadyExists (68)
		codeOutcome(dm.Add(noMUST)),  // objectClassViolation (65)
		codeOutcome(dm.Add(orphan)),  // noSuchObject (32)
		codeOutcome(dm.Add(outside)), // noSuchObject (32)
		codeOutcome(dm.Add(badDN)),   // invalidDNSyntax (34)
	}
}

// caseModifyCompare pins the C1 modify/compare semantics on a dedicated
// entry, including RFC 4511 add-existing-value and delete-missing-value
// behavior where the engines are specified to agree.
func caseModifyCompare(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	dm := e.dm(t)
	defer dm.Close()

	dn := userDN("erin")
	var out []opOutcome

	addDesc := ldap.NewModifyRequest(dn, nil)
	addDesc.Add("description", []string{"one", "two"})
	out = append(out, codeOutcome(dm.Modify(addDesc)))

	dupVal := ldap.NewModifyRequest(dn, nil)
	dupVal.Add("description", []string{"one"})
	out = append(out, codeOutcome(dm.Modify(dupVal))) // attributeOrValueExists (20)

	delVal := ldap.NewModifyRequest(dn, nil)
	delVal.Delete("description", []string{"two"})
	out = append(out, codeOutcome(dm.Modify(delVal)))

	repl := ldap.NewModifyRequest(dn, nil)
	repl.Replace("description", []string{"final"})
	out = append(out, codeOutcome(dm.Modify(repl)))

	// Replace of an attribute the entry does not carry creates it (RFC
	// 4511); delete of an absent *value* is noSuchAttribute (16) per RFC.
	replMissing := ldap.NewModifyRequest(dn, nil)
	replMissing.Replace("roomNumber", []string{"7A"})
	out = append(out, codeOutcome(dm.Modify(replMissing)))

	out = append(out, readOutcome(dm, dn, "description", "roomNumber"))

	cmp := func(attr, val string) opOutcome {
		ok, err := dm.Compare(dn, attr, val)
		if err != nil {
			return codeOutcome(err)
		}
		if ok {
			return opOutcome{Code: ldap.LDAPResultCompareTrue}
		}
		return opOutcome{Code: ldap.LDAPResultCompareFalse}
	}
	out = append(out,
		cmp("description", "FINAL"), // caseIgnoreMatch folds
		cmp("description", "other"), // false
		// Compare against an absent attribute is CAND-23 (compareFalse vs
		// noSuchAttribute is exactly what that probe adjudicates).
	)
	ok, err := dm.Compare("uid=ghost,"+peopleDN, "cn", "x")
	out = append(out, compareGone(ok, err))
	return out
}

// compareGone normalizes compare-against-missing-entry: both engines must
// answer noSuchObject(32); anything else records the raw code.
func compareGone(ok bool, err error) opOutcome {
	out := codeOutcome(err)
	if out.Code == 0 {
		out.Code = ldap.LDAPResultCompareFalse
		if ok {
			out.Code = ldap.LDAPResultCompareTrue
		}
	}
	return out
}

// caseModifyDN pins C1 rename/move semantics on dedicated entries.
func caseModifyDN(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	dm := e.dm(t)
	defer dm.Close()

	add := ldap.NewAddRequest("cn=rename-src,"+suffixDN, nil)
	add.Attribute("objectClass", []string{"top", "device"})
	add.Attribute("cn", []string{"rename-src"})
	add.Attribute("description", []string{"rename me"})

	var out []opOutcome
	out = append(out, codeOutcome(dm.Add(add)))
	out = append(out, codeOutcome(dm.ModifyDN(ldap.NewModifyDNRequest("cn=rename-src,"+suffixDN, "cn=rename-dst", true, ""))))
	out = append(out, readOutcome(dm, "cn=rename-dst,"+suffixDN, "cn", "description"))
	out = append(out, readOutcome(dm, "cn=rename-src,"+suffixDN, "cn")) // 32

	// Move under a different in-suffix parent.
	out = append(out, codeOutcome(dm.ModifyDN(ldap.NewModifyDNRequest("cn=rename-dst,"+suffixDN, "cn=rename-dst", true, peopleDN))))
	out = append(out, readOutcome(dm, "cn=rename-dst,"+peopleDN, "cn"))
	out = append(out, readOutcome(dm, "cn=rename-dst,"+suffixDN, "cn")) // 32

	// Rename onto an existing DN → entryAlreadyExists (68).
	out = append(out, codeOutcome(dm.ModifyDN(ldap.NewModifyDNRequest("cn=rename-dst,"+peopleDN, "uid=alice", true, ""))))
	// Rename a missing entry → noSuchObject (32).
	out = append(out, codeOutcome(dm.ModifyDN(ldap.NewModifyDNRequest("cn=ghost,"+suffixDN, "cn=ghost2", true, ""))))
	// Cleanup so later cases see a stable tree.
	del := ldap.NewDelRequest("cn=rename-dst,"+peopleDN, nil)
	out = append(out, codeOutcome(dm.Del(del)))
	return out
}

// caseRuntimeACIMatrix re-runs the T-036 runtime ACI probes as direct
// LDAP (C8): the runtime account reads the suffix and CRUDs people and
// groups, but cannot touch aci attributes or write outside the two
// containers.
func caseRuntimeACIMatrix(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	rt := mustDial(t, e, userSpec(runtimeDN, runtimePassword))

	var out []opOutcome
	out = append(out, readOutcome(rt, suffixDN, "aci", "dc"))
	out = append(out, searchOutcome(rt, peopleDN, ldap.ScopeSingleLevel, 0, "(uid=alice)", []string{"uid", "userPassword"}))
	out = append(out, searchOutcome(rt, suffixDN, ldap.ScopeBaseObject, 0, "(objectClass=*)", []string{"userPassword"}))

	// Runtime may add/delete people and groups entries.
	addU := ldap.NewAddRequest(userDN("rtprobe"), nil)
	addU.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"})
	addU.Attribute("uid", []string{"rtprobe"})
	addU.Attribute("cn", []string{"RT Probe"})
	addU.Attribute("sn", []string{"Probe"})
	out = append(out, codeOutcome(rt.Add(addU)))

	modU := ldap.NewModifyRequest(userDN("rtprobe"), nil)
	modU.Replace("description", []string{"runtime wrote this"})
	out = append(out, codeOutcome(rt.Modify(modU)))

	addG := ldap.NewAddRequest(groupDN("rtgroup"), nil)
	addG.Attribute("objectClass", []string{"top", "groupOfNames"})
	addG.Attribute("cn", []string{"rtgroup"})
	addG.Attribute("member", []string{userDN("rtprobe")})
	out = append(out, codeOutcome(rt.Add(addG)))

	// ... but never aci attributes (people-write / groups-write deny aci).
	modACI := ldap.NewModifyRequest(userDN("rtprobe"), nil)
	modACI.Add("aci", []string{`(targetattr="*")(version 3.0; acl "evil"; allow (all) userdn="ldap:///all";)`})
	out = append(out, codeOutcome(rt.Modify(modACI)))
	modACIG := ldap.NewModifyRequest(groupDN("rtgroup"), nil)
	modACIG.Add("aci", []string{`(targetattr="*")(version 3.0; acl "evil"; allow (all) userdn="ldap:///all";)`})
	out = append(out, codeOutcome(rt.Modify(modACIG)))

	// ... and never write outside people/groups (suffix is read-only).
	addOU := ldap.NewAddRequest("ou=runtime-escape,"+suffixDN, nil)
	addOU.Attribute("objectClass", []string{"top", "organizationalUnit"})
	addOU.Attribute("ou", []string{"runtime-escape"})
	out = append(out, codeOutcome(rt.Add(addOU)))

	// ... and never see the engine admin tree (D2 shape, C8 guarantee):
	// 389 may answer with insufficientAccessRights, native with
	// noSuchObject (no cn=config DIT) — both are "unreachable".
	admin := readOutcome(rt, "cn=config", "cn")
	if admin.Code != 0 || len(admin.Entries) == 0 {
		admin = opOutcome{Code: -100, Note: "admin-tree-unreachable"}
	}
	out = append(out, admin)

	// Cleanup as DM so both engines stay in lockstep.
	dm := e.dm(t)
	defer dm.Close()
	out = append(out, codeOutcome(dm.Del(ldap.NewDelRequest(groupDN("rtgroup"), nil))))
	out = append(out, codeOutcome(dm.Del(ldap.NewDelRequest(userDN("rtprobe"), nil))))
	return out
}

// casePasswordPolicy covers the C4 write-path effects whose *codes* are
// Contract-neutral: too-short and in-history passwords are rejected on
// both engines (the exact code is CAND-9's delta question), a good
// password commits and binds.
func casePasswordPolicy(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	dm := e.dm(t)
	defer dm.Close()

	dn := userDN("pwprobe")
	var out []opOutcome

	self := mustDial(t, e, userSpec(dn, userPasswords["pwprobe"]))

	// Too short → rejected (rejection is Contract; the exact code is
	// CAND-9's delta question).
	short := ldap.NewModifyRequest(dn, nil)
	short.Replace("userPassword", []string{"short1"})
	out = append(out, policyRejected(self.Modify(short)))
	out = append(out, dialCode(t, e, userSpec(dn, userPasswords["pwprobe"]))) // old pw still valid

	// Legitimate change commits and the new password binds.
	good := ldap.NewModifyRequest(dn, nil)
	good.Replace("userPassword", []string{"parity-pwprobe-NEW-pass1"})
	out = append(out, codeOutcome(self.Modify(good)))
	out = append(out, dialCode(t, e, userSpec(dn, "parity-pwprobe-NEW-pass1")))
	out = append(out, dialCode(t, e, userSpec(dn, userPasswords["pwprobe"]))) // old pw dead

	// Reuse of the just-replaced password → rejected (history; CAND-9 code).
	self2 := mustDial(t, e, userSpec(dn, "parity-pwprobe-NEW-pass1"))
	reuse := ldap.NewModifyRequest(dn, nil)
	reuse.Replace("userPassword", []string{userPasswords["pwprobe"]})
	out = append(out, policyRejected(self2.Modify(reuse)))

	// Restore to a fresh password as DM. (A DM reset to an in-history
	// value is CAND-27: 389's rootdn bypasses policy, native applies
	// history to DM writes.)
	restore := ldap.NewModifyRequest(dn, nil)
	restore.Replace("userPassword", []string{"parity-pwprobe-RESTORED1"})
	out = append(out, codeOutcome(dm.Modify(restore)))
	out = append(out, dialCode(t, e, userSpec(dn, "parity-pwprobe-RESTORED1")))
	return out
}

// policyRejected normalizes a password-policy rejection: both engines
// refuse (that is Contract); the refusal code is CAND-9's delta.
func policyRejected(err error) opOutcome {
	out := codeOutcome(err)
	if out.Code != 0 {
		return opOutcome{Code: -100, Note: "policy-rejected"}
	}
	return out
}

// caseLockout covers C3/C4: after maxFailures bad binds the account
// locks. The locked-bind code and the lock marker attributes are
// CAND-10's adjudication material, so the code is normalized to
// "rejected" here and the entry readback only proves the entry itself
// is still readable.
func caseLockout(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	dm := e.dm(t)
	defer dm.Close()

	dn := userDN("lockprobe")
	var out []opOutcome
	out = append(out, dialCode(t, e, userSpec(dn, userPasswords["lockprobe"]))) // sanity: binds
	for i := 0; i < 3; i++ {
		out = append(out, dialCode(t, e, userSpec(dn, "parity-lock-WRONG-000")))
	}
	locked := dialCode(t, e, userSpec(dn, userPasswords["lockprobe"]))
	if locked.Code != 0 {
		locked = opOutcome{Code: -100, Note: "rejected"} // code is CAND-10
	}
	out = append(out, locked)
	out = append(out, readOutcome(dm, dn, "uid"))
	return out
}

// caseTreeShape covers C5: object classes of the core fixture entries.
// Only entries that never gain a group membership are read: membered
// entries carry an engine-specific auxiliary class (CAND-24: 389's
// memberOf plugin auto-adds nsmemberof, native adds none).
func caseTreeShape(c *caseCtx) []opOutcome {
	e := c.e
	dm := e.dm(c.t)
	defer dm.Close()
	dns := []string{
		suffixDN, peopleDN, groupsDN,
		userDN("labldap-runtime"), userDN("pwprobe"), userDN("histprobe"), userDN("norah"),
		groupDN("staff"), groupDN("ops-renamed"), groupDN("probegrp"),
		markerDN,
	}
	var out []opOutcome
	for _, dn := range dns {
		out = append(out, readOutcome(dm, dn, "objectClass"))
	}
	return out
}

// caseWhoAmI covers the C1 WhoAmI extended op for a bound user. Exact
// authzid rendering (case, anonymous form) is CAND-20; here both engines
// must answer success with the bound user's dn: authzid.
func caseWhoAmI(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	conn := mustDial(t, e, userSpec(userDN("erin"), userPasswords["erin"]))
	out := whoami(conn)
	out.Value = canonAuthzID(out.Value)
	return []opOutcome{out}
}

// canonAuthzID folds the DN inside a dn: authzid for comparison.
func canonAuthzID(v string) string {
	if len(v) > 3 && v[:3] == "dn:" {
		return "dn:" + canonDN(v[3:])
	}
	return v
}

// --- small helpers shared by cases and probes ---

// withControls attaches controls to a ModifyRequest.
func withControls(req *ldap.ModifyRequest, controls ...ldap.Control) *ldap.ModifyRequest {
	req.Controls = append(req.Controls, controls...)
	return req
}

// replaceAttr builds a single-attribute replace ModifyRequest.
func replaceAttr(dn, attr string, vals ...string) *ldap.ModifyRequest {
	req := ldap.NewModifyRequest(dn, nil)
	req.Replace(attr, vals)
	return req
}
