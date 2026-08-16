package parity

import (
	"strings"

	ldap "github.com/go-ldap/ldap/v3"
)

// candProbe is one Delta-candidate adjudication (contract section 7). The
// probe executes the same operation sequence against both engines and
// returns an outcome set per engine; the dual-engine runner records both
// columns into the delta ledger and derives the verdict: "match" when
// native agrees with the oracle (no Delta), "delta" when it does not.
type candProbe struct {
	id    string // "CAND-1" .. "CAND-20"
	topic string
	run   func(c *caseCtx) []opOutcome
}

// candProbes covers every logged candidate plus the Wave-3 adjudication
// probes (CAND-21..24) for contract rows the first dual-engine run proved
// divergent. CAND-7 was resolved in Wave 2 (both handlers exist); it is
// re-asserted here as evidence.
var candProbes = []candProbe{
	{"CAND-1", "anonymous-bind-disabled result code", probeCAND1},
	{"CAND-2", "approxMatch filter semantics", probeCAND2},
	{"CAND-3", "modify delete/replace of missing attribute", probeCAND3},
	{"CAND-4", "out-of-suffix ModifyDN result code", probeCAND4},
	{"CAND-5", "paged-cookie scope binding", probeCAND5},
	{"CAND-6", "rename into own subtree", probeCAND6},
	{"CAND-7", "supportedExtension truthful (resolved)", probeCAND7},
	{"CAND-8", "schema MAY/unknown-attribute enforcement", probeCAND8},
	{"CAND-9", "password-policy-violation write code", probeCAND9},
	{"CAND-10", "lockout bind failure code", probeCAND10},
	{"CAND-11", "re-setting the current password", probeCAND11},
	{"CAND-12", "groupOfNames emptied by RI member removal", probeCAND12},
	{"CAND-13", "ACI evaluation order / deny-wins", probeCAND13},
	{"CAND-14", "userPassword read on a person entry as runtime", probeCAND14},
	{"CAND-15", "self/all/anyone bind-rule semantics", probeCAND15},
	{"CAND-16", "ACI entry-level add/delete targetattr scope", probeCAND16},
	{"CAND-17", "groupdn membership scope (nesting)", probeCAND17},
	{"CAND-18", "paged-cookie tamper result code", probeCAND18},
	{"CAND-19", "assertion control on non-Modify ops", probeCAND19},
	{"CAND-20", "WhoAmI authzid rendering", probeCAND20},
	{"CAND-21", "malformed-DN bind result code (D8)", probeCAND21},
	{"CAND-22", "pre-bind root DSE read under anonymous-off", probeCAND22},
	{"CAND-23", "compare against an absent attribute", probeCAND23},
	{"CAND-24", "memberOf auxiliary object class add/retract", probeCAND24},
	{"CAND-25", "DSE publication: v2 advertisement + assertion OID", probeCAND25},
	{"CAND-26", "critical assertion on Modify (pass and fail)", probeCAND26},
	{"CAND-27", "DM password reset vs history policy", probeCAND27},
	{"CAND-28", "subschema publishes pwdAccountLockedTime", probeCAND28},
}

// CAND-1: anonymous bind with the policy disabled, on the wire (go-ldap
// refuses to send an empty password client-side, so the raw form is the
// only honest observation). Steps: LDAPS anonymous, cleartext anonymous
// (secure-auth policy also applies), LDAPS unauthenticated (DN + empty
// password).
func probeCAND1(c *caseCtx) []opOutcome {
	t := c.t
	return []opOutcome{
		rawBind(t, c, true, 3, "", ""),
		rawBind(t, c, false, 3, "", ""),
		rawBind(t, c, true, 3, userDN("alice"), ""),
	}
}

// CAND-2: (cn~=x) approx matching. Native folds approx to equality until
// T-131 matching rules land; 389 may apply a real approx algorithm. The
// probe records the matched DN sets for a near-miss and a far-miss term.
func probeCAND2(c *caseCtx) []opOutcome {
	e := c.e
	dm := e.dm(c.t)
	defer dm.Close()
	sub := func(filter string) opOutcome {
		return searchOutcome(dm, peopleDN, ldap.ScopeSingleLevel, 0, filter, []string{"uid"})
	}
	return []opOutcome{
		sub("(cn~=Alice Anderson)"), // exact value, trivially equal
		sub("(cn~=Alic Anderson)"),  // near miss: equality folds to no-match
		sub("(sn~=Andersen)"),       // near miss on sn
		sub("(uid~=alice)"),         // exact on uid
	}
}

// CAND-3: RFC 4511 modify edge cases on a dedicated entry.
func probeCAND3(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	dm := e.dm(t)
	defer dm.Close()

	dn := userDN("erin")
	delMissingAttr := ldap.NewModifyRequest(dn, nil)
	delMissingAttr.Delete("telephoneNumber", []string{}) // attr absent entirely
	delMissingValue := ldap.NewModifyRequest(dn, nil)
	delMissingValue.Delete("description", []string{"never-set"})
	replaceMissing := ldap.NewModifyRequest(dn, nil)
	replaceMissing.Replace("telephoneNumber", []string{"+1 555 0100"})

	return []opOutcome{
		codeOutcome(dm.Modify(delMissingAttr)),
		codeOutcome(dm.Modify(delMissingValue)),
		codeOutcome(dm.Modify(replaceMissing)),
		readOutcome(dm, dn, "telephoneNumber"),
		// cleanup: keep the tree identical for the other engine.
		codeOutcome(dm.Modify(func() *ldap.ModifyRequest {
			r := ldap.NewModifyRequest(dn, nil)
			r.Delete("telephoneNumber", []string{"+1 555 0100"})
			return r
		}())),
	}
}

// CAND-4: ModifyDN whose newSuperior leaves the managed suffix.
func probeCAND4(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	dm := e.dm(t)
	defer dm.Close()
	out := []opOutcome{
		codeOutcome(dm.ModifyDN(ldap.NewModifyDNRequest(userDN("zoe"), "uid=zoe", true, "dc=other,dc=test"))),
		readOutcome(dm, userDN("zoe"), "uid"), // unmoved
	}
	return out
}

// CAND-5: cookie scope binding — a cookie minted for query A must not
// paginate query B (different filter). Codes only: the entries a bad
// cookie would return are engine-order-dependent. (Tamper result codes
// are CAND-18.)
func probeCAND5(c *caseCtx) []opOutcome {
	e := c.e
	dm := e.dm(c.t)
	defer dm.Close()
	_, cookie := pagedPage(dm, peopleDN, "(objectClass=inetOrgPerson)", 4, nil)
	second, _ := pagedPage(dm, peopleDN, "(uid=z*)", 4, cookie)
	second.Entries = nil
	// Same query, cookie replayed for the next page: legitimate flow.
	replay, _ := pagedPage(dm, peopleDN, "(objectClass=inetOrgPerson)", 4, cookie)
	replay.Entries = nil
	return []opOutcome{second, replay}
}

// CAND-6: rename an entry into its own subtree. 389 rejects it as
// LDAP-illegal; native's store historically allowed it, detaching the
// subtree from index walks. The probe runs LAST against ou=movedemo and
// records the post-state either way.
func probeCAND6(c *caseCtx) []opOutcome {
	e := c.e
	dm := e.dm(c.t)
	defer dm.Close()
	kidDN := "cn=kid," + moveDemoOU
	code := codeOutcome(dm.ModifyDN(ldap.NewModifyDNRequest(moveDemoOU, "ou=movedemo", true, kidDN)))
	post := readOutcome(dm, moveDemoOU, "ou")
	visible := searchOutcome(dm, suffixDN, ldap.ScopeWholeSubtree, 0, "(ou=movedemo)", []string{"ou"})
	return []opOutcome{code, post, visible}
}

// CAND-7 (resolved in Wave 2): the Root DSE supportedExtension
// advertisement is truthful — both StartTLS and WhoAmI actually work.
func probeCAND7(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	conn := mustDial(t, e, userSpec(userDN("dave"), userPasswords["dave"]))
	w := whoami(conn)
	w.Value = canonAuthzID(w.Value)
	stls := dialCode(t, e, dialSpec{startTLS: true, bindDN: userDN("dave"), bindPass: userPasswords["dave"]})
	return []opOutcome{w, stls}
}

// CAND-8: schema enforcement depth. (a) marker attributes
// destinationIndicator/owner on a device entry (389 accepts per the CAND
// note); (b) an attribute undefined in the standard schema — 389 rejects
// unknown attributes, native's gate enforces MUST only.
func probeCAND8(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	dm := e.dm(t)
	defer dm.Close()

	markerAttrs := ldap.NewAddRequest("cn=markerdemo,"+suffixDN, nil)
	markerAttrs.Attribute("objectClass", []string{"top", "device"})
	markerAttrs.Attribute("cn", []string{"markerdemo"})
	markerAttrs.Attribute("destinationIndicator", []string{"lab"})
	markerAttrs.Attribute("owner", []string{dmDN})

	unknown := ldap.NewAddRequest("cn=unknownattr,"+suffixDN, nil)
	unknown.Attribute("objectClass", []string{"top", "device"})
	unknown.Attribute("cn", []string{"unknownattr"})
	unknown.Attribute("xyzzyUndefinedAttr", []string{"1"})

	out := []opOutcome{
		codeOutcome(dm.Add(markerAttrs)),
		codeOutcome(dm.Add(unknown)),
		readOutcome(dm, "cn=markerdemo,"+suffixDN, "destinationIndicator", "owner"),
		readOutcome(dm, "cn=unknownattr,"+suffixDN, "cn"),
	}
	// Cleanup what succeeded so the other engine sees the same tree.
	out = append(out, codeOutcome(dm.Del(ldap.NewDelRequest("cn=markerdemo,"+suffixDN, nil))))
	out = append(out, codeOutcome(dm.Del(ldap.NewDelRequest("cn=unknownattr,"+suffixDN, nil))))
	return out
}

// histProbeAfterCAND9 is histprobe's password between CAND-9 (which
// restores to this fresh value) and CAND-11 (which starts from it).
const histProbeAfterCAND9 = "parity-hist-third-001"

// CAND-9: exact result code for password-policy-violation writes (native
// plugin-abort path surfaces unwillingToPerform(53); 389 is expected to
// answer constraintViolation(19)). Recorded for both min-length and
// history rejections on a dedicated account.
func probeCAND9(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	dm := e.dm(t)
	defer dm.Close()

	dn := userDN("histprobe")
	self := mustDial(t, e, userSpec(dn, userPasswords["histprobe"]))

	short := ldap.NewModifyRequest(dn, nil)
	short.Replace("userPassword", []string{"short1"})
	minLen := codeOutcome(self.Modify(short))

	rotate := ldap.NewModifyRequest(dn, nil)
	rotate.Replace("userPassword", []string{"parity-hist-second-01"})
	rotCode := codeOutcome(self.Modify(rotate))

	self2 := mustDial(t, e, userSpec(dn, "parity-hist-second-01"))
	back := ldap.NewModifyRequest(dn, nil)
	back.Replace("userPassword", []string{userPasswords["histprobe"]})
	histCode := codeOutcome(self2.Modify(back))

	// Restore to a fresh password (DM): re-setting the original would hit
	// the history list again and leave CAND-11's starting credential
	// engine-dependent.
	restore := ldap.NewModifyRequest(dn, nil)
	restore.Replace("userPassword", []string{histProbeAfterCAND9})
	restored := codeOutcome(dm.Modify(restore))
	return []opOutcome{minLen, rotCode, histCode, restored}
}

// CAND-10: exact bind failure code once the failure lockout has engaged
// (native invalidCredentials(49); confirm 389's answer), plus the lock
// marker attributes the engine sets on the entry. Uses the dedicated
// lockprobe2 account so the Contract-tier caseLockout (lockprobe) cannot
// pollute the observation. The final readback requests all user and
// operational attributes so the ledger shows exactly which lock markers
// each engine surfaces.
func probeCAND10(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	dm := e.dm(t)
	defer dm.Close()

	dn := userDN("lockprobe2")
	out := []opOutcome{dialCode(t, e, userSpec(dn, userPasswords["lockprobe2"]))}
	for i := 0; i < 3; i++ {
		out = append(out, dialCode(t, e, userSpec(dn, "parity-lock2-WRONG-00")))
	}
	out = append(out, dialCode(t, e, userSpec(dn, userPasswords["lockprobe2"]))) // locked: code is the question
	out = append(out, searchOutcome(dm, dn, ldap.ScopeBaseObject, 0, "(objectClass=*)", []string{"*", "+"}))
	return out
}

// CAND-11: re-setting the *current* password. Both engines reject;
// 389 returns constraintViolation(19), native unwillingToPerform(53)
// (history check includes the current password).
func probeCAND11(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	dm := e.dm(t)
	defer dm.Close()

	dn := userDN("histprobe")
	self := mustDial(t, e, userSpec(dn, histProbeAfterCAND9))
	same := ldap.NewModifyRequest(dn, nil)
	same.Replace("userPassword", []string{histProbeAfterCAND9})
	out := []opOutcome{codeOutcome(self.Modify(same))}
	out = append(out, dialCode(t, e, userSpec(dn, histProbeAfterCAND9)))
	// Restore to a fresh value (DM) so post-state is identical after the
	// rejected same-password re-set.
	restore := ldap.NewModifyRequest(dn, nil)
	restore.Replace("userPassword", []string{"parity-hist-fourth-01"})
	out = append(out, codeOutcome(dm.Modify(restore)))
	return out
}

// CAND-12: referential integrity removing the LAST member of a
// groupOfNames (member is MUST; an empty group is schema-illegal). Both
// engines' answers are recorded: group existence, member presence.
func probeCAND12(c *caseCtx) []opOutcome {
	e := c.e
	dm := e.dm(c.t)
	defer dm.Close()
	pre := readOutcome(dm, groupDN("lastmember"), "member")
	del := codeOutcome(dm.Del(ldap.NewDelRequest(userDN("soleuser"), nil)))
	post := readOutcome(dm, groupDN("lastmember"), "member", "objectClass")
	return []opOutcome{pre, del, post}
}

// CAND-13: evaluation order — overlapping allow rules where a
// targetattr!= exclusion acts as the deny. The runtime account holds
// people-write (targetattr!="aci") plus suffix-read
// (targetattr!="userPassword"); writing aci and reading userPassword on
// people entries must be governed by the exclusions regardless of rule
// order. The outcome set is the order-sensitive evidence.
func probeCAND13(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	rt := mustDial(t, e, userSpec(runtimeDN, runtimePassword))
	readPW := searchOutcome(rt, userDN("alice"), ldap.ScopeBaseObject, 0, "(objectClass=*)", []string{"userPassword"})
	modACI := ldap.NewModifyRequest(userDN("alice"), nil)
	modACI.Add("aci", []string{`(targetattr="*")(version 3.0; acl "evil"; allow (all) userdn="ldap:///all";)`})
	writeACI := codeOutcome(rt.Modify(modACI))
	writeDesc := codeOutcome(rt.Modify(replaceAttr(userDN("alice"), "description", "runtime-ok")))
	// Restore alice's description to the seeded state (none).
	clean := ldap.NewModifyRequest(userDN("alice"), nil)
	clean.Delete("description", []string{"runtime-ok"})
	cleanup := codeOutcome(rt.Modify(clean))
	return []opOutcome{readPW, writeACI, writeDesc, cleanup}
}

// CAND-14: may the runtime account read userPassword on a person entry?
// runtime-people-write grants targetattr!="aci" (which includes
// userPassword); T-036 only probed suffix/marker. Recorded, not assumed.
func probeCAND14(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	rt := mustDial(t, e, userSpec(runtimeDN, runtimePassword))
	return []opOutcome{
		searchOutcome(rt, userDN("alice"), ldap.ScopeBaseObject, 0, "(objectClass=*)", []string{"userPassword"}),
		searchOutcome(rt, suffixDN, ldap.ScopeBaseObject, 0, "(objectClass=*)", []string{"userPassword"}),
		searchOutcome(rt, markerDN, ldap.ScopeBaseObject, 0, "(objectClass=*)", []string{"userPassword"}),
	}
}

// CAND-15: bind-rule semantics for self / all / anyone.
//
//	self:    alice may write her own description, not bob's.
//	all:     a bound user reads ou=probe-all; the runtime account too.
//	anyone:  a pre-bind (anonymous wire-state) connection still matches.
func probeCAND15(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	alice := mustDial(t, e, userSpec(userDN("alice"), userPasswords["alice"]))
	selfOK := codeOutcome(alice.Modify(replaceAttr(userDN("alice"), "description", "self-described")))
	selfOther := codeOutcome(alice.Modify(replaceAttr(userDN("bob"), "description", "alice-was-here")))
	allRead := readOutcome(alice, probeAllOU, "ou")
	leafRead := readOutcome(alice, "cn=leaf,"+probeAllOU, "description")

	anon, err := e.dial(t, dialSpec{ldaps: true, noBind: true})
	if err != nil {
		t.Fatalf("parity: %s pre-bind dial: %v", e.name(), err)
	}
	defer anon.Close()
	anyoneRead := readOutcome(anon, probeAnyoneOU, "ou")
	allAnon := readOutcome(anon, probeAllOU, "ou") // all must NOT match pre-bind

	// Restore alice's description (delete the value self added).
	cleanup := codeOutcome(alice.Modify(func() *ldap.ModifyRequest {
		r := ldap.NewModifyRequest(userDN("alice"), nil)
		r.Delete("description", []string{"self-described"})
		return r
	}()))
	return []opOutcome{selfOK, selfOther, allRead, leafRead, anyoneRead, allAnon, cleanup}
}

// CAND-16: entry-level scope — targetattr must not gate Add/Delete of
// whole entries (native ignores targetattr for entry ops); and the
// runtime account adding an entry that itself carries an aci attribute
// (389's per-attribute add check may deny what native allows).
func probeCAND16(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	rt := mustDial(t, e, userSpec(runtimeDN, runtimePassword))
	dm := e.dm(t)
	defer dm.Close()

	plain := ldap.NewAddRequest(userDN("addprobe"), nil)
	plain.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"})
	plain.Attribute("uid", []string{"addprobe"})
	plain.Attribute("cn", []string{"Add Probe"})
	plain.Attribute("sn", []string{"Probe"})

	carrying := ldap.NewAddRequest(userDN("addaciprobe"), nil)
	carrying.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"})
	carrying.Attribute("uid", []string{"addaciprobe"})
	carrying.Attribute("cn", []string{"Add ACI Probe"})
	carrying.Attribute("sn", []string{"Probe"})
	carrying.Attribute("aci", []string{`(targetattr="description")(version 3.0; acl "self-desc-leaf"; allow (write) userdn="ldap:///self";)`})

	out := []opOutcome{
		codeOutcome(rt.Add(plain)),
		codeOutcome(rt.Add(carrying)),
		codeOutcome(rt.Del(ldap.NewDelRequest(userDN("addprobe"), nil))),
	}
	// Delete whatever the runtime could not (keep engines in lockstep).
	out = append(out, codeOutcome(dm.Del(ldap.NewDelRequest(userDN("addprobe"), nil))))
	out = append(out, codeOutcome(dm.Del(ldap.NewDelRequest(userDN("addaciprobe"), nil))))
	return out
}

// CAND-17: groupdn membership scope. probegrp has direct member dave and
// nested member innergrp (whose member is erin). Direct-member semantics
// allow dave and deny erin; a nesting oracle would allow both.
func probeCAND17(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	dave := mustDial(t, e, userSpec(userDN("dave"), userPasswords["dave"]))
	daveRead := readOutcome(dave, "cn=leaf,"+probeGroupDNOU, "description")
	erin := mustDial(t, e, userSpec(userDN("erin"), userPasswords["erin"]))
	erinRead := readOutcome(erin, "cn=leaf,"+probeGroupDNOU, "description")
	// Direct group membership of a *group* (innergrp in probegrp) does
	// not transitively admit innergrp's members when nesting is off.
	return []opOutcome{daveRead, erinRead}
}

// CAND-18: tampered paged cookie result code. The first cookie byte is
// flipped; both engines must reject, and the codes are recorded.
func probeCAND18(c *caseCtx) []opOutcome {
	e := c.e
	dm := e.dm(c.t)
	defer dm.Close()
	_, cookie := pagedPage(dm, peopleDN, "(objectClass=inetOrgPerson)", 4, nil)
	tampered := append([]byte(nil), cookie...)
	if len(tampered) > 0 {
		tampered[0] ^= 0xff
	}
	bad, _ := pagedPage(dm, peopleDN, "(objectClass=inetOrgPerson)", 4, tampered)
	bad.Entries = nil
	empty, _ := pagedPage(dm, peopleDN, "(objectClass=inetOrgPerson)", 4, []byte{0x01})
	empty.Entries = nil
	return []opOutcome{bad, empty}
}

// CAND-19: assertion control outside Modify. Critical assertion on
// Add/Delete/Search must not be silently ignored; non-critical on
// non-Modify is ignored by native, possibly honored by 389. All writes
// target the disposable cn=assertadd entry so the probe is state-neutral
// no matter which semantics the oracle implements.
func probeCAND19(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	dm := e.dm(t)
	defer dm.Close()

	addReq := ldap.NewAddRequest("cn=assertadd,"+suffixDN, nil)
	addReq.Attribute("objectClass", []string{"top", "device"})
	addReq.Attribute("cn", []string{"assertadd"})
	addReq.Controls = append(addReq.Controls, assertionControl(t, "(cn=assertadd)", true))

	delCrit := ldap.NewDelRequest("cn=assertadd,"+suffixDN, nil)
	delCrit.Controls = append(delCrit.Controls, assertionControl(t, "(cn=assertadd)", true))

	delNonCrit := ldap.NewDelRequest("cn=assertadd,"+suffixDN, nil)
	delNonCrit.Controls = append(delNonCrit.Controls, assertionControl(t, "(cn=nope)", false))

	searchCrit := searchOutcome(dm, markerDN, ldap.ScopeBaseObject, 0, "(objectClass=*)", []string{"cn"},
		assertionControl(t, "(cn=labldap-baseline)", true))

	out := []opOutcome{
		codeOutcome(dm.Add(addReq)),
		codeOutcome(dm.Del(delCrit)),
		codeOutcome(dm.Del(delNonCrit)),
		searchCrit,
		readOutcome(dm, markerDN, "cn"), // marker must have survived
	}
	// Cleanup tolerates either engine branch (entry may or may not exist).
	out = append(out, codeOutcome(dm.Del(ldap.NewDelRequest("cn=assertadd,"+suffixDN, nil))))
	return out
}

// CAND-20: WhoAmI authzid rendering — canonical form for an exact-case
// bind, case preservation for a case-variant bind DN, and the anonymous
// form on a pre-bind connection.
func probeCAND20(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	exact := mustDial(t, e, userSpec(userDN("erin"), userPasswords["erin"]))
	exactOut := whoami(exact)

	variant := mustDial(t, e, userSpec("UID=ERIN,OU=PEOPLE,DC=EXAMPLE,DC=TEST", userPasswords["erin"]))
	variantOut := whoami(variant)

	anon, err := e.dial(t, dialSpec{ldaps: true, noBind: true})
	if err != nil {
		t.Fatalf("parity: %s pre-bind dial: %v", e.name(), err)
	}
	defer anon.Close()
	anonOut := whoami(anon)
	return []opOutcome{exactOut, variantOut, anonOut}
}

// probeSetNote adds a note to every outcome (used to label sub-cases).
func probeSetNote(outs []opOutcome, notes ...string) []opOutcome {
	for i := range outs {
		if i < len(notes) {
			outs[i].Note = notes[i]
		}
	}
	return outs
}

// CAND-25: exact capability advertisement sets. Contract C10 requires
// v3 to be served and StartTLS/WhoAmI/paged to be advertised (the
// Contract case asserts those presences); the exact sets are D6 honest
// advertisement: the pinned 389 historically advertises
// supportedLDAPVersion {"2","3"} while native publishes exactly {"3"}
// (D10 records that 389 refuses actual LDAPv2 binds anyway), 389 omits
// the assertion OID from supportedControl (it does not implement RFC
// 4528 — CAND-26), and 389 lists its own extended operations (including
// RFC 3062, which is E3-Excluded for native).
func probeCAND25(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	conn := mustDial(t, e, userSpec(userDN("alice"), userPasswords["alice"]))
	ctrl := readOutcome(conn, "", "supportedControl")
	assertAdv := opOutcome{Code: ctrl.Code, Value: "assertion-not-advertised"}
	for _, en := range ctrl.Entries {
		for _, v := range en.Attrs["supportedcontrol"] {
			if v == oidAssertion {
				assertAdv.Value = "assertion-advertised"
			}
		}
	}
	return []opOutcome{
		readOutcome(conn, "", "supportedLDAPVersion"),
		assertAdv,
		readOutcome(conn, "", "supportedExtension"),
	}
}

// CAND-26: RFC 4528 assertion semantics on Modify across both
// criticalities. Observed on the pinned oracle (consistent with the
// OID's absence from 389's supportedControl, CAND-25): the control is
// NOT implemented — critical requests are refused with
// unavailableCriticalExtension (12), non-critical requests are silently
// ignored (the modify commits even when the assertion fails). Native
// honors RFC 4528 at both criticalities (D7): pass commits, fail aborts
// with assertionFailed (122). The probe tolerates mid-probe divergence
// (the presence assertion used later holds on both branches) and ends
// with a deterministic restore.
func probeCAND26(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	dm := e.dm(t)
	defer dm.Close()

	dn := userDN("dave")
	seed := ldap.NewModifyRequest(dn, nil)
	seed.Replace("description", []string{"assert-v1"})

	out := []opOutcome{
		codeOutcome(dm.Modify(seed)),
		// Non-critical pass: commits on both (389 by ignoring, native by
		// honoring) — identical outcome.
		codeOutcome(dm.Modify(withControls(
			replaceAttr(dn, "description", "assert-v2"),
			assertionControl(t, "(description=assert-v1)", false)))),
		// Non-critical FAIL: 389 ignores the control and commits; native
		// aborts with 122.
		codeOutcome(dm.Modify(withControls(
			replaceAttr(dn, "description", "assert-v3"),
			assertionControl(t, "(description=nope)", false)))),
		readOutcome(dm, dn, "description"), // commit evidence either way
		// Critical, presence-true assertion (holds on both branches):
		// 389 refuses (12); native commits.
		codeOutcome(dm.Modify(withControls(
			replaceAttr(dn, "description", "assert-v5"),
			assertionControl(t, "(description=*)", true)))),
		// Critical, failing assertion: 389 refuses (12) before
		// evaluation; native aborts with 122.
		codeOutcome(dm.Modify(withControls(
			replaceAttr(dn, "description", "assert-v6"),
			assertionControl(t, "(description=nope)", true)))),
		readOutcome(dm, dn, "description"),
	}
	// Restore deterministically so the tree stays identical on both
	// engines regardless of which branch committed.
	restore := ldap.NewModifyRequest(dn, nil)
	restore.Replace("description", []string{"assert-v1"})
	out = append(out, codeOutcome(dm.Modify(restore)))
	return out
}

// CAND-27: Directory Manager password reset against the history policy.
// 389's rootdn bypasses password policy (in-history reset succeeds);
// native applies history to DM writes (unwillingToPerform). Dedicated
// account so history contents are deterministic: after the self-rotate,
// history holds exactly the original password.
func probeCAND27(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	dm := e.dm(t)
	defer dm.Close()

	dn := userDN("dmpwprobe")
	self := mustDial(t, e, userSpec(dn, userPasswords["dmpwprobe"]))

	rotate := ldap.NewModifyRequest(dn, nil)
	rotate.Replace("userPassword", []string{"parity-dmpw-second-01"})
	out := []opOutcome{codeOutcome(self.Modify(rotate))}

	// DM reset to the in-history original password: the question.
	inHist := ldap.NewModifyRequest(dn, nil)
	inHist.Replace("userPassword", []string{userPasswords["dmpwprobe"]})
	out = append(out, codeOutcome(dm.Modify(inHist)))

	// DM reset to a fresh password must succeed on both (keeps the
	// post-state identical no matter how the in-history reset landed).
	fresh := ldap.NewModifyRequest(dn, nil)
	fresh.Replace("userPassword", []string{"parity-dmpw-third-001"})
	out = append(out, codeOutcome(dm.Modify(fresh)))
	out = append(out, dialCode(t, e, userSpec(dn, "parity-dmpw-third-001")))
	return out
}

// CAND-28: subschema publication of pwdAccountLockedTime. Native
// publishes every C5 operational attribute; the pinned 389 schema does
// not define pwdAccountLockedTime (its lockout state lives in
// accountUnlockTime/passwordRetryCount — see CAND-10's readback).
// nsAccountLock is the control: both engines publish it.
func probeCAND28(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	conn := e.dm(t)
	defer conn.Close()

	dse, err := conn.Search(ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"subschemaSubentry"}, nil))
	if err != nil || len(dse.Entries) == 0 {
		t.Fatalf("parity: %s subschema discovery: %v", e.name(), err)
	}
	subDN := dse.Entries[0].GetAttributeValue("subschemaSubentry")
	if subDN == "" {
		t.Fatalf("parity: %s root DSE carries no subschemaSubentry", e.name())
	}

	res, err := conn.Search(ldap.NewSearchRequest(
		subDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)", []string{"attributeTypes"}, nil))
	if err != nil {
		t.Fatalf("parity: %s subschema read: %v", e.name(), err)
	}
	pub := map[string]bool{}
	for _, en := range res.Entries {
		for _, a := range en.Attributes {
			if !strings.EqualFold(a.Name, "attributeTypes") {
				continue
			}
			for _, v := range a.Values {
				for _, name := range []string{"pwdAccountLockedTime", "nsAccountLock"} {
					if schemaValueNamed(v, name) {
						pub[strings.ToLower(name)] = true
					}
				}
			}
		}
	}
	out := []opOutcome{{Code: 0}}
	for _, name := range []string{"nsaccountlock", "pwdaccountlockedtime"} {
		if pub[name] {
			out[0].Entries = append(out[0].Entries, canonEntry{DN: "at:" + name})
		}
	}
	return out
}

// CAND-21 (D8): bind with a malformed DN. 389 answers invalidDNSyntax
// (34); native authenticates the DN string and answers
// invalidCredentials (49). Raw-wire form: go-ldap validates the DN
// client-side on some paths. The second step is the well-formed
// unknown-DN control (both engines must agree on 49).
func probeCAND21(c *caseCtx) []opOutcome {
	t := c.t
	return []opOutcome{
		rawBind(t, c, true, 3, "this is not a dn", "parity-nope-secret-1"),
		rawBind(t, c, true, 3, userDN("nosuchuser"), "parity-nope-secret-1"),
	}
}

// CAND-22: pre-bind (anonymous wire state) root DSE read. 389's
// nsslapd-allow-anonymous-access=off refuses the operation with
// inappropriateAuthentication (48) before ACI evaluation; native
// evaluates the DSE as world-readable. The authenticated control read
// must succeed on both (that half is Contract, asserted in C10's case).
func probeCAND22(c *caseCtx) []opOutcome {
	t, e := c.t, c.e
	anon, err := e.dial(t, dialSpec{ldaps: true, noBind: true})
	if err != nil {
		t.Fatalf("parity: %s pre-bind dial: %v", e.name(), err)
	}
	defer anon.Close()
	preBind := readOutcome(anon, "", "namingContexts")

	authed := mustDial(t, e, userSpec(userDN("dave"), userPasswords["dave"]))
	postBind := readOutcome(authed, "", "namingContexts")
	return []opOutcome{preBind, postBind}
}

// CAND-23: compare against an attribute the entry does not carry. 389
// answers noSuchAttribute (16); native answers compareFalse (5). The
// control compare on a present value must agree (compareTrue).
func probeCAND23(c *caseCtx) []opOutcome {
	e := c.e
	dm := e.dm(c.t)
	defer dm.Close()

	cmp := func(attr, val string) opOutcome {
		ok, err := dm.Compare(userDN("erin"), attr, val)
		if err != nil {
			return codeOutcome(err)
		}
		if ok {
			return opOutcome{Code: ldap.LDAPResultCompareTrue}
		}
		return opOutcome{Code: ldap.LDAPResultCompareFalse}
	}
	return []opOutcome{
		cmp("telephoneNumber", "+1 555 0000"), // absent attribute
		cmp("sn", "Evans"),                    // control: present, matches
	}
}

// CAND-24: auxiliary object class lifecycle of the memberOf derivation.
// 389's plugin is configured with --autoaddoc nsmemberof (mirroring the
// production reconciler). On membership ADD both engines end up with
// nsmemberof on the member entry (observed); on RETRACTION the engines
// may differ (389 keeps the auto-added class, native drops it with the
// memberOf value). Dedicated entries keep the probe state-neutral.
func probeCAND24(c *caseCtx) []opOutcome {
	e := c.e
	dm := e.dm(c.t)
	defer dm.Close()

	add := ldap.NewAddRequest(userDN("ocprobe"), nil)
	add.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"})
	add.Attribute("uid", []string{"ocprobe"})
	add.Attribute("cn", []string{"OC Probe"})
	add.Attribute("sn", []string{"Probe"})

	grp := ldap.NewAddRequest(groupDN("ocgrp"), nil)
	grp.Attribute("objectClass", []string{"top", "groupOfNames"})
	grp.Attribute("cn", []string{"ocgrp"})
	grp.Attribute("member", []string{userDN("ocprobe")})

	// Retract the membership again (group keeps a different member so it
	// stays schema-legal).
	swap := ldap.NewModifyRequest(groupDN("ocgrp"), nil)
	swap.Replace("member", []string{userDN("dave")})

	out := []opOutcome{
		codeOutcome(dm.Add(add)),
		readOutcome(dm, userDN("ocprobe"), "objectClass"), // pre-membership
		codeOutcome(dm.Add(grp)),
		readOutcome(dm, userDN("ocprobe"), "objectClass", "memberOf"), // post-membership
		codeOutcome(dm.Modify(swap)),
		readOutcome(dm, userDN("ocprobe"), "objectClass", "memberOf"), // post-retraction
	}
	// Cleanup so the engines stay in lockstep for the remaining probes.
	out = append(out, codeOutcome(dm.Del(ldap.NewDelRequest(groupDN("ocgrp"), nil))))
	out = append(out, codeOutcome(dm.Del(ldap.NewDelRequest(userDN("ocprobe"), nil))))
	return out
}
