package parity

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// Fixture DNs. One scenario fixture is compiled once and applied to both
// engines (parity contract section 5 rule 1).
const (
	suffixDN  = "dc=example,dc=test"
	peopleDN  = "ou=people,dc=example,dc=test"
	groupsDN  = "ou=groups,dc=example,dc=test"
	runtimeDN = "uid=labldap-runtime," + peopleDN
	dmDN      = "cn=Directory Manager"
	markerDN  = "cn=labldap-baseline," + suffixDN

	probeAllOU     = "ou=probe-all," + suffixDN
	probeAnyoneOU  = "ou=probe-anyone," + suffixDN
	probeGroupDNOU = "ou=probe-groupdn," + suffixDN
	moveDemoOU     = "ou=movedemo," + suffixDN
)

// Test-only lab credentials (fixed so ledger goldens are stable). These
// are throwaway fixtures, never usable outside the parity lab.
const (
	runtimePassword = "parity-runtime-secret-01"
	nativeDMSecret  = "parity-dm-secret-000001"
)

// userPasswords covers the five scenario users plus the probe-only
// accounts the harness seeds directly (runtime account, lockout/history/
// self-service/RI targets). All satisfy the compiled minLength of 12.
var userPasswords = map[string]string{
	"labldap-runtime": runtimePassword,
	"alice":           "parity-alice-secret-01",
	"bob":             "parity-bob-secret-0001",
	"carol":           "parity-carol-secret-001",
	"dave":            "parity-dave-secret-0001",
	"erin":            "parity-erin-secret-0001",
	"pwprobe":         "parity-pwprobe-secret1",
	"lockprobe":       "parity-lock-secret-001",
	"lockprobe2":      "parity-lock2-secret-01",
	"histprobe":       "parity-hist-secret-001",
	"soleuser":        "parity-sole-secret-0001",
	"norah":           "parity-norah-secret-01",
	"dmpwprobe":       "parity-dmpw-secret-001",
}

func userDN(id string) string  { return "uid=" + id + "," + peopleDN }
func groupDN(id string) string { return "cn=" + id + "," + groupsDN }

// scenarioYAML is the single fixture scenario (contract section 5 rule 1).
// It compiles through internal/config so both engines inherit the same
// suffix, transport policy, password policy, runtime ACIs, and probe ACIs
// (rawACI exercises the contract C8 grammar paths the DSL cannot express:
// self/all/anyone/groupdn bind rules).
func scenarioYAML() []byte {
	return []byte(`
apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata: { name: parity }
spec:
  directory:
    engine: native
    suffix: "dc=example,dc=test"
    peopleRDN: "ou=people"
    groupsRDN: "ou=groups"
    allowRawACI: true
  transport:
    insecureLabMode: true
    ldap: { enabled: true, port: 3389 }
    ldaps: { enabled: true, port: 3636 }
    startTLS: true
    allowCleartextBind: false
    allowAnonymousBind: false
  runtimeAccount: { id: labldap-runtime, passwordFile: secrets/runtime }
  users:
    - id: alice
      passwordFile: secrets/alice
      attributes: { sn: Anderson, givenName: Alice, displayName: Alice Anderson, mail: alice@example.test }
    - id: bob
      passwordFile: secrets/bob
      attributes: { sn: Brown, givenName: Bob, mail: bob@example.test }
    - id: carol
      passwordFile: secrets/carol
      attributes: { sn: Carter, givenName: Carol, mail: carol@example.test }
    - id: dave
      passwordFile: secrets/dave
      attributes: { sn: Davis, givenName: Dave, mail: dave@example.test }
    - id: erin
      passwordFile: secrets/erin
      attributes: { sn: Evans, givenName: Erin, mail: erin@example.test }
  groups:
    - id: staff
      members: [ { user: alice }, { user: bob } ]
    - id: ops
      members: [ { user: carol } ]
  passwordPolicy:
    minLength: 12
    historyCount: 3
    maxAge: 0s
    warningAge: 0s
    lockout: { enabled: true, maxFailures: 3, lockoutDuration: 300s }
    storageScheme: PBKDF2-SHA256
  acls:
    - id: probe-self-desc
      rawACI: '(target="ldap:///ou=people,dc=example,dc=test")(targetattr="description")(version 3.0; acl "labldap:probe-self-desc"; allow (write) userdn="ldap:///self";)'
    - id: probe-self-pwd
      rawACI: '(target="ldap:///ou=people,dc=example,dc=test")(targetattr="userPassword")(version 3.0; acl "labldap:probe-self-pwd"; allow (write) userdn="ldap:///self";)'
    - id: probe-all-read
      rawACI: '(target="ldap:///ou=probe-all,dc=example,dc=test")(targetattr="*")(version 3.0; acl "labldap:probe-all-read"; allow (read,search,compare) userdn="ldap:///all";)'
    - id: probe-anyone-read
      rawACI: '(target="ldap:///ou=probe-anyone,dc=example,dc=test")(targetattr="*")(version 3.0; acl "labldap:probe-anyone-read"; allow (read,search,compare) userdn="ldap:///anyone";)'
    - id: probe-groupdn-read
      rawACI: '(target="ldap:///ou=probe-groupdn,dc=example,dc=test")(targetattr="*")(version 3.0; acl "labldap:probe-groupdn-read"; allow (read,search,compare) groupdn="ldap:///cn=probegrp,ou=groups,dc=example,dc=test";)'
`)
}

// fixture is the compiled scenario plus the shared TLS materials.
type fixture struct {
	compiled *config.Compiled
	tls      *tlsFixture
}

func compileFixture(t *testing.T) *fixture {
	t.Helper()
	secrets := config.MapResolver{"secrets/runtime": runtimePassword}
	for id, pw := range userPasswords {
		secrets["secrets/"+id] = pw
	}
	c, err := config.Compile(t.Context(), scenarioYAML(), "parity.yaml", config.LoadOptions{
		Caller:  config.CallerCLI,
		Secrets: secrets,
	})
	if err != nil {
		t.Fatalf("parity: compile fixture scenario: %v", err)
	}
	return &fixture{compiled: c, tls: makeTLSFixture(t)}
}

// aciTexts returns the full compiled ACI set in compiler order (runtime
// ACIs first, then operator ACLs) — what labldapd hands to the native
// engine at startup.
func (f *fixture) aciTexts() []string {
	out := make([]string, 0, len(f.compiled.Data.ACIs))
	for _, a := range f.compiled.Data.ACIs {
		out = append(out, a.Text)
	}
	return out
}

// aciPlacements groups the compiled ACI texts by their placement entry so
// the 389 oracle can be seeded with the same aci attribute values the
// production tree reconciler would write.
func (f *fixture) aciPlacements() map[string][]string {
	out := map[string][]string{}
	for _, a := range f.compiled.Data.ACIs {
		out[a.Target] = append(out[a.Target], a.Text)
	}
	return out
}

// policy returns the compiled password policy.
func (f *fixture) policy() config.NormalizedPolicy {
	return f.compiled.Engine.PasswordPolicy
}

// seedDirectory applies the identical LDAP operation sequence to an engine
// as Directory Manager (contract section 5 rule 2): the suffix root,
// organizational units, runtime account, scenario users/groups, probe-only
// fixtures, the baseline marker, and finally the compiled ACI set placed
// as aci attribute values exactly where the production tree reconciler
// puts them. On the native engine the aci values are inert entry data —
// native ACI enforcement comes from the startup options — while on 389
// the same values configure access evaluation.
func seedDirectory(t *testing.T, fx *fixture, conn *ldap.Conn) {
	t.Helper()

	add := func(dn string, attrs []ldap.Attribute) {
		t.Helper()
		req := ldap.NewAddRequest(dn, nil)
		for _, a := range attrs {
			req.Attribute(a.Type, a.Vals)
		}
		if err := conn.Add(req); err != nil {
			// The 389 backend create pre-creates the suffix root entry;
			// tolerate that one collision so the sequence stays identical.
			if dn == suffixDN && ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
				return
			}
			t.Fatalf("parity: seed add %s: %v", dn, err)
		}
	}
	attr := func(name string, vals ...string) ldap.Attribute {
		return ldap.Attribute{Type: name, Vals: vals}
	}

	add(suffixDN, []ldap.Attribute{
		attr("objectClass", "top", "domain"),
		attr("dc", "example"),
	})
	add(peopleDN, []ldap.Attribute{
		attr("objectClass", "top", "organizationalUnit"),
		attr("ou", "people"),
	})
	add(groupsDN, []ldap.Attribute{
		attr("objectClass", "top", "organizationalUnit"),
		attr("ou", "groups"),
	})

	addUser := func(id, cn, sn string, extra ...ldap.Attribute) {
		t.Helper()
		attrs := []ldap.Attribute{
			attr("objectClass", "top", "person", "organizationalPerson", "inetOrgPerson"),
			attr("uid", id),
			attr("cn", cn),
			attr("sn", sn),
			attr("userPassword", userPasswords[id]),
		}
		attrs = append(attrs, extra...)
		add(userDN(id), attrs)
	}
	addUser("labldap-runtime", "LabLDAP Runtime", "Runtime")
	addUser("alice", "Alice Anderson", "Anderson",
		attr("givenName", "Alice"), attr("displayName", "Alice Anderson"), attr("mail", "alice@example.test"))
	addUser("bob", "Bob Brown", "Brown", attr("givenName", "Bob"), attr("mail", "bob@example.test"))
	addUser("carol", "Carol Carter", "Carter", attr("givenName", "Carol"), attr("mail", "carol@example.test"))
	addUser("dave", "Dave Davis", "Davis", attr("givenName", "Dave"), attr("mail", "dave@example.test"))
	addUser("erin", "Erin Evans", "Evans", attr("givenName", "Erin"), attr("mail", "erin@example.test"))
	addUser("pwprobe", "Pete Probe", "Probe")
	addUser("lockprobe", "Larry Lock", "Lock")
	addUser("lockprobe2", "Lucy Lock", "Lock")
	addUser("histprobe", "Hank Hist", "Hist")
	addUser("soleuser", "Solo User", "User")
	// norah never joins a group: she is the stable objectClass reference
	// (membered users gain engine-specific memberOf auxiliary classes).
	addUser("norah", "Nora Nogroup", "Nogroup")
	// dmpwprobe exists only for CAND-27 (DM password reset vs history).
	addUser("dmpwprobe", "Dana Reset", "Reset")

	addGroup := func(id, description string, memberDNs ...string) {
		t.Helper()
		attrs := []ldap.Attribute{
			attr("objectClass", "top", "groupOfNames"),
			attr("cn", id),
			attr("member", memberDNs...),
		}
		if description != "" {
			attrs = append(attrs, attr("description", description))
		}
		add(groupDN(id), attrs)
	}
	addGroup("staff", "staff group", userDN("alice"), userDN("bob"))
	addGroup("ops", "", userDN("carol"))
	addGroup("probegrp", "", userDN("dave"), groupDN("innergrp"))
	addGroup("innergrp", "", userDN("erin"))
	addGroup("lastmember", "", userDN("soleuser"))

	addOU := func(dn, ou string) {
		t.Helper()
		add(dn, []ldap.Attribute{
			attr("objectClass", "top", "organizationalUnit"),
			attr("ou", ou),
		})
	}
	addOU(probeAllOU, "probe-all")
	addOU(probeAnyoneOU, "probe-anyone")
	addOU(probeGroupDNOU, "probe-groupdn")
	addOU(moveDemoOU, "movedemo")

	addDevice := func(dn, cn, description string) {
		t.Helper()
		attrs := []ldap.Attribute{
			attr("objectClass", "top", "device"),
			attr("cn", cn),
		}
		if description != "" {
			attrs = append(attrs, attr("description", description))
		}
		add(dn, attrs)
	}
	addDevice("cn=leaf,"+probeAllOU, "leaf", "all-leaf")
	addDevice("cn=leaf,"+probeAnyoneOU, "leaf", "anyone-leaf")
	addDevice("cn=leaf,"+probeGroupDNOU, "leaf", "groupdn-leaf")
	addDevice("cn=kid,"+moveDemoOU, "kid", "move demo child")
	addDevice(markerDN, "labldap-baseline", `{"labldap.dev/baseline":{"revision":"parity-fixture-v1"}}`)

	// ACI placement: replace converges any 389 default aci values to the
	// compiled set (matching the production tree reconciler's converge
	// semantics) and creates the attribute on a fresh native store.
	placements := fx.aciPlacements()
	targets := make([]string, 0, len(placements))
	for target := range placements {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	for _, target := range targets {
		req := ldap.NewModifyRequest(target, nil)
		req.Replace("aci", placements[target])
		if err := conn.Modify(req); err != nil {
			t.Fatalf("parity: seed aci on %s: %v", target, err)
		}
	}
}

// --- outcome canonicalization (contract section 5 rule 3) ---

// opOutcome is one canonicalized LDAP outcome: the result code plus any
// returned entries after DN/attribute normalization. Code -1 marks a
// transport-level failure (TLS handshake, disconnect) where no LDAP
// result exists.
type opOutcome struct {
	Code    int          `json:"code"`
	Entries []canonEntry `json:"entries,omitempty"`
	Value   string       `json:"value,omitempty"`
	Note    string       `json:"note,omitempty"`
}

type canonEntry struct {
	DN    string              `json:"dn"`
	Attrs map[string][]string `json:"attrs,omitempty"`
}

// secretAttrs are dropped outright: password material never enters an
// outcome, a log, or the ledger (contract section 5 rule 5; AGENTS.md).
var secretAttrs = map[string]bool{
	"userpassword":    true,
	"passwordhistory": true,
}

// engineInternalAttrs are 389-internal operational attributes (entry
// database IDs, DSA-specific DN copies) that native does not model at
// all. They are dropped from outcomes: neither presence nor value is
// comparable (contract section 5 rule 4; D6's spirit).
var engineInternalAttrs = map[string]bool{
	"dsentrydn": true,
	"entrydn":   true,
	"entryid":   true,
	"parentid":  true,
}

// presentOnlyAttrs carry engine-specific values (timestamps, UUIDs, DNs of
// the modifying identity): presence is Contract, the value is not
// (contract section 5 rule 4).
var presentOnlyAttrs = map[string]bool{
	"vendorname":            true, // D1: identity values differ intentionally
	"vendorversion":         true,
	"createtimestamp":       true,
	"modifytimestamp":       true,
	"creatorsname":          true,
	"modifiersname":         true,
	"entryuuid":             true,
	"entrycsn":              true,
	"nsuniqueid":            true,
	"pwdchangedtime":        true,
	"pwdaccountlockedtime":  true,
	"numsubordinates":       true,
	"hassubordinates":       true,
	"subschemasubentry":     true,
	"passwordexpirytime":    true,
	"accountunlocktime":     true,
	"pwdpolicysubentry":     true,
	"passwordretrycount":    true,
	"retrycountresettime":   true,
	"passwordgraceusertime": true,
}

// canonDN folds a DN through internal/config canonicalization (the
// contract mandates the config DN rules; DNs that fail to parse are
// lowercased so a malformed-DN delta is still visible).
func canonDN(dn string) string {
	d, err := config.ParseDN(dn)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(dn))
	}
	return d.FoldedKey()
}

// canonDNValue normalizes a DN-valued attribute (member, memberOf, ...)
// structurally rather than by string suffix (contract C6).
func canonDNValue(v string) string { return canonDN(v) }

// canonicalize converts a wire entry into its comparison form.
func canonicalize(e *ldap.Entry) canonEntry {
	out := canonEntry{DN: canonDN(e.DN), Attrs: map[string][]string{}}
	for _, a := range e.Attributes {
		name := strings.ToLower(a.Name)
		if secretAttrs[name] || engineInternalAttrs[name] {
			continue
		}
		if presentOnlyAttrs[name] {
			out.Attrs[name] = []string{"PRESENT"}
			continue
		}
		vals := make([]string, 0, len(a.Values))
		for _, v := range a.Values {
			if name == "member" || name == "memberof" || name == "uniquemember" || name == "owner" {
				v = canonDNValue(v)
			}
			vals = append(vals, v)
		}
		sort.Strings(vals)
		out.Attrs[name] = vals
	}
	return out
}

// canonicalizeAll sorts entries by canonical DN (search result order is
// not Contract) and drops entries with no comparable attributes.
func canonicalizeAll(entries []*ldap.Entry) []canonEntry {
	out := make([]canonEntry, 0, len(entries))
	for _, e := range entries {
		out = append(out, canonicalize(e))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DN < out[j].DN })
	return out
}

// ldapCode extracts the LDAP result code from an error: 0 for nil, the
// ResultCode of an *ldap.Error, or -1 for transport/other failures.
func ldapCode(err error) int {
	if err == nil {
		return ldap.LDAPResultSuccess
	}
	var lerr *ldap.Error
	if errors.As(err, &lerr) {
		return int(lerr.ResultCode)
	}
	return -1
}

// codeOutcome builds an outcome from an operation error only.
func codeOutcome(err error) opOutcome {
	return opOutcome{Code: ldapCode(err)}
}

// searchOutcome runs a search and captures code + canonicalized entries.
func searchOutcome(conn *ldap.Conn, base string, scope, sizeLimit int, filter string, attrs []string, controls ...ldap.Control) opOutcome {
	req := ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, sizeLimit, 0, false, filter, attrs, controls)
	res, err := conn.Search(req)
	out := opOutcome{Code: ldapCode(err)}
	if res != nil {
		out.Entries = canonicalizeAll(res.Entries)
	}
	return out
}

// readOutcome reads one entry (base scope) with explicit attributes.
func readOutcome(conn *ldap.Conn, dn string, attrs ...string) opOutcome {
	return searchOutcome(conn, dn, ldap.ScopeBaseObject, 0, "(objectClass=*)", attrs)
}

// countOutcome captures only the result code and entry count — used where
// the *set* returned under a size limit is engine-order-dependent.
func countOutcome(conn *ldap.Conn, base string, scope, sizeLimit int, filter string, attrs []string, controls ...ldap.Control) opOutcome {
	req := ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, sizeLimit, 0, false, filter, attrs, controls)
	res, err := conn.Search(req)
	out := opOutcome{Code: ldapCode(err)}
	if res != nil {
		out.Value = fmt.Sprintf("%d", len(res.Entries))
	}
	return out
}
