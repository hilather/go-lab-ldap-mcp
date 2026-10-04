package parity

import (
	"fmt"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// Resolved CAND-36 (modrdn ACL gates and result-code ordering), CAND-37
// (targetattr!="*" and star lists) and CAND-38 (absolute filters), oracle
// probes 25-29 in testdata/filter-attr-oracle-probes.txt. Own fixture, so
// the shared ledger fixture never sees these ACIs. Cross-parent moves
// (CAND-39) and case-only renames (CAND-30) stay open and are not run here.

const (
	c38OU       = "ou=probe-c38," + suffixDN
	c38Password = "parity-c38-secret-0001"
	c38RSC      = "read,search,compare"
)

var c38Subjects = []struct {
	id   string
	acis [][2]string
}{
	{"c38_uid", [][2]string{{`(targetattr="*")`, "read,search"}, {`(targetattr="uid")`, "write"}}},
	{"c38_cn", [][2]string{{`(targetattr="*")`, "read,search"}, {`(targetattr="cn")`, "write"}}},
	{"c38_deny_desc", [][2]string{{`(targetattr="*")`, "read,search,write"}, {`(targetattr="description")`, "deny:write"}}},
	{"c38_deny_uid", [][2]string{{`(targetattr="*")`, "read,search,write"}, {`(targetattr="uid")`, "deny:write"}}},
	{"c38_deny_noattr", [][2]string{{`(targetattr="uid")`, "write"}, {``, "deny:write"}}},
	{"c38_none", [][2]string{{`(targetattr="*")`, "read,search"}}},
	{"c38_star", [][2]string{{`(targetattr="*")`, "write"}}},
	{"c38_neg", [][2]string{{`(targetattr!="*")`, c38RSC}}},
	{"c38_negmix", [][2]string{{`(targetattr!="* || sn")`, c38RSC}}},
	{"c38_negdeny", [][2]string{{`(targetattr="*")`, c38RSC}, {`(targetattr!="*")`, "deny:" + c38RSC}}},
	{"c38_ad", [][2]string{{`(targetattr="*")`, c38RSC}, {`(targetattr!="*")`, "add,delete"}}},
}

func c38Fixture(t *testing.T) *fixture {
	t.Helper()
	var acls strings.Builder
	for _, s := range c38Subjects {
		for i, a := range s.acis {
			action, perms := "allow", a[1]
			if p, ok := strings.CutPrefix(perms, "deny:"); ok {
				action, perms = "deny", p
			}
			id := fmt.Sprintf("%s-%d", strings.ReplaceAll(s.id, "_", "-"), i)
			fmt.Fprintf(&acls, "    - id: %s\n      rawACI: '(target=\"ldap:///%s\")%s(version 3.0; acl \"labldap:%s\"; %s (%s) userdn=\"ldap:///uid=%s,%s\";)'\n",
				id, c38OU, a[0], id, action, perms, s.id, peopleDN)
		}
	}
	scenario := append(scenarioYAML(), []byte(acls.String())...)
	secrets := config.MapResolver{"secrets/runtime": runtimePassword}
	for id, pw := range userPasswords {
		secrets["secrets/"+id] = pw
	}
	c, err := config.Compile(t.Context(), scenario, "c38-parity.yaml", config.LoadOptions{Caller: config.CallerCLI, Secrets: secrets})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{compiled: c, tls: makeTLSFixture(t)}
}

type c38Rename struct {
	subject, newRDN string // newRDN has one %s for the fresh entry's uid
	del             bool
	want            int
}

var c38Renames = []c38Rename{
	{"c38_uid", "uid=%s-r", true, 0},
	{"c38_uid", "uid=%s-r", false, 0},
	{"c38_uid", "cn=%s-r", false, 50},
	{"c38_cn", "uid=%s-r", false, 50},
	{"c38_cn", "cn=%s-r", false, 0},
	{"c38_deny_desc", "uid=%s-r", true, 0},
	{"c38_deny_uid", "uid=%s-r", true, 50},
	{"c38_deny_uid", "cn=%s-r", false, 0},
	{"c38_deny_noattr", "uid=%s-r", true, 50},
	{"c38_none", "uid=%s-r", true, 50},
	{"c38_uid", "bogusAttr=%s", false, 50},
	{"c38_uid", "uid=%s", true, 0}, // no-op rename (probe 28)
	{"c38_cn", "uid=%s", false, 50},
}

// c38Outcomes runs every row on e, asserting the oracle answers, and returns
// the outcomes for the dual-engine comparison.
func c38Outcomes(t *testing.T, e engine) []opOutcome {
	t.Helper()
	dm := e.dm(t)
	defer dm.Close()
	person := []string{"top", "person", "organizationalPerson", "inetOrgPerson"}
	var created []string
	add := func(dn string, attrs map[string][]string) {
		t.Helper()
		req := ldap.NewAddRequest(dn, nil)
		for _, n := range []string{"objectClass", "ou", "uid", "cn", "sn", "description", "userPassword"} {
			if v, ok := attrs[n]; ok {
				req.Attribute(n, v)
			}
		}
		if err := dm.Add(req); err != nil {
			t.Fatalf("seed %s: %v", dn, err)
		}
		created = append([]string{dn}, created...)
	}
	add(c38OU, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"probe-c38"}})
	add("uid=fa_bob,"+c38OU, map[string][]string{"objectClass": person, "uid": {"fa_bob"}, "cn": {"fa_bob"}, "sn": {"S"}, "description": {"hello"}})
	add("uid=ord_b,"+c38OU, map[string][]string{"objectClass": person, "uid": {"ord_b"}, "cn": {"ord_b"}, "sn": {"S"}})
	for _, s := range c38Subjects {
		add(userDN(s.id), map[string][]string{"objectClass": person, "uid": {s.id}, "cn": {s.id}, "sn": {"S"}, "userPassword": {c38Password}})
	}
	var out []opOutcome
	record := func(o opOutcome, want int, note string) {
		if o.Code != want {
			t.Errorf("%s %s: code %d, oracle %d", e.name(), note, o.Code, want)
		}
		o.Note = note
		out = append(out, o)
	}
	as := func(id string) *ldap.Conn { return mustDial(t, e, userSpec(userDN(id), c38Password)) }

	for i, r := range c38Renames {
		uid := fmt.Sprintf("c38ren%02d", i)
		add("uid="+uid+","+c38OU, map[string][]string{"objectClass": person, "uid": {uid}, "cn": {uid}, "sn": {"S"}})
		newRDN := fmt.Sprintf(r.newRDN, uid)
		conn := as(r.subject)
		o := codeOutcome(conn.ModifyDN(ldap.NewModifyDNRequest("uid="+uid+","+c38OU, newRDN, r.del, "")))
		conn.Close()
		if o.Code == 0 && newRDN != "uid="+uid {
			created[0] = newRDN + "," + c38OU // newest first
		}
		record(o, r.want, fmt.Sprintf("%s modrdn %s del=%v", r.subject, newRDN, r.del))
	}
	for _, r := range []struct {
		note, subject, dn, newRDN, sup string
		want                           int
	}{
		{"missing source", "c38_star", "uid=ghost," + c38OU, "uid=ghost2", "", 50},
		{"onto existing", "c38_none", "uid=fa_bob," + c38OU, "uid=ord_b", "", 68},
		{"beneath itself", "c38_none", c38OU, "ou=probe-c38", "uid=fa_bob," + c38OU, 53},
	} {
		conn := as(r.subject)
		record(codeOutcome(conn.ModifyDN(ldap.NewModifyDNRequest(r.dn, r.newRDN, true, r.sup))), r.want, r.subject+" "+r.note)
		conn.Close()
	}
	for _, r := range []struct{ subject, filter, want string }{
		{"c38_neg", "(uid=fa_bob)", ""},
		{"c38_negmix", "(sn=S)", ""},
		{"c38_negdeny", "(uid=fa_bob)", "fa_bob"},
	} {
		conn := as(r.subject)
		o := searchOutcome(conn, c38OU, ldap.ScopeSingleLevel, 0, r.filter, []string{"1.1"})
		conn.Close()
		if got := fattrNames(o); o.Code != 0 || got != r.want {
			t.Errorf("%s %s %s: code %d [%s], oracle [%s]", e.name(), r.subject, r.filter, o.Code, got, r.want)
		}
		o.Note = r.subject + " " + r.filter
		out = append(out, o)
	}
	conn := as("c38_ad")
	addReq := ldap.NewAddRequest("uid=c38new,"+c38OU, nil)
	addReq.Attribute("objectClass", person)
	addReq.Attribute("uid", []string{"c38new"})
	addReq.Attribute("cn", []string{"c38new"})
	addReq.Attribute("sn", []string{"S"})
	record(codeOutcome(conn.Add(addReq)), 0, "c38_ad add with targetattr!=*")
	record(codeOutcome(conn.Del(ldap.NewDelRequest("uid=c38new,"+c38OU, nil))), 0, "c38_ad delete with targetattr!=*")
	conn.Close()
	for _, r := range []struct{ base, filter string }{
		{suffixDN, "(&)"}, {suffixDN, "(|)"}, {"", "(&)"}, {"cn=schema", "(|)"},
		{c38OU, "(!(&))"}, {c38OU, "(&(uid=fa_bob)(|))"}, {"uid=ghost," + suffixDN, "(&)"},
	} {
		for _, who := range []string{"dm", "c38_none"} {
			c := dm
			if who != "dm" {
				c = as(who)
			}
			record(searchOutcome(c, r.base, ldap.ScopeWholeSubtree, 0, r.filter, []string{"1.1"}), 2, fmt.Sprintf("%s search base %q %s", who, r.base, r.filter))
			if who != "dm" {
				c.Close()
			}
		}
	}
	clean := e.dm(t)
	defer clean.Close()
	for _, dn := range created {
		if err := clean.Del(ldap.NewDelRequest(dn, nil)); err != nil {
			t.Errorf("cleanup %s: %v", dn, err)
		}
	}
	return out
}

func TestNativeCand3638(t *testing.T) {
	fx := c38Fixture(t)
	native := startNative(t, fx)
	defer native.close(t)
	c38Outcomes(t, native)
}
