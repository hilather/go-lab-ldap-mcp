//go:build integration

package dirsrv

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

const (
	runtimeBindDN   = "uid=rt,ou=people,dc=example,dc=test"
	runtimeBindPass = "runtime-secret"
	runtimePeopleDN = "ou=people,dc=example,dc=test"
	runtimeGroupsDN = "ou=groups,dc=example,dc=test"
	runtimeSuffix   = "dc=example,dc=test"
)

// engineDial is the engine-neutral LDAP endpoint. C12/C13 helpers use this
// — never docker exec — so native and 389 share one host-LDAP code path.
type engineDial struct {
	engine     string // Engine389DS | EngineNative
	ldapAddr   string
	ldapsAddr  string
	caFile     string
	serverName string
	dmPassword string
}

// runtimeYAML is the single compiled scenario for startRuntimeEnv on both
// engines. Unifying 389 onto this tree (history + lockout, no extra seeds)
// is an accepted IT change; tests Add their own users and must not re-set
// the same password unless they are the D20 case.
func runtimeYAML() string {
	return `apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata: { name: runtime }
spec:
  directory: { suffix: "dc=example,dc=test" }
  transport: { ldaps: { enabled: true, port: 3636 }, startTLS: true }
  runtimeAccount: { id: rt, passwordFile: secrets/runtime-ldap }
  passwordPolicy:
    minLength: 12
    historyCount: 4
    maxAge: 0s
    warningAge: 0s
    lockout: { enabled: true, maxFailures: 5, lockoutDuration: 60s }
    storageScheme: PBKDF2-SHA256
`
}

func nativeDial(n *nativeInstance) engineDial {
	return engineDial{
		engine:     EngineNative,
		ldapAddr:   n.LDAPAddr,
		ldapsAddr:  n.LDAPSAddr,
		caFile:     n.CAFile,
		serverName: n.ServerName,
		dmPassword: n.dmPassword,
	}
}

// Dial returns a host-LDAP endpoint for the running 389 container. The
// instance self-signed CA plus container hostname is the same trust path
// startRuntimeEnv already used for the runtime pool.
func (i *Instance) Dial(t *testing.T) engineDial {
	t.Helper()
	if i.hostDial != nil && i.hostDial.ldapsAddr == i.LDAPSAddr {
		return *i.hostDial
	}
	ca := filepath.Join(t.TempDir(), "ca.crt")
	i.WriteCA(t, ca)
	d := engineDial{
		engine:     Engine389DS,
		ldapAddr:   i.LDAPAddr,
		ldapsAddr:  i.LDAPSAddr,
		caFile:     ca,
		serverName: i.Hostname(t),
		dmPassword: i.Password().Reveal(),
	}
	i.hostDial = &d
	return d
}

// startEngine stages the selected engine from yaml: native via startNative,
// 389 via the pinned container plus in-container apply of that same yaml.
func startEngine(t *testing.T, yaml string) engineDial {
	t.Helper()
	if itEngine(t) == EngineNative {
		return nativeDial(startNative(t, yaml))
	}
	inst := Start(t)
	_, guest := stageSeedApply(t, inst, yaml, seedCanary)
	if out, err := execApply(t, inst, guest, nil); err != nil {
		t.Fatalf("apply: %v\n%s", err, redactLogs(out, seedCanary, inst.password))
	}
	return inst.Dial(t)
}

func (d engineDial) tlsConfig() (*tls.Config, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: d.serverName}
	if d.caFile == "" {
		return tc, nil
	}
	pem, err := os.ReadFile(d.caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates in %s", d.caFile)
	}
	tc.RootCAs = pool
	return tc, nil
}

func (d engineDial) connect() (*ldap.Conn, error) {
	tc, err := d.tlsConfig()
	if err != nil {
		return nil, err
	}
	return ldap.DialURL("ldaps://"+d.ldapsAddr, ldap.DialWithTLSConfig(tc))
}

func (d engineDial) bind(bindDN, password string) (*ldap.Conn, error) {
	conn, err := d.connect()
	if err != nil {
		return nil, err
	}
	if err := conn.Bind(bindDN, password); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (d engineDial) dm() (*ldap.Conn, error) {
	return d.bind("cn=Directory Manager", d.dmPassword)
}

func (d engineDial) dmMust(t *testing.T) *ldap.Conn {
	t.Helper()
	conn, err := d.dm()
	if err != nil {
		t.Fatalf("dm bind: %v", err)
	}
	return conn
}

func ldapSearch(t *testing.T, d engineDial, dn string, attrs ...string) string {
	t.Helper()
	return ldapSearchScope(t, d, dn, ldap.ScopeBaseObject, "(objectClass=*)", attrs...)
}

func ldapSearchAllowMissing(t *testing.T, d engineDial, dn string) string {
	t.Helper()
	conn, err := d.dm()
	if err != nil {
		return err.Error()
	}
	defer conn.Close()
	req := ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"dn"}, nil)
	res, err := conn.Search(req)
	if err != nil {
		return err.Error()
	}
	return formatSearchLDIF(res.Entries, []string{"dn"})
}

func ldapSearchChildren(t *testing.T, d engineDial, base string) string {
	t.Helper()
	return ldapSearchScope(t, d, base, ldap.ScopeSingleLevel, "(objectClass=*)", "dn")
}

func ldapSearchFilter(t *testing.T, d engineDial, base, filter string) string {
	t.Helper()
	return ldapSearchScope(t, d, base, ldap.ScopeWholeSubtree, filter, "dn")
}

func ldapSearchScope(t *testing.T, d engineDial, base string, scope int, filter string, attrs ...string) string {
	t.Helper()
	conn := d.dmMust(t)
	defer conn.Close()
	if filter == "" {
		filter = "(objectClass=*)"
	}
	req := ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, 0, 0, false, filter, attrs, nil)
	res, err := conn.Search(req)
	if err != nil {
		t.Fatalf("ldapsearch %s: %v", base, err)
	}
	return formatSearchLDIF(res.Entries, attrs)
}

func formatSearchLDIF(entries []*ldap.Entry, attrs []string) string {
	var b strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&b, "dn: %s\n", e.DN)
		names := attrs
		if len(names) == 0 {
			for _, a := range e.Attributes {
				names = append(names, a.Name)
			}
		}
		for _, name := range names {
			if strings.EqualFold(name, "dn") {
				continue
			}
			for _, v := range e.GetAttributeValues(name) {
				fmt.Fprintf(&b, "%s: %s\n", name, v)
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func userBind(t *testing.T, d engineDial, dn, password string) error {
	t.Helper()
	conn, err := d.bind(dn, password)
	if err != nil {
		t.Logf("bind %s: %v", dn, err)
		return err
	}
	_ = conn.Close()
	return nil
}

func runtimeBind(t *testing.T, d engineDial, dn, password string) error {
	t.Helper()
	return userBind(t, d, dn, password)
}

func addExtraPerson(t *testing.T, d engineDial, dn string) {
	t.Helper()
	conn := d.dmMust(t)
	defer conn.Close()
	req := ldap.NewAddRequest(dn, nil)
	req.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"})
	req.Attribute("cn", []string{"extra"})
	req.Attribute("sn", []string{"extra"})
	req.Attribute("uid", []string{"extra"})
	if err := conn.Add(req); err != nil {
		t.Fatalf("ldapadd extra: %v", err)
	}
}

func addUserDescription(t *testing.T, d engineDial, dn, value string) {
	t.Helper()
	conn := d.dmMust(t)
	defer conn.Close()
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Add("description", []string{value})
	if err := conn.Modify(mod); err != nil {
		t.Fatalf("ldapmodify description: %v", err)
	}
}

func runtimeReplace(t *testing.T, d engineDial, dn, attr, value string) {
	t.Helper()
	conn, err := d.bind(runtimeBindDN, runtimeBindPass)
	if err != nil {
		t.Fatalf("runtime bind: %v", err)
	}
	defer conn.Close()
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Replace(attr, []string{value})
	if err := conn.Modify(mod); err != nil {
		t.Fatalf("direct ldap replace %s: %v", attr, err)
	}
}

func addPluginProbe(t *testing.T, d engineDial) {
	t.Helper()
	conn := d.dmMust(t)
	defer conn.Close()
	alice := ldap.NewAddRequest("uid=alice,"+runtimeSuffix, nil)
	alice.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"})
	alice.Attribute("cn", []string{"alice"})
	alice.Attribute("sn", []string{"alice"})
	alice.Attribute("uid", []string{"alice"})
	alice.Attribute("userPassword", []string{"AlicePass12"})
	if err := conn.Add(alice); err != nil {
		t.Fatalf("ldapadd alice: %v", err)
	}
	bob := ldap.NewAddRequest("uid=bob,"+runtimeSuffix, nil)
	bob.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"})
	bob.Attribute("cn", []string{"bob"})
	bob.Attribute("sn", []string{"bob"})
	bob.Attribute("uid", []string{"bob"})
	bob.Attribute("userPassword", []string{"BobPass1234"})
	if err := conn.Add(bob); err != nil {
		t.Fatalf("ldapadd bob: %v", err)
	}
	staff := ldap.NewAddRequest("cn=staff,"+runtimeSuffix, nil)
	staff.Attribute("objectClass", []string{"top", "groupOfNames"})
	staff.Attribute("cn", []string{"staff"})
	staff.Attribute("member", []string{"uid=alice," + runtimeSuffix})
	if err := conn.Add(staff); err != nil {
		t.Fatalf("ldapadd staff: %v", err)
	}
}

func lockAccount(t *testing.T, d engineDial, dn string) {
	t.Helper()
	conn := d.dmMust(t)
	defer conn.Close()
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Replace("nsAccountLock", []string{"true"})
	if err := conn.Modify(mod); err != nil {
		t.Fatalf("lock %s: %v", dn, err)
	}
}

func ldapDelete(t *testing.T, d engineDial, dn string) {
	t.Helper()
	conn := d.dmMust(t)
	defer conn.Close()
	if err := conn.Del(ldap.NewDelRequest(dn, nil)); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
		t.Fatalf("ldapdelete %s: %v", dn, err)
	}
}

func replaceGroupMembers(t *testing.T, d engineDial, dn string, members ...string) {
	t.Helper()
	conn := d.dmMust(t)
	defer conn.Close()
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Replace("member", members)
	if err := conn.Modify(mod); err != nil {
		t.Fatalf("replace members %s: %v", dn, err)
	}
}

func deleteNamedACI(t *testing.T, d engineDial, target, name string) {
	t.Helper()
	conn := d.dmMust(t)
	defer conn.Close()
	req := ldap.NewSearchRequest(target, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"aci"}, nil)
	res, err := conn.Search(req)
	if err != nil || len(res.Entries) == 0 {
		t.Fatalf("search aci %s: %v", target, err)
	}
	var text string
	for _, v := range res.Entries[0].GetAttributeValues("aci") {
		if strings.Contains(v, name) {
			text = v
			break
		}
	}
	if text == "" {
		t.Fatalf("named ACI %s not found in %s:\n%s", name, target, formatSearchLDIF(res.Entries, []string{"aci"}))
	}
	mod := ldap.NewModifyRequest(target, nil)
	mod.Delete("aci", []string{text})
	if err := conn.Modify(mod); err != nil {
		t.Fatalf("delete aci %s: %v", name, err)
	}
}

func addProbeUser(t *testing.T, d engineDial, password string) {
	t.Helper()
	conn := d.dmMust(t)
	defer conn.Close()
	req := ldap.NewAddRequest("uid=pwprobe,"+runtimePeopleDN, nil)
	req.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"})
	req.Attribute("cn", []string{"probe"})
	req.Attribute("sn", []string{"probe"})
	req.Attribute("uid", []string{"pwprobe"})
	req.Attribute("userPassword", []string{password})
	if err := conn.Add(req); err != nil {
		t.Fatalf("ldapadd: %v", err)
	}
}

func allowSelfPassword(t *testing.T, d engineDial) {
	t.Helper()
	conn := d.dmMust(t)
	defer conn.Close()
	mod := ldap.NewModifyRequest(runtimeSuffix, nil)
	mod.Add("aci", []string{`(target="ldap:///dc=example,dc=test")(targetattr="userPassword")(version 3.0; acl "self-pwd"; allow (write) userdn="ldap:///self";)`})
	if err := conn.Modify(mod); err != nil {
		t.Fatalf("aci: %v", err)
	}
}

func userPasswd(t *testing.T, d engineDial, dn, old, neu string) (string, error) {
	t.Helper()
	// Confirm the current secret still binds, then replace as the runtime
	// account (labldap:runtime-password). Self-write is not used: native
	// suffix ACIs do not inherit like 389, and DM bypasses history (D29).
	if err := userBind(t, d, dn, old); err != nil {
		return err.Error(), err
	}
	conn, err := d.bind(runtimeBindDN, runtimeBindPass)
	if err != nil {
		return err.Error(), err
	}
	defer conn.Close()
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Replace("userPassword", []string{neu})
	if err := conn.Modify(mod); err != nil {
		return err.Error(), err
	}
	return "", nil
}

// treeYAML is the minimal suffix+runtime scenario (no extra seeds, no
// password policy) used by effect-level plugin tests that Add their own
// probe entries at the suffix root.
func treeYAML() string {
	return `apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata: { name: tree }
spec:
  directory: { suffix: "dc=example,dc=test" }
  transport: { ldaps: { enabled: true, port: 3636 } }
  runtimeAccount: { id: rt, passwordFile: secrets/runtime-ldap }
`
}

func (d engineDial) secret() observability.Secret {
	return observability.Secret(d.dmPassword)
}
