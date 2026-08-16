package ldapserver

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

const aciRuntimeDNA = "uid=labldap-runtime,ou=people,dc=example,dc=test"

func mustParseA(t *testing.T, text string) *ParsedACI {
	t.Helper()
	p, err := ParseACITextA(text)
	if err != nil {
		t.Fatalf("ParseACITextA(%q) failed: %v", text, err)
	}
	return p
}

func mustDNA(t *testing.T, s string) config.DN {
	t.Helper()
	d, err := config.ParseDN(s)
	if err != nil {
		t.Fatalf("config.ParseDN(%q): %v", s, err)
	}
	return d
}

func permsEqualA(got []Permission, want ...Permission) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// The four golden runtime ACIs the compiler emits (C8 runtime set).
func TestParseACITextARuntimeGolden(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "config", "testdata", "runtime-acis.txt"))
	if err != nil {
		t.Fatal(err)
	}
	type want struct {
		target  string
		mode    ACITargetAttrModeA
		attrs   []string
		perms   []Permission
		subject string
	}
	wants := map[string]want{
		"labldap:runtime-suffix-read": {
			target:  "dc=example,dc=test",
			mode:    ACITargetAttrDenyA,
			attrs:   []string{"userPassword"},
			perms:   []Permission{PermRead, PermSearch, PermCompare},
			subject: aciRuntimeDNA,
		},
		"labldap:runtime-people-write": {
			target:  "ou=people,dc=example,dc=test",
			mode:    ACITargetAttrDenyA,
			attrs:   []string{"aci"},
			perms:   []Permission{PermAdd, PermDelete, PermWrite, PermRead, PermSearch, PermCompare},
			subject: aciRuntimeDNA,
		},
		"labldap:runtime-groups-write": {
			target:  "ou=groups,dc=example,dc=test",
			mode:    ACITargetAttrDenyA,
			attrs:   []string{"aci"},
			perms:   []Permission{PermAdd, PermDelete, PermWrite, PermRead, PermSearch, PermCompare},
			subject: aciRuntimeDNA,
		},
		"labldap:runtime-password": {
			target:  "ou=people,dc=example,dc=test",
			mode:    ACITargetAttrAllowA,
			attrs:   []string{"userPassword"},
			perms:   []Permission{PermWrite},
			subject: aciRuntimeDNA,
		},
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("runtime-acis.txt has %d lines, want 4", len(lines))
	}
	for _, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) != 3 {
			t.Fatalf("golden line has %d fields: %q", len(fields), line)
		}
		id, target, text := fields[0], fields[1], fields[2]
		w, ok := wants[id]
		if !ok {
			t.Fatalf("unexpected golden ACI id %q", id)
		}
		p := mustParseA(t, text)
		if p.ID != id {
			t.Errorf("%s: ID = %q", id, p.ID)
		}
		if !p.TargetDN.Equal(mustDNA(t, target)) {
			t.Errorf("%s: TargetDN = %q, want %q", id, p.TargetDN.String(), target)
		}
		if p.AttrMode != w.mode {
			t.Errorf("%s: AttrMode = %s, want %s", id, p.AttrMode, w.mode)
		}
		if strings.Join(p.Attrs, ",") != strings.Join(w.attrs, ",") {
			t.Errorf("%s: Attrs = %v, want %v", id, p.Attrs, w.attrs)
		}
		if p.Deny {
			t.Errorf("%s: Deny set on an allow rule", id)
		}
		if !permsEqualA(p.Permissions, w.perms...) {
			t.Errorf("%s: Permissions = %v, want %v", id, p.Permissions, w.perms)
		}
		if p.Subject.Kind != ACISubjectUserDNA || !p.Subject.DN.Equal(mustDNA(t, w.subject)) {
			t.Errorf("%s: Subject = %s %q", id, p.Subject.Kind, p.Subject.DN.String())
		}
	}
}

// Operator ACLs come from the same compiler path as the runtime set; compile
// a scenario exercising every emission branch and parse the emitted text.
func TestParseACITextAOperatorGolden(t *testing.T) {
	scenario := []byte(`
apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata: { name: x }
spec:
  directory: { suffix: "dc=example,dc=test", allowRawACI: true }
  transport: { ldaps: { enabled: true, port: 3636 } }
  runtimeAccount: { id: rt, passwordFile: secrets/runtime-ldap }
  users:
    - id: alice
      passwordFile: secrets/user-alice
  groups:
    - id: staff
      members:
        - user: alice
  acls:
    - id: staff-read
      principal: { kind: group, ref: staff }
      target: { kind: suffix }
      permissions: [read, search, compare]
      attributes: { allow: ["*"], deny: [userPassword] }
    - id: alice-attr
      principal: { kind: user, ref: alice }
      target: { kind: entry, dn: "uid=alice,ou=people,dc=example,dc=test" }
      permissions: [write]
      attributes: { allow: [userPassword] }
    - id: world
      principal: { kind: anyone }
      target: { kind: groups }
      permissions: [read, search]
      attributes: {}
    - id: raw-pass
      # Raw text targets the suffix so the plan's Target matches the text.
      rawACI: '(target="ldap:///dc=example,dc=test")(targetattr="cn|sn")(version 3.0; acl "labldap:raw-pass"; deny (write) userdn="ldap:///self";)'
`)
	c, err := config.Compile(t.Context(), scenario, "aci-ops.yaml", config.LoadOptions{
		Caller: config.CallerCLI,
		Secrets: config.MapResolver{
			"secrets/runtime-ldap": "lab-fixture-runtime-password",
			"secrets/user-alice":   "lab-fixture-alice-password",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Data.ACIs) != 8 {
		t.Fatalf("compiled %d ACIs, want 4 runtime + 4 operator", len(c.Data.ACIs))
	}
	// Every emitted ACI, runtime or operator, must parse.
	parsed := map[string]*ParsedACI{}
	for _, a := range c.Data.ACIs {
		p, err := ParseACITextA(a.Text)
		if err != nil {
			t.Fatalf("compiled ACI %s failed to parse: %v\ntext: %s", a.ID, err, a.Text)
		}
		if p.ID != a.ID {
			t.Errorf("compiled ACI %s: parsed ID %q", a.ID, p.ID)
		}
		if !p.TargetDN.Equal(mustDNA(t, a.Target)) {
			t.Errorf("compiled ACI %s: parsed target %q, plan target %q", a.ID, p.TargetDN.String(), a.Target)
		}
		parsed[a.ID] = p
	}

	staff := parsed["labldap:staff-read"]
	if staff.Subject.Kind != ACISubjectGroupDNA {
		t.Fatalf("staff-read subject kind = %s, want groupdn", staff.Subject.Kind)
	}
	if !staff.Subject.DN.Equal(mustDNA(t, "cn=staff,ou=groups,dc=example,dc=test")) {
		t.Errorf("staff-read group DN = %q", staff.Subject.DN.String())
	}
	if staff.AttrMode != ACITargetAttrDenyA || !permsEqualA(staff.Permissions, PermRead, PermSearch, PermCompare) {
		t.Errorf("staff-read = %+v", staff)
	}

	alice := parsed["labldap:alice-attr"]
	if alice.Subject.Kind != ACISubjectUserDNA || !alice.Subject.DN.Equal(mustDNA(t, "uid=alice,ou=people,dc=example,dc=test")) {
		t.Errorf("alice-attr subject = %s %q", alice.Subject.Kind, alice.Subject.DN.String())
	}
	if alice.AttrMode != ACITargetAttrAllowA || len(alice.Attrs) != 1 || alice.Attrs[0] != "userPassword" {
		t.Errorf("alice-attr attrs = %s %v", alice.AttrMode, alice.Attrs)
	}

	world := parsed["labldap:world"]
	if world.Subject.Kind != ACISubjectAnyoneA {
		t.Errorf("world subject kind = %s, want anyone", world.Subject.Kind)
	}
	if world.AttrMode != ACITargetAttrAllA {
		t.Errorf("world attr mode = %s, want all (attributes {} emits targetattr=\"*\")", world.AttrMode)
	}

	raw := parsed["labldap:raw-pass"]
	if !raw.Deny {
		t.Errorf("raw-pass should be a deny rule")
	}
	if raw.AttrMode != ACITargetAttrAllowA || strings.Join(raw.Attrs, ",") != "cn,sn" {
		t.Errorf("raw-pass attrs = %s %v", raw.AttrMode, raw.Attrs)
	}
	if raw.Subject.Kind != ACISubjectSelfA {
		t.Errorf("raw-pass subject = %s, want self", raw.Subject.Kind)
	}
}

// Injection characters inside quoted productions are data, never clause
// syntax (C8). The compiler escapes ( ) " \ as \28 \29 \" \\.
func TestParseACITextAInjectionIsData(t *testing.T) {
	runtimeWho := `userdn="ldap:///` + aciRuntimeDNA + `"`
	tests := []struct {
		name   string
		target string // raw DN text inside the quoted target value
		wantDN string
	}{
		{"parens", `cn=a\28b\29,c=see,dc=example,dc=test`, "cn=a(b),c=see,dc=example,dc=test"},
		{"quote", `cn=a\"b,dc=example,dc=test`, `cn=a"b,dc=example,dc=test`},
		{"backslash", `cn=a\\b,dc=example,dc=test`, `cn=a\b,dc=example,dc=test`},
		// ACI-level \\ collapses to the DN-level \, which ParseDN then
		// resolves to a literal comma inside the RDN value.
		{"semicolon comma star", `cn=a;b*c,ou=peo\\,ple,dc=example,dc=test`, `cn=a;b*c,ou=peo\,ple,dc=example,dc=test`},
		{"fake clause in DN", `cn=x\22; deny (write) userdn=\22ldap:///uid=hax,dc=example,dc=test`, `cn=x"; deny (write) userdn="ldap:///uid=hax,dc=example,dc=test`},
		{"newline escape", `cn=a\0ab,dc=example,dc=test`, "cn=a\nb,dc=example,dc=test"},
		{"uppercase hex escape", `cn=a\0Ab,dc=example,dc=test`, "cn=a\nb,dc=example,dc=test"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			text := `(target="ldap:///` + tc.target + `")(targetattr="*")(version 3.0; acl "labldap:inj"; allow (read,search) ` + runtimeWho + `;)`
			p := mustParseA(t, text)
			if !p.TargetDN.Equal(mustDNA(t, tc.wantDN)) {
				t.Errorf("TargetDN = %q, want %q", p.TargetDN.String(), tc.wantDN)
			}
			// The injected text must not have produced extra permissions or a
			// different subject.
			if !permsEqualA(p.Permissions, PermRead, PermSearch) {
				t.Errorf("Permissions = %v (injection created clauses?)", p.Permissions)
			}
			if p.Deny || p.Subject.Kind != ACISubjectUserDNA || !p.Subject.DN.Equal(mustDNA(t, aciRuntimeDNA)) {
				t.Errorf("Deny=%v Subject=%s %q (injection changed the rule?)", p.Deny, p.Subject.Kind, p.Subject.DN.String())
			}
			if p.ID != "labldap:inj" {
				t.Errorf("ID = %q", p.ID)
			}
		})
	}
}

// The same injection discipline applies to targetattr and the acl name.
func TestParseACITextAAttrAndNameData(t *testing.T) {
	p := mustParseA(t, `(target="ldap:///dc=example,dc=test")(targetattr="userCertificate;binary")(version 3.0; acl "labldap:opt"; allow (read) userdn="ldap:///all";)`)
	if p.AttrMode != ACITargetAttrAllowA || len(p.Attrs) != 1 || p.Attrs[0] != "userCertificate;binary" {
		t.Errorf("attr with option: %s %v", p.AttrMode, p.Attrs)
	}
	if p.Subject.Kind != ACISubjectAllA {
		t.Errorf("subject = %s, want all", p.Subject.Kind)
	}

	p = mustParseA(t, `(target="ldap:///dc=example,dc=test")(version 3.0; acl "name with spaces: ok"; deny (delete) groupdn="ldap:///cn=staff,ou=groups,dc=example,dc=test";)`)
	if p.ID != "name with spaces: ok" || !p.Deny {
		t.Errorf("ID=%q Deny=%v", p.ID, p.Deny)
	}
	if p.Subject.Kind != ACISubjectGroupDNA {
		t.Errorf("subject = %s, want groupdn", p.Subject.Kind)
	}
	// Missing targetattr means all attributes (389 semantics).
	if p.AttrMode != ACITargetAttrAllA || !p.TargetsAttr("anything") {
		t.Errorf("omitted targetattr should mean all attributes, got %s", p.AttrMode)
	}
}

func TestParseACITextAKeywordCase(t *testing.T) {
	p := mustParseA(t, `(TARGET="LDAP:///dc=example,dc=test")(TARGETATTR="UID|CN")(Version 3.0; ACL "labldap:case"; ALLOW (READ,Search) USERDN="LDAP:///ANYONE";)`)
	if !p.TargetDN.Equal(mustDNA(t, "dc=example,dc=test")) {
		t.Errorf("TargetDN = %q", p.TargetDN.String())
	}
	if p.AttrMode != ACITargetAttrAllowA || strings.Join(p.Attrs, ",") != "UID,CN" {
		t.Errorf("attrs = %s %v", p.AttrMode, p.Attrs)
	}
	if !permsEqualA(p.Permissions, PermRead, PermSearch) {
		t.Errorf("perms = %v", p.Permissions)
	}
	if p.Subject.Kind != ACISubjectAnyoneA {
		t.Errorf("subject = %s, want anyone", p.Subject.Kind)
	}
	// Attribute lookup is case-insensitive regardless of emission case.
	if !p.TargetsAttr("uid") || !p.TargetsAttr("cn") || p.TargetsAttr("sn") {
		t.Error("TargetsAttr case folding wrong")
	}
}

func TestParseACITextAHelpers(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "config", "testdata", "runtime-acis.txt"))
	if err != nil {
		t.Fatal(err)
	}
	var suffixRead, password *ParsedACI
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		fields := strings.Split(line, "\t")
		switch fields[0] {
		case "labldap:runtime-suffix-read":
			suffixRead = mustParseA(t, fields[2])
		case "labldap:runtime-password":
			password = mustParseA(t, fields[2])
		}
	}
	if suffixRead.TargetsAttr("userpassword") {
		t.Error("suffix-read must not target userPassword")
	}
	if !suffixRead.TargetsAttr("uid") {
		t.Error("suffix-read must target uid")
	}
	if suffixRead.HasPerm(PermAdd) || !suffixRead.HasPerm(PermRead) {
		t.Error("suffix-read perms wrong")
	}
	if !password.TargetsAttr("userPassword") || password.TargetsAttr("uid") {
		t.Error("password ACI targets only userPassword")
	}
}

func TestParseACITextARejects(t *testing.T) {
	validPrefix := `(target="ldap:///dc=example,dc=test")(targetattr="*")`
	validBody := `(version 3.0; acl "labldap:x"; allow (read) userdn="ldap:///all";)`
	bigAttr := strings.Repeat("a", 64)
	tests := []struct {
		name string
		text string
	}{
		{"empty", ""},
		{"oversize", validPrefix + validBody + strings.Repeat(" ", MaxACITextBytesA)},
		{"missing body", validPrefix},
		{"missing target", validBody},
		{"unknown clause targetfilter", `(targetfilter="(uid=x)")` + validPrefix + validBody},
		{"unknown clause ip", validPrefix + validBody[:len(validBody)-1] + `)(ip="127.0.0.1")`},
		{"389-only targattrfilters", `(targattrfilters="add=cn")` + validPrefix + validBody},
		{"unknown permission", `(target="ldap:///dc=example,dc=test")(version 3.0; acl "x"; allow (read,proxy) userdn="ldap:///all";)`},
		{"389 perm 'all' out of subset", `(target="ldap:///dc=example,dc=test")(version 3.0; acl "x"; allow (all) userdn="ldap:///all";)`},
		{"empty permission list", `(target="ldap:///dc=example,dc=test")(version 3.0; acl "x"; allow () userdn="ldap:///all";)`},
		{"trailing comma in perms", `(target="ldap:///dc=example,dc=test")(version 3.0; acl "x"; allow (read,) userdn="ldap:///all";)`},
		{"missing version keyword", `(target="ldap:///dc=example,dc=test")(acl "x"; allow (read) userdn="ldap:///all";)`},
		{"wrong version", `(target="ldap:///dc=example,dc=test")(version 2.0; acl "x"; allow (read) userdn="ldap:///all";)`},
		{"missing acl keyword", `(target="ldap:///dc=example,dc=test")(version 3.0; allow (read) userdn="ldap:///all";)`},
		{"missing acl id", `(target="ldap:///dc=example,dc=test")(version 3.0; acl; allow (read) userdn="ldap:///all";)`},
		{"empty acl id", `(target="ldap:///dc=example,dc=test")(version 3.0; acl ""; allow (read) userdn="ldap:///all";)`},
		{"acl id with control char", `(target="ldap:///dc=example,dc=test")(version 3.0; acl "a\09b"; allow (read) userdn="ldap:///all";)`},
		{"missing action", `(target="ldap:///dc=example,dc=test")(version 3.0; acl "x"; (read) userdn="ldap:///all";)`},
		{"malformed userdn no url", `(target="ldap:///dc=example,dc=test")(version 3.0; acl "x"; allow (read) userdn="dc=example,dc=test";)`},
		{"userdn wrong scheme", `(target="ldap:///dc=example,dc=test")(version 3.0; acl "x"; allow (read) userdn="http:///dc=example,dc=test";)`},
		{"userdn host part", `(target="ldap:///dc=example,dc=test")(version 3.0; acl "x"; allow (read) userdn="ldap://host/dc=example,dc=test";)`},
		{"userdn empty", `(target="ldap:///dc=example,dc=test")(version 3.0; acl "x"; allow (read) userdn="ldap:///";)`},
		{"userdn not a dn", `(target="ldap:///dc=example,dc=test")(version 3.0; acl "x"; allow (read) userdn="ldap:///not a dn";)`},
		{"userdn unquoted", `(target="ldap:///dc=example,dc=test")(version 3.0; acl "x"; allow (read) userdn=ldap:///dc=example,dc=test;)`},
		{"groupdn keyword", `(target="ldap:///dc=example,dc=test")(version 3.0; acl "x"; allow (read) groupdn="ldap:///all";)`},
		{"boolean combinator", `(target="ldap:///dc=example,dc=test")(version 3.0; acl "x"; allow (read) userdn="ldap:///all" or userdn="ldap:///self";)`},
		{"unterminated quote", `(target="ldap:///dc=example,dc=test)(version 3.0; acl "x"; allow (read) userdn="ldap:///all";)`},
		{"unterminated paren", `(target="ldap:///dc=example,dc=test")(version 3.0; acl "x"; allow (read) userdn="ldap:///all";`},
		{"dangling escape", `(target="ldap:///dc=example,dc=test\`},
		{"invalid escape", `(target="ldap:///dc=example,dc=\qtest")(version 3.0; acl "x"; allow (read) userdn="ldap:///all";)`},
		{"single hex digit", `(target="ldap:///dc=example,dc=\2test")(version 3.0; acl "x"; allow (read) userdn="ldap:///all";)`},
		{"nul escape", `(target="ldap:///dc=\00")(version 3.0; acl "x"; allow (read) userdn="ldap:///all";)`},
		{"trailing garbage", validPrefix + validBody + ` garbage`},
		{"stray rparen", validPrefix + validBody + `)`},
		{"duplicate target", validPrefix + validPrefix + validBody},
		{"duplicate body", validPrefix + validBody + validBody},
		{"duplicate targetattr", `(target="ldap:///dc=example,dc=test")(targetattr="uid")(targetattr="cn")` + validBody},
		{"target without url", `(target="dc=example,dc=test")` + validBody},
		{"target keyword", `(target="ldap:///all")` + validBody},
		{"targetattr empty", `(target="ldap:///dc=example,dc=test")(targetattr="")` + validBody},
		{"targetattr empty segment", `(target="ldap:///dc=example,dc=test")(targetattr="uid|")` + validBody},
		{"targetattr star mixed", `(target="ldap:///dc=example,dc=test")(targetattr="*|uid")` + validBody},
		{"targetattr star deny", `(target="ldap:///dc=example,dc=test")(targetattr!="*")` + validBody},
		{"targetattr bad char", `(target="ldap:///dc=example,dc=test")(targetattr="user Password")` + validBody},
		{"targetattr oversized name", `(target="ldap:///dc=example,dc=test")(targetattr="1` + bigAttr + `")` + validBody},
		{"targetattr bang without equals", `(target="ldap:///dc=example,dc=test")(targetattr!"uid")` + validBody},
		{"bang in body", `(target="ldap:///dc=example,dc=test")(version 3.0; acl "x"; allow ! (read) userdn="ldap:///all";)`},
		{"missing semi after version", `(target="ldap:///dc=example,dc=test")(version 3.0 acl "x"; allow (read) userdn="ldap:///all";)`},
		{"missing semi after bind rule", `(target="ldap:///dc=example,dc=test")(version 3.0; acl "x"; allow (read) userdn="ldap:///all")`},
		{"extra semi garbage", validPrefix + `(version 3.0; acl "x"; allow (read) userdn="ldap:///all";;)`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ParseACITextA(tc.text)
			if err == nil {
				t.Fatalf("parsed %+v, want error", p)
			}
			if !errors.Is(err, ErrACIParseA) {
				t.Fatalf("error %v does not wrap ErrACIParseA", err)
			}
			var pe *ACIParseErrorA
			if !errors.As(err, &pe) {
				t.Fatalf("error %T is not *ACIParseErrorA", err)
			}
			if pe.Offset < 0 {
				t.Errorf("negative offset %d", pe.Offset)
			}
			// Stable: same input, identical message.
			if _, err2 := ParseACITextA(tc.text); err2 == nil || err2.Error() != err.Error() {
				t.Errorf("error not stable: %q vs %q", err, err2)
			}
		})
	}
}

// Errors must not leak quoted-string contents (C8 stable, secret-free).
func TestParseACITextAErrorOmitsQuotedData(t *testing.T) {
	marker := "cn=topsecret-marker-value,dc=example,dc=test"
	// The marker sits in a quoted target; the failure is the unknown clause.
	text := `(target="ldap:///` + marker + `")(roledn="ldap:///cn=x")(version 3.0; acl "x"; allow (read) userdn="ldap:///all";)`
	_, err := ParseACITextA(text)
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), "topsecret-marker-value") {
		t.Errorf("error embeds quoted DN data: %q", err.Error())
	}
}

func TestParseACITextABounds(t *testing.T) {
	valid := `(target="ldap:///dc=example,dc=test")(version 3.0; acl "x"; allow (read) userdn="ldap:///all";)`
	if len(valid) >= MaxACITextBytesA {
		t.Fatal("test premise broken")
	}
	if _, err := ParseACITextA(strings.Repeat("(", MaxACITextBytesA+1)); err == nil {
		t.Error("oversize input accepted")
	}
	// Deeply nested parens cannot stack-overflow: the parser is iterative
	// over a flat token stream, so this is just an unknown-clause error.
	nested := strings.Repeat("(", 4096) + strings.Repeat(")", 4096)
	if _, err := ParseACITextA(nested); !errors.Is(err, ErrACIParseA) {
		t.Errorf("nested parens: %v", err)
	}
}

func FuzzParseACITextA(f *testing.F) {
	seeds := []string{
		`(target="ldap:///dc=example,dc=test")(targetattr!="userPassword")(version 3.0; acl "labldap:runtime-suffix-read"; allow (read,search,compare) userdn="ldap:///uid=labldap-runtime,ou=people,dc=example,dc=test";)`,
		`(target="ldap:///ou=people,dc=example,dc=test")(targetattr="userPassword")(version 3.0; acl "labldap:runtime-password"; allow (write) userdn="ldap:///uid=labldap-runtime,ou=people,dc=example,dc=test";)`,
		`(target="ldap:///dc=example,dc=test")(targetattr="*")(version 3.0; acl "labldap:staff-read"; allow (read,search,compare) groupdn="ldap:///cn=staff,ou=groups,dc=example,dc=test";)`,
		`(target="ldap:///ou=people,dc=example,dc=test")(targetattr="cn|sn")(version 3.0; acl "labldap:raw-pass"; deny (write) userdn="ldap:///self";)`,
		`(target="ldap:///cn=a\28b\29,dc=example,dc=test")(version 3.0; acl "x"; allow (add) userdn="ldap:///anyone";)`,
		`(target="ldap:///dc=example,dc=test")(version 3.0; acl "x"; allow (read) userdn="ldap:///all";)`,
		``,
		`(`,
		`(target=`,
		`(target="ldap:///dc=example,dc=test"`,
		`(version 2.0; acl "x"; allow (all) userdn="ldap:///all";)`,
		`garbage`,
		`(targetattr="*|uid")`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		// Must never panic; error vs success is the grammar's decision.
		if _, err := ParseACITextA(text); err != nil && !errors.Is(err, ErrACIParseA) {
			t.Fatalf("error %v does not wrap ErrACIParseA", err)
		}
	})
}
