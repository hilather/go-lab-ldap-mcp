package ldapserver

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// runtimeGoldenB reads the compiler golden runtime ACI file (C8 names it as
// the canonical fixture) and returns one record per line.
func runtimeGoldenB(t *testing.T) [][3]string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "config", "testdata", "runtime-acis.txt"))
	if err != nil {
		t.Fatalf("read runtime-acis.txt: %v", err)
	}
	var out [][3]string
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		parts := strings.Split(line, "\t")
		if len(parts) != 3 {
			t.Fatalf("golden line has %d tab fields, want 3: %q", len(parts), line)
		}
		out = append(out, [3]string{parts[0], parts[1], parts[2]})
	}
	if len(out) != 4 {
		t.Fatalf("golden file has %d ACIs, want the four labldap:runtime-* lines", len(out))
	}
	return out
}

func attrsEqualB(got ACIAttrsB, all, except bool, names ...string) bool {
	return got.All == all && got.Except == except && slices.Equal(got.Names, names)
}

func TestParseACITextBRuntimeGolden(t *testing.T) {
	runtimeDN := "uid=labldap-runtime,ou=people,dc=example,dc=test"
	wants := map[string]struct {
		attrs ACIAttrsB
		perms []Permission
	}{
		"labldap:runtime-suffix-read": {
			attrs: ACIAttrsB{Except: true, Names: []string{"userpassword"}},
			perms: []Permission{PermRead, PermSearch, PermCompare},
		},
		"labldap:runtime-people-write": {
			attrs: ACIAttrsB{Except: true, Names: []string{"aci"}},
			perms: []Permission{PermAdd, PermDelete, PermWrite, PermRead, PermSearch, PermCompare},
		},
		"labldap:runtime-groups-write": {
			attrs: ACIAttrsB{Except: true, Names: []string{"aci"}},
			perms: []Permission{PermAdd, PermDelete, PermWrite, PermRead, PermSearch, PermCompare},
		},
		"labldap:runtime-password": {
			attrs: ACIAttrsB{Names: []string{"userpassword"}},
			perms: []Permission{PermWrite},
		},
	}
	for _, rec := range runtimeGoldenB(t) {
		id, target, text := rec[0], rec[1], rec[2]
		p, err := ParseACITextB(text)
		if err != nil {
			t.Fatalf("%s: parse failed: %v\ntext: %s", id, err, text)
		}
		want, ok := wants[id]
		if !ok {
			t.Fatalf("unexpected golden ACI id %q", id)
		}
		if p.ID != id {
			t.Errorf("%s: ID = %q", id, p.ID)
		}
		if p.TargetDN.String() != target {
			t.Errorf("%s: TargetDN = %q, want %q", id, p.TargetDN.String(), target)
		}
		if !attrsEqualB(p.Attrs, want.attrs.All, want.attrs.Except, want.attrs.Names...) {
			t.Errorf("%s: Attrs = %+v, want %+v", id, p.Attrs, want.attrs)
		}
		if !slices.Equal(p.Permissions, want.perms) {
			t.Errorf("%s: Permissions = %v, want %v", id, p.Permissions, want.perms)
		}
		if p.Deny {
			t.Errorf("%s: runtime ACIs are allow ACIs", id)
		}
		if p.Subject.Kind != ACISubjectDNB || p.Subject.DN.String() != runtimeDN {
			t.Errorf("%s: Subject = %v %q", id, p.Subject.Kind, p.Subject.DN.String())
		}
	}

	// Spot-check the evaluator-facing helpers on the parsed golden set.
	p, err := ParseACITextB(runtimeGoldenB(t)[0][2])
	if err != nil {
		t.Fatal(err)
	}
	if !p.HasPermission(PermRead) || p.HasPermission(PermWrite) {
		t.Errorf("runtime-suffix-read permission set wrong: %v", p.Permissions)
	}
	if !p.Attrs.Includes("cn") || !p.Attrs.Includes("CN") {
		t.Error("targetattr!= should cover cn case-insensitively")
	}
	if p.Attrs.Includes("userPassword") || p.Attrs.Includes("USERPASSWORD") {
		t.Error("targetattr!=userPassword must exclude userPassword")
	}
}

// TestParseACITextBCompilerOperatorACIs compiles an operator scenario with
// group, user, and attribute-filtered ACLs (including an id full of
// injection characters) and parses every emitted ACI text.
func TestParseACITextBCompilerOperatorACIs(t *testing.T) {
	src := []byte(`
apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata: { name: x }
spec:
  directory: { suffix: "dc=example,dc=test" }
  transport: { ldaps: { enabled: true, port: 3636 } }
  runtimeAccount: { id: rt, passwordFile: secrets/runtime-ldap }
  users:
    - id: 'evil")('
      passwordFile: secrets/user-alice
    - id: bob
      passwordFile: secrets/user-alice
  groups:
    - id: staff
      members: [{ user: bob }]
  acls:
    - id: staff-read
      principal: { kind: group, ref: staff }
      target: { kind: suffix }
      permissions: [read, search]
    - id: evil-write
      principal: { kind: user, ref: 'evil")(' }
      target: { kind: entry, dn: "ou=people,dc=example,dc=test" }
      permissions: [write]
      attributes: { allow: [description] }
    - id: suffix-nopw
      principal: { kind: group, ref: staff }
      target: { kind: suffix }
      permissions: [read, search, compare]
      attributes: { deny: [userPassword] }
`)
	c, err := config.Compile(t.Context(), src, "aci-parse-b.yaml", config.LoadOptions{
		Caller: config.CallerCLI,
		Secrets: config.MapResolver{
			"secrets/runtime-ldap": "lab-fixture-runtime-password",
			"secrets/user-alice":   "lab-fixture-alice-password",
		},
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if got, want := len(c.Data.ACIs), 7; got != want {
		t.Fatalf("compiled %d ACIs, want %d (4 runtime + 3 operator)", got, want)
	}
	byID := map[string]*ParsedACIB{}
	for _, a := range c.Data.ACIs {
		p, err := ParseACITextB(a.Text)
		if err != nil {
			t.Fatalf("%s: compiler output must parse: %v\ntext: %s", a.ID, err, a.Text)
		}
		if p.ID != a.ID {
			t.Errorf("%s: parsed ID = %q", a.ID, p.ID)
		}
		if p.TargetDN.String() != a.Target {
			t.Errorf("%s: TargetDN = %q, want %q", a.ID, p.TargetDN.String(), a.Target)
		}
		if _, dup := byID[p.ID]; dup {
			t.Errorf("%s parsed twice", p.ID)
		}
		byID[p.ID] = p
	}

	staff := byID["labldap:staff-read"]
	if staff == nil || staff.Subject.Kind != ACISubjectGroupB {
		t.Fatalf("staff-read subject = %+v", staff)
	}
	if got := staff.Subject.DN.String(); got != c.Normalized.Groups[0].DN {
		t.Errorf("staff-read groupdn = %q, want %q", got, c.Normalized.Groups[0].DN)
	}
	if !slices.Equal(staff.Permissions, []Permission{PermRead, PermSearch}) {
		t.Errorf("staff-read perms = %v", staff.Permissions)
	}
	if !staff.Attrs.All {
		t.Errorf("staff-read without attributes filter must be All: %+v", staff.Attrs)
	}

	evil := byID["labldap:evil-write"]
	if evil == nil || evil.Subject.Kind != ACISubjectDNB {
		t.Fatalf("evil-write subject = %+v", evil)
	}
	attr, val, ok := evil.Subject.DN.Leaf()
	if !ok || attr != "uid" || val != `evil")(` {
		t.Errorf("evil-write subject leaf = %q=%q ok=%v; injection chars must survive as data", attr, val, ok)
	}
	if !attrsEqualB(evil.Attrs, false, false, "description") {
		t.Errorf("evil-write attrs = %+v", evil.Attrs)
	}

	nopw := byID["labldap:suffix-nopw"]
	if nopw == nil || !attrsEqualB(nopw.Attrs, false, true, "userpassword") {
		t.Fatalf("suffix-nopw attrs = %+v", nopw)
	}
	if nopw.Attrs.Includes("userPassword") {
		t.Error("suffix-nopw must exclude userPassword")
	}
}

func TestParseACITextBSubjectForms(t *testing.T) {
	body := func(who string) string {
		return `(target="ldap:///dc=example,dc=test")(targetattr="*")(version 3.0; acl "s"; allow (read) ` + who + `;)`
	}
	cases := []struct {
		name string
		text string
		kind ACISubjectKindB
		dn   string
	}{
		{"userdn exact", body(`userdn="ldap:///uid=alice,ou=people,dc=example,dc=test"`), ACISubjectDNB, "uid=alice,ou=people,dc=example,dc=test"},
		{"all", body(`userdn="ldap:///all"`), ACISubjectAllB, ""},
		{"anyone", body(`userdn="ldap:///anyone"`), ACISubjectAnyoneB, ""},
		{"self", body(`userdn="ldap:///self"`), ACISubjectSelfB, ""},
		{"groupdn", body(`groupdn="ldap:///cn=staff,ou=groups,dc=example,dc=test"`), ACISubjectGroupB, "cn=staff,ou=groups,dc=example,dc=test"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ParseACITextB(tc.text)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if p.Subject.Kind != tc.kind {
				t.Errorf("kind = %v, want %v", p.Subject.Kind, tc.kind)
			}
			if tc.dn != "" && p.Subject.DN.String() != tc.dn {
				t.Errorf("DN = %q, want %q", p.Subject.DN.String(), tc.dn)
			}
		})
	}
}

func TestParseACITextBDenyAndAttrLists(t *testing.T) {
	p, err := ParseACITextB(`(targetattr="cn |sn|uid;lang-en")(target="ldap:///ou=people,dc=example,dc=test")(version 3.0; acl "d"; deny (write,add) groupdn="ldap:///cn=staff,ou=groups,dc=example,dc=test";)`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !p.Deny {
		t.Error("expected deny effect")
	}
	if !attrsEqualB(p.Attrs, false, false, "cn", "sn", "uid;lang-en") {
		t.Errorf("attr list = %+v", p.Attrs)
	}
	if !slices.Equal(p.Permissions, []Permission{PermWrite, PermAdd}) {
		t.Errorf("perms = %v", p.Permissions)
	}
	if p.Subject.Kind != ACISubjectGroupB {
		t.Errorf("subject = %v", p.Subject.Kind)
	}
}

// TestParseACITextBInjectionIsData proves that metacharacters inside a
// quoted production can never open or rewrite a clause.
func TestParseACITextBInjectionIsData(t *testing.T) {
	t.Run("paren and star in target DN", func(t *testing.T) {
		p, err := ParseACITextB(`(target="ldap:///cn=a)b *;c,dc=example,dc=test")(targetattr="*")(version 3.0; acl "inj"; allow (read) userdn="ldap:///anyone";)`)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		want, derr := config.ParseDN("cn=a)b *;c,dc=example,dc=test")
		if derr != nil {
			t.Fatalf("fixture DN: %v", derr)
		}
		if !p.TargetDN.Equal(want) {
			t.Errorf("TargetDN = %q, want %q", p.TargetDN.String(), want.String())
		}
	})

	t.Run("escaped quote paren comma", func(t *testing.T) {
		// The compiler's escaping for a uid value of: a"(),b
		// Exactly what the compiler emits for a uid value of: a"(),b
		// (DN-level escaping first, then aciEscape on top).
		p, err := ParseACITextB(`(target="ldap:///uid=a\\\"\28\29\\,b,ou=people,dc=example,dc=test")(targetattr="*")(version 3.0; acl "inj"; allow (read) userdn="ldap:///all";)`)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		attr, val, ok := p.TargetDN.Leaf()
		if !ok || attr != "uid" || val != `a"(),b` {
			t.Errorf("leaf = %q=%q ok=%v, want uid=%q", attr, val, ok, `a"(),b`)
		}
	})

	t.Run("clause breakout attempt stays data", func(t *testing.T) {
		// The target value smuggles a whole escaped deny body; it must be
		// swallowed into the DN as data, never parsed as clauses.
		p, err := ParseACITextB(`(target="ldap:///dc=example,dc=test\")(targetattr=\"*\")(version 3.0; acl \"evil\"; deny (write) userdn=\"ldap:///all\";\)")(targetattr="*")(version 3.0; acl "real"; allow (read) userdn="ldap:///all";)`)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if p.ID != "real" {
			t.Errorf("ID = %q; smuggled acl name must not win", p.ID)
		}
		if p.Deny {
			t.Error("smuggled deny must not take effect")
		}
		if p.HasPermission(PermWrite) || !p.HasPermission(PermRead) {
			t.Errorf("perms = %v; smuggled write must not appear", p.Permissions)
		}
		if p.TargetDN.Depth() != 2 {
			t.Errorf("TargetDN depth = %d; injected text must stay inside the DN value", p.TargetDN.Depth())
		}
	})

	t.Run("escaped targetattr breakout rejected as invalid attr", func(t *testing.T) {
		// The targetattr value unescapes to a full deny clause; attribute
		// validation rejects it rather than honoring it.
		_, err := ParseACITextB(`(target="ldap:///dc=example,dc=test")(targetattr="cn\")(version 3.0; acl \"x\"; deny (write) userdn=\"ldap:///all\";)")(version 3.0; acl "r"; allow (read) userdn="ldap:///all";)`)
		if err == nil {
			t.Fatal("expected rejection")
		}
		if !errors.Is(err, ErrACIParseB) || !strings.Contains(err.Error(), "invalid attribute name") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestParseACITextBRejects(t *testing.T) {
	const (
		tgt  = `(target="ldap:///dc=example,dc=test")`
		body = `(version 3.0; acl "a"; allow (read) userdn="ldap:///all";)`
	)
	cases := []struct {
		name string
		text string
		want string
	}{
		{"empty", "", "empty input"},
		{"whitespace only", "  \n\t ", "missing target clause"},
		{"NUL byte", tgt + "\x00" + body, "input contains NUL"},
		{"unknown clause keyword", `(targets="ldap:///dc=example,dc=test")` + body, "unknown ACI clause"},
		{"389 targetfilter out of grammar", `(targetfilter="(uid=x)")` + tgt + body, "unknown ACI clause"},
		{"389 targattrfilters out of grammar", tgt + `(targattrfilters="add=cn")` + body, "unknown ACI clause"},
		{"missing body", tgt, "missing version/acl body clause"},
		{"missing target", body, "missing target clause"},
		{"missing acl id", tgt + `(version 3.0; allow (read) userdn="ldap:///all";)`, "expected acl name clause"},
		{"empty acl id", tgt + `(version 3.0; acl ""; allow (read) userdn="ldap:///all";)`, "acl name is empty"},
		{"wrong version", tgt + `(version 2.0; acl "a"; allow (read) userdn="ldap:///all";)`, "expected version 3.0"},
		{"unknown permission", tgt + `(version 3.0; acl "a"; allow (read,proxy) userdn="ldap:///all";)`, "unknown permission"},
		{"uppercase permission", tgt + `(version 3.0; acl "a"; allow (READ) userdn="ldap:///all";)`, "unknown permission"},
		{"empty permission list", tgt + `(version 3.0; acl "a"; allow () userdn="ldap:///all";)`, "expected permission"},
		{"trailing comma", tgt + `(version 3.0; acl "a"; allow (read,) userdn="ldap:///all";)`, "expected permission"},
		{"duplicate permission", tgt + `(version 3.0; acl "a"; allow (read,read) userdn="ldap:///all";)`, "duplicate permission"},
		{"missing permission parens", tgt + `(version 3.0; acl "a"; allow read userdn="ldap:///all";)`, "expected permission list"},
		{"userdn wrong scheme", tgt + `(version 3.0; acl "a"; allow (read) userdn="ldap://dc=example,dc=test";)`, "ldap:/// URL form"},
		{"userdn not a DN", tgt + `(version 3.0; acl "a"; allow (read) userdn="ldap:///just-a-word";)`, "bind rule DN is not valid"},
		{"userdn empty DN", tgt + `(version 3.0; acl "a"; allow (read) userdn="ldap:///";)`, "bind rule DN is not valid"},
		{"groupdn special keyword", tgt + `(version 3.0; acl "a"; allow (read) groupdn="ldap:///all";)`, "bind rule DN is not valid"},
		{"missing bind rule", tgt + `(version 3.0; acl "a"; allow (read);)`, "expected userdn or groupdn"},
		{"compound bind rule", tgt + `(version 3.0; acl "a"; allow (read) userdn="ldap:///all" or userdn="ldap:///dc=example,dc=test";)`, "expected semicolon after bind rule"},
		{"extra body clause", tgt + `(version 3.0; acl "a"; allow (read) userdn="ldap:///all"; ip="10.0.0.1";)`, "expected end of ACI clause"},
		{"unterminated quote", `(target="ldap:///dc=example,dc=test)`, "unterminated quoted target"},
		{"dangling escape", `(target="ldap:///dc=example,dc=test\`, "dangling escape"},
		{"incomplete hex escape", `(target="ldap:///dc=example,dc=test\2")`, "incomplete hex escape"},
		{"unterminated paren", `(target="ldap:///dc=example,dc=test"`, "expected end of ACI clause"},
		{"trailing garbage", tgt + body + " junk", "expected start of ACI clause"},
		{"target not ldap URL", `(target="dc=example,dc=test")` + body, "ldap:/// URL form"},
		{"target empty DN", `(target="ldap:///")` + body, "target DN is not valid"},
		{"duplicate target", tgt + tgt + body, "duplicate target clause"},
		{"duplicate body", tgt + body + body, "duplicate version/acl body clause"},
		{"targetattr empty element", tgt + `(targetattr="cn||sn")` + body, "empty attribute in targetattr list"},
		{"targetattr invalid name", tgt + `(targetattr="bad attr!")` + body, "invalid attribute name"},
		{"targetattr wildcard mixed", tgt + `(targetattr="*|cn")` + body, "wildcard * must be the only targetattr element"},
		{"targetattr negated wildcard", tgt + `(targetattr!="*")` + body, "wildcard * is not valid in targetattr!="},
		{"uppercase clause keyword", `(TARGET="ldap:///dc=example,dc=test")` + body, "unknown ACI clause"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseACITextB(tc.text)
			if err == nil {
				t.Fatalf("parse succeeded with %+v, want error containing %q", got, tc.want)
			}
			if !errors.Is(err, ErrACIParseB) {
				t.Errorf("err = %v, want errors.Is ErrACIParseB", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %q, want substring %q", err, tc.want)
			}
		})
	}
}

// TestParseACITextBErrorIsSecretFree: rejections describe structure and
// offsets only; they never echo tokens or quoted values from the input.
func TestParseACITextBErrorIsSecretFree(t *testing.T) {
	_, err := ParseACITextB(`(target="ldap:///dc=example,dc=test")(version 3.0; acl "a"; allow (read,proxy) userdn="ldap:///all";)`)
	if err == nil {
		t.Fatal("expected rejection")
	}
	if strings.Contains(err.Error(), "proxy") {
		t.Errorf("error echoes input token: %q", err)
	}
	_, err = ParseACITextB(`(target="ldap:///uid=secret-bearer,dc=example,dc=test")(version 3.0; acl "a"; allow (read) userdn=`)
	if err == nil {
		t.Fatal("expected rejection")
	}
	if strings.Contains(err.Error(), "secret-bearer") {
		t.Errorf("error echoes quoted value: %q", err)
	}
}

// TestParseACITextBOversized: input length is bounded before scanning.
func TestParseACITextBOversized(t *testing.T) {
	big := strings.Repeat("(targetattr=\"cn\")", maxACITextLenB/17+1)
	if _, err := ParseACITextB(big); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v, want length rejection", err)
	}
}

// TestParseACITextBNeverPanics hammers truncations and deterministic byte
// mutations of a valid ACI. Any panic fails the test.
func TestParseACITextBNeverPanics(t *testing.T) {
	base := `(target="ldap:///ou=people,dc=example,dc=test")(targetattr!="aci")(version 3.0; acl "labldap:x"; allow (add,delete,write) userdn="ldap:///uid=r,ou=people,dc=example,dc=test";)`
	for i := 0; i <= len(base); i++ {
		_, _ = ParseACITextB(base[:i])
	}
	const alphabet = `()"\;,*=!|abc3.`
	state := uint32(1)
	next := func() uint32 {
		state = state*1664525 + 1013904223
		return state >> 16
	}
	for n := 0; n < 5000; n++ {
		b := []byte(base)
		for m := 0; m < 3; m++ {
			b[int(next())%len(b)] = alphabet[int(next())%len(alphabet)]
		}
		_, _ = ParseACITextB(string(b))
	}
}

// TestParseACITextBWhitespaceAndOrder: clauses may arrive in any order with
// liberal ASCII whitespace, matching 389 tolerance for raw ACI.
func TestParseACITextBWhitespaceAndOrder(t *testing.T) {
	p, err := ParseACITextB("\n ( version 3.0 ; acl \"w\" ; allow ( read , search ) userdn=\"ldap:///all\" ; ) \n( targetattr = \"cn\" )\n( target = \"ldap:///dc=example,dc=test\" )\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if p.ID != "w" || p.TargetDN.String() != "dc=example,dc=test" {
		t.Errorf("parsed = %+v", p)
	}
	if !slices.Equal(p.Permissions, []Permission{PermRead, PermSearch}) {
		t.Errorf("perms = %v", p.Permissions)
	}
}

// TestParseACITextBOmittedTargetAttr: a raw ACI without targetattr follows
// 389 semantics — all attributes.
func TestParseACITextBOmittedTargetAttr(t *testing.T) {
	p, err := ParseACITextB(`(target="ldap:///dc=example,dc=test")(version 3.0; acl "o"; allow (read) userdn="ldap:///anyone";)`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !p.Attrs.All || !p.Attrs.Includes("userPassword") {
		t.Errorf("omitted targetattr must cover all attributes: %+v", p.Attrs)
	}
}

func FuzzParseACITextB(f *testing.F) {
	seeds := []string{
		`(target="ldap:///dc=example,dc=test")(targetattr!="userPassword")(version 3.0; acl "labldap:runtime-suffix-read"; allow (read,search,compare) userdn="ldap:///uid=labldap-runtime,ou=people,dc=example,dc=test";)`,
		`(target="ldap:///ou=people,dc=example,dc=test")(targetattr="userPassword")(version 3.0; acl "labldap:runtime-password"; allow (write) userdn="ldap:///uid=labldap-runtime,ou=people,dc=example,dc=test";)`,
		`(targetattr="cn|sn")(target="ldap:///dc=x,dc=test")(version 3.0; acl "g"; deny (add,delete) groupdn="ldap:///cn=g,ou=groups,dc=x,dc=test";)`,
		`(target="ldap:///dc=x,dc=test")(version 3.0; acl "s"; allow (compare) userdn="ldap:///self";)`,
		`(target="ldap:///uid=a\22\28\29\2c b,dc=x,dc=test")(targetattr="*")(version 3.0; acl "e"; allow (read) userdn="ldap:///anyone";)`,
		``, `(`, `(target=`, `"`, `\`, `(version 3.0;)`,
		`(targetfilter="(uid=x)")`, `junk`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := ParseACITextB(s)
		if err != nil {
			if !errors.Is(err, ErrACIParseB) {
				t.Fatalf("error must wrap ErrACIParseB: %v", err)
			}
			return
		}
		if p.ID == "" || len(p.Permissions) == 0 || p.TargetDN.Depth() == 0 {
			t.Fatalf("successful parse missing required fields: %+v", p)
		}
	})
}
