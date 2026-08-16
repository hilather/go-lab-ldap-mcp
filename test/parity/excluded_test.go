package parity

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/ldapserver"
)

// TestExcludedSurfaceNative proves the Excluded tier (contract section 4)
// is inert or unreachable through the native engine's LabLDAP surface.
// Excluded items are 389 behaviors native must NOT implement in M9, so
// these are native-only assertions (no oracle involved).
func TestExcludedSurfaceNative(t *testing.T) {
	fx := compileFixture(t)
	ne := startNative(t, fx)
	defer ne.close(t)

	t.Run("root-dse-advertises-no-excluded-features", func(t *testing.T) {
		// E1 (replication), E2 (SASL), E4 (roles/CoS/...), E5 (AD/Samba),
		// E7 (389 CLI compatibility) would all surface as extra Root DSE
		// capabilities. The native DSE publishes exactly the contract set.
		// Production inspect uses the bound pool (KD-6 / D24): pre-bind
		// Root DSE is refused when anonymous access is off.
		conn := mustDial(t, ne, userSpec(userDN("alice"), userPasswords["alice"]))
		defer conn.Close()
		res := readOutcome(conn, "") // no attr list → full published set
		if res.Code != 0 || len(res.Entries) != 1 {
			t.Fatalf("root DSE read: %+v", res)
		}
		got := make([]string, 0, len(res.Entries[0].Attrs))
		for name := range res.Entries[0].Attrs {
			// objectClass is entry data, not a capability advertisement.
			if name == "objectclass" {
				continue
			}
			got = append(got, name)
		}
		sort.Strings(got)
		// presentOnlyAttrs normalized several of these to PRESENT markers;
		// the names are what matter here.
		want := []string{
			"namingcontexts", "subschemasubentry", "supportedcontrol",
			"supportedextension", "supportedldapversion", "vendorname", "vendorversion",
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("native root DSE attrs = %v, want exactly %v", got, want)
		}
	})

	t.Run("e2-sasl-unreachable", func(t *testing.T) {
		// supportedSASLMechanisms absent (checked above); a SASL bind on
		// the wire is rejected and the connection torn down.
		out := rawSASLBind(t, ne.ldapAddr)
		if out.Code == 0 {
			t.Fatalf("SASL bind unexpectedly succeeded: %+v", out)
		}
		if !strings.Contains(out.Note, "disconnection") && !strings.Contains(out.Note, "closed") {
			t.Fatalf("SASL bind outcome %+v: expected notice-of-disconnection or close", out)
		}
	})

	t.Run("e3-rfc3062-password-modify-unreachable", func(t *testing.T) {
		dm := ne.dm(t)
		defer dm.Close()
		_, err := dm.Extended(ldap.NewExtendedRequest(oidPasswordMod46, nil))
		if code := ldapCode(err); code != 2 { // protocolError
			t.Fatalf("RFC 3062 ext op: got code %d, want protocolError(2)", code)
		}
		// Nothing changed: the fixture user still binds with its password.
		if ok := dialCode(t, ne, userSpec(userDN("alice"), userPasswords["alice"])); ok.Code != 0 {
			t.Fatalf("alice bind after RFC 3062 attempt: %+v", ok)
		}
	})

	t.Run("e6-out-of-grammar-aci-rejected-at-startup", func(t *testing.T) {
		// Raw ACI outside the compiler-subset grammar (C8) must be a loud
		// configuration rejection, never a silent ignore (E6).
		outside := []string{
			`(target="ldap:///dc=example,dc=test")(targetattr="*")(version 3.0; acl "x"; allow (read) userdn="ldap:///all";)(targattrfilters="add=foo")`,
			`(version 3.0; acl "x"; allow (read) userdn="ldap:///all#branch";)`,
		}
		for _, text := range outside {
			if _, err := ldapserver.NewACIEngine([]string{text}, nil); err == nil {
				t.Fatalf("out-of-grammar ACI accepted: %s", text)
			}
		}
	})

	t.Run("e8-no-indexes-in-engine-plan", func(t *testing.T) {
		// Indexes are not a scenario/plan object (E8): the compiled engine
		// plan carries no index configuration for native to honor.
		rt := reflect.TypeOf(config.EnginePlan{})
		for i := 0; i < rt.NumField(); i++ {
			if strings.Contains(strings.ToLower(rt.Field(i).Name), "index") {
				t.Fatalf("EnginePlan grew an index field: %s — amend the contract first", rt.Field(i).Name)
			}
		}
	})

	t.Run("e1-e7-no-admin-or-replication-surface", func(t *testing.T) {
		// Native has no cn=config/cn=tasks/cn=replication DIT (D2); the
		// runtime identity is denied any engine-admin tree (C8). cn=schema
		// is deliberately absent from this list: it is the subschema alias
		// and stays world-readable (C10, verified in caseSubschema).
		rt := mustDial(t, ne, userSpec(runtimeDN, runtimePassword))
		for _, dn := range []string{"cn=config", "cn=tasks", "cn=replication,cn=config", "cn=changelog"} {
			out := readOutcome(rt, dn, "cn")
			if out.Code == 0 && len(out.Entries) > 0 {
				t.Fatalf("runtime reached admin/replication entry %s: %+v", dn, out)
			}
		}
	})
}
