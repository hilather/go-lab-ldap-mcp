//go:build integration

package dirsrv

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

// TestRESTMovesWithRuntimeGrant (resolved CAND-39 and CAND-30) moves
// entries through REST as the runtime account on both engines: the runtime
// ACIs grant moddn under people, groups and each additional suffix, so
// people <-> groups moves and case-only renames succeed; a move between
// managed suffixes is a stable newDN field error (389: affectsMultipleDSAs,
// oracle probe 34), and a move to a parent without a grant is forbidden.
func TestRESTMovesWithRuntimeGrant(t *testing.T) {
	env, h := startMultiDomainEnv(t)
	t.Logf("engine=%s", env.engine)
	const (
		people = "ou=people,dc=example,dc=test"
		groups = "ou=groups,dc=example,dc=test"
		r1     = "dc=region1,dc=example,dc=net"
	)
	get := func(dn string) directory.DirectoryEntry {
		t.Helper()
		raw := restRaw(t, h, http.MethodGet, "/api/v1/entries?dn="+url.QueryEscape(dn), mdAdminToken, "", "", http.StatusOK)
		var ent directory.DirectoryEntry
		if err := json.Unmarshal(raw, &ent); err != nil {
			t.Fatal(err)
		}
		return ent
	}
	move := func(dn, newDN string, want int) []byte {
		t.Helper()
		rev := get(dn).Revision
		body := `{"dn":"` + dn + `","newDN":"` + newDN + `","deleteOldRdn":true}`
		return restRaw(t, h, http.MethodPost, "/api/v1/entries/move", mdAdminToken, `"`+string(rev)+`"`, body, want)
	}
	mkOU := func(dn string) {
		t.Helper()
		restRaw(t, h, http.MethodPost, "/api/v1/entries", mdAdminToken, "", `{"dn":"`+dn+`","objectClasses":["organizationalUnit"]}`, http.StatusCreated)
	}

	mkOU("ou=c39mv," + people)
	raw := move("ou=c39mv,"+people, "ou=c39mv,"+groups, http.StatusOK)
	var ent directory.DirectoryEntry
	if err := json.Unmarshal(raw, &ent); err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(ent.DN, "ou=c39mv,"+groups) {
		t.Fatalf("moved DN %q", ent.DN)
	}
	move("ou=c39mv,"+groups, "ou=c39mv,"+people, http.StatusOK)

	// Case-only rename respells the DN (CAND-30).
	raw = move("ou=c39mv,"+people, "ou=C39MV,"+people, http.StatusOK)
	if err := json.Unmarshal(raw, &ent); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ent.DN, "ou=C39MV,") {
		t.Fatalf("case-only rename DN %q, want respelled", ent.DN)
	}

	// Inside an additional suffix the runtime account holds moddn too.
	mkOU("ou=c39a," + r1)
	mkOU("ou=c39b," + r1)
	mkOU("ou=c39x,ou=c39a," + r1)
	move("ou=c39x,ou=c39a,"+r1, "ou=c39x,ou=c39b,"+r1, http.StatusOK)

	// Across managed suffixes: stable field error before any LDAP call.
	if got := string(move("ou=c39x,ou=c39b,"+r1, "ou=c39x,"+people, http.StatusForbidden)); !strings.Contains(got, "newDN") {
		t.Fatalf("cross-suffix move problem: %s", got)
	}
	// Over LDAP, even Directory Manager gets affectsMultipleDSAs(71)
	// before any other check, also for a missing source (probe 34).
	pem, err := os.ReadFile(env.caFile)
	if err != nil {
		t.Fatal(err)
	}
	cas := x509.NewCertPool()
	if !cas.AppendCertsFromPEM(pem) {
		t.Fatal("parse test CA")
	}
	dm, err := ldap.DialURL("ldaps://"+env.ldapsAddr, ldap.DialWithTLSConfig(&tls.Config{RootCAs: cas, ServerName: env.serverName, MinVersion: tls.VersionTLS12}))
	if err != nil {
		t.Fatal(err)
	}
	defer dm.Close()
	if err := dm.Bind("cn=Directory Manager", env.dmPassword); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ dn, sup string }{
		{"ou=c39x,ou=c39b," + r1, people},
		{"ou=C39MV," + people, r1},
		{"ou=ghost,ou=c39b," + r1, people},
	} {
		var le *ldap.Error
		err := dm.ModifyDN(ldap.NewModifyDNRequest(tc.dn, strings.SplitN(tc.dn, ",", 2)[0], true, tc.sup))
		if !errors.As(err, &le) || le.ResultCode != ldap.LDAPResultAffectsMultipleDSAs {
			t.Errorf("%s: DM move %s under %s: %v, oracle 71", env.engine, tc.dn, tc.sup, err)
		}
	}

	// To the suffix root: no moddn grant there.
	restRaw(t, h, http.MethodPost, "/api/v1/entries/move", mdAdminToken, `"`+string(get("ou=C39MV,"+people).Revision)+`"`,
		`{"dn":"ou=C39MV,`+people+`","newDN":"ou=c39mv,dc=example,dc=test","deleteOldRdn":true}`, http.StatusForbidden)
}
