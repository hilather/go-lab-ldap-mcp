//go:build integration

package dirsrv

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/test/fixtures/ldapwire"
)

// C1/C3/C8: sequential reauthentication changes authorization only after Bind.
// Every request awaits its response; outstanding-operation scheduling is tested
// independently by the native deterministic dispatch unit regression.
func TestNativeReviewSequentialRebindAuthorization(t *testing.T) {
	env := startCompatEngineFromYAML(t, workflowYAML())
	pem, err := os.ReadFile(env.caFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("CA")
	}
	for i := 0; i < 20; i++ {
		codes, err := ldapwire.RebindAuthorization(t.Context(), env.ldapsAddr, &tls.Config{RootCAs: roots, ServerName: env.serverName, MinVersion: tls.VersionTLS12}, "uid=alice,ou=people,dc=example,dc=test", seedCanary, env.dmPassword)
		if err != nil {
			t.Fatal(err)
		}
		if codes != [3]int64{50, 0, 6} {
			t.Fatalf("iteration=%d IDs 1/2/3 codes=%v", i, codes)
		}
	}
}

// The supported anonymous-enabled fixture isolates ACI denial from 389's
// global anonymous gate. This asserts authorization, not Bind completion order.
func TestNativeReviewPipelinedAuthorization(t *testing.T) {
	yaml := strings.Replace(workflowYAML(), "transport: { ldaps:", "transport: { allowAnonymousBind: true, ldaps:", 1)
	env := startCompatEngineFromYAML(t, yaml)
	pem, err := os.ReadFile(env.caFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("CA")
	}
	for i := 0; i < 20; i++ {
		codes, err := ldapwire.PipelinedAuthorization(t.Context(), env.ldapsAddr, &tls.Config{RootCAs: roots, ServerName: env.serverName, MinVersion: tls.VersionTLS12}, "uid=alice,ou=people,dc=example,dc=test", seedCanary, env.dmPassword)
		if err != nil {
			t.Fatal(err)
		}
		if codes != [3]int64{50, 0, 6} {
			t.Fatalf("iteration=%d IDs1/2/3 codes=%v", i, codes)
		}
	}
}
