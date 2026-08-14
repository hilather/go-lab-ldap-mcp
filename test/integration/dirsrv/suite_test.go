//go:build integration

package dirsrv

import (
	"strings"
	"testing"
)

// T-043: test-log secret scan of the same redaction used by the harness.
func TestT043TestLogSecretScan(t *testing.T) {
	const dm = "suite-dm-canary-password"
	const user = "suite-alice-canary-12"
	log := strings.Join([]string{
		`IMPORTANT: Set cn=Directory Manager password to "` + dm + `"`,
		"DS_DM_PASSWORD=" + dm,
		"bind as uid=alice with " + user,
		"-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
	}, "\n")
	got := redactLogs(log, dm, user)
	for _, leak := range []string{dm, user, "BEGIN RSA PRIVATE KEY", "MIIEowIBAAKCAQEA"} {
		if strings.Contains(got, leak) {
			t.Fatalf("test log leaked %q:\n%s", leak, got)
		}
	}
}
