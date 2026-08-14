package dirsrv

import (
	"strings"
	"testing"
)

func TestRedactLogs(t *testing.T) {
	const dm = "super-secret-dm-password"
	const pem = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
	cases := []struct {
		name string
		in   string
		want []string
		deny []string
	}{
		{
			name: "dscontainer first-boot quoted password",
			in:   `IMPORTANT: Set cn=Directory Manager password to "generatedPW123"`,
			want: []string{"[redacted]"},
			deny: []string{"generatedPW123"},
		},
		{
			name: "password set to",
			in:   "password set to hunter2",
			want: []string{"[redacted]"},
			deny: []string{"hunter2"},
		},
		{
			name: "root dn",
			in:   "Root DN password: abcdef",
			want: []string{"[redacted]"},
			deny: []string{"abcdef"},
		},
		{
			name: "env echo",
			in:   "DS_DM_PASSWORD=" + dm,
			want: []string{"[redacted]"},
			deny: []string{dm},
		},
		{
			name: "explicit secret plus pem",
			in:   "bind with " + dm + "\n" + pem,
			want: []string{"[redacted]", "[redacted-pem]"},
			deny: []string{dm, "BEGIN RSA PRIVATE KEY", "MIIEowIBAAKCAQEA"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redactLogs(tc.in, dm)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Fatalf("missing %q in %q", w, got)
				}
			}
			for _, d := range tc.deny {
				if strings.Contains(got, d) {
					t.Fatalf("leaked %q in %q", d, got)
				}
			}
		})
	}
}
