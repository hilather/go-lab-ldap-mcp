//go:build integration

package dirsrv

import (
	"errors"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

func TestDecodeSummary(t *testing.T) {
	type sum struct {
		Command string `json:"command"`
		OK      bool   `json:"ok"`
		Phases  []struct {
			Phase  string         `json:"phase"`
			Counts map[string]int `json:"counts"`
		} `json:"phases"`
	}
	const summary = "{\n  \"command\": \"apply\",\n  \"ok\": true,\n  \"phases\": [{\"phase\": \"load\", \"counts\": {\"users\": 1}}]\n}"
	cases := map[string]string{
		"summary only":          summary,
		"logs before":           "time=2026-10-04T00:18:24Z level=INFO msg=starting\n" + summary,
		"logs after (CI flake)": summary + "\ntime=2026-10-04T00:18:37Z level=INFO msg=\"bootstrap phase\" phase=drift ok=true\n",
		"earlier run skipped":   "{\"command\": \"verify\", \"ok\": false}\n" + summary + "\ntime=x level=INFO\n",
	}
	for name, out := range cases {
		t.Run(name, func(t *testing.T) {
			var got sum
			if err := decodeSummary(out, &got); err != nil {
				t.Fatal(err)
			}
			if got.Command != "apply" || !got.OK || len(got.Phases) != 1 || got.Phases[0].Counts["users"] != 1 {
				t.Fatalf("decoded %+v", got)
			}
		})
	}
	for name, out := range map[string]string{
		"no summary":       "time=x level=INFO msg=nothing\n",
		"nested command":   "{\"ok\": true, \"plan\": {\"command\": \"apply\"}}",
		"no opening brace": "\"command\": \"apply\"}",
	} {
		t.Run(name, func(t *testing.T) {
			var got sum
			if err := decodeSummary(out, &got); err == nil {
				t.Fatalf("decoded %+v from %q, want error", got, out)
			}
		})
	}
}

func TestRetryInvalidCredentials(t *testing.T) {
	invalid := &ldap.Error{ResultCode: ldap.LDAPResultInvalidCredentials}
	t.Run("49 then success", func(t *testing.T) {
		n := 0
		err := retryInvalidCredentials(time.Second, time.Millisecond, func() error {
			n++
			if n < 3 {
				return invalid
			}
			return nil
		})
		if err != nil || n != 3 {
			t.Fatalf("err=%v attempts=%d", err, n)
		}
	})
	t.Run("other error fails at once", func(t *testing.T) {
		n := 0
		other := &ldap.Error{ResultCode: ldap.LDAPResultConfidentialityRequired}
		err := retryInvalidCredentials(time.Second, time.Millisecond, func() error { n++; return other })
		if !errors.Is(err, other) || n != 1 {
			t.Fatalf("err=%v attempts=%d", err, n)
		}
	})
	t.Run("persistent 49 times out", func(t *testing.T) {
		err := retryInvalidCredentials(20*time.Millisecond, 5*time.Millisecond, func() error { return invalid })
		if !errors.Is(err, errDMBindTimeout) {
			t.Fatalf("err=%v", err)
		}
	})
}
