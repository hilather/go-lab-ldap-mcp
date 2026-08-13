package ds389

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

type pwpScript struct {
	calls  []string
	get    string
	setErr error
}

func (s *pwpScript) exec(_ context.Context, _ string, args []string) ([]byte, []byte, error) {
	joined := strings.Join(args, " ")
	s.calls = append(s.calls, joined)
	if strings.Contains(joined, "pwpolicy get") {
		return []byte(s.get), nil, nil
	}
	if strings.Contains(joined, "pwpolicy set") {
		if s.setErr != nil {
			return nil, []byte(s.setErr.Error()), s.setErr
		}
		return []byte("Successfully updated global password policy\n"), nil, nil
	}
	return []byte(`{}`), nil, nil
}

func sampleGet(minlen, hist, exp, maxage, warn, lock, fail, lockdur, scheme string) string {
	return `{
  "attrs": {
    "passwordminlength": ["` + minlen + `"],
    "passwordhistory": ["` + hist + `"],
    "passwordinhistory": ["2"],
    "passwordexp": ["` + exp + `"],
    "passwordmaxage": ["` + maxage + `"],
    "passwordwarning": ["` + warn + `"],
    "passwordlockout": ["` + lock + `"],
    "passwordmaxfailure": ["` + fail + `"],
    "passwordlockoutduration": ["` + lockdur + `"],
    "passwordstoragescheme": ["` + scheme + `"],
    "passwordchecksyntax": ["on"]
  }
}`
}

func TestReconcilePolicyApplyReadback(t *testing.T) {
	sc := &pwpScript{get: sampleGet("12", "on", "on", "86400", "3600", "on", "3", "60", "PBKDF2-SHA256")}
	eng := Engine{Runner: Runner{Exec: sc.exec}}
	res, err := eng.ReconcilePolicy(t.Context(), bootstrap.PolicyRequest{
		PasswordFile: "/secret/dm.pw",
		Instance:     "localhost",
		Write:        true,
		Policy: config.NormalizedPolicy{
			MinLength: 12, HistoryCount: 2, MaxAge: 24 * time.Hour, WarningAge: time.Hour,
			LockoutEnabled: true, MaxFailures: 3, LockoutDuration: time.Minute,
			StorageScheme: "PBKDF2-SHA256",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Applied) == 0 {
		t.Fatal("expected applied fields")
	}
	set := strings.Join(sc.calls, " ")
	if strings.Contains(set, "sh -c") {
		t.Fatal("sh -c")
	}
	if !strings.Contains(set, "--pwdminlen") || !strings.Contains(set, "-y") {
		t.Fatalf("set argv = %s", set)
	}
}

func TestReconcilePolicyUnsupportedMinLength(t *testing.T) {
	for _, n := range []int{-1, 1, 513} {
		eng := Engine{Runner: Runner{Exec: (&pwpScript{}).exec}}
		_, err := eng.ReconcilePolicy(t.Context(), bootstrap.PolicyRequest{
			PasswordFile: "/s", Instance: "localhost", Write: true,
			Policy: config.NormalizedPolicy{MinLength: n, StorageScheme: "PBKDF2-SHA256"},
		})
		if err == nil {
			t.Fatalf("minLength %d: expected unsupported_field", n)
		}
		apperr.Assert(t, err).Code(apperr.CodeBootstrap).FieldPath("phase.pwpolicy")
		if !fieldHas(err, "phase.pwpolicy", "unsupported_field") {
			t.Fatalf("minLength %d: %v", n, err)
		}
	}
}

func TestReconcilePolicyReadbackMismatch(t *testing.T) {
	sc := &pwpScript{get: sampleGet("8", "off", "off", "86400", "0", "off", "3", "3600", "PBKDF2-SHA512")}
	eng := Engine{Runner: Runner{Exec: sc.exec}}
	_, err := eng.ReconcilePolicy(t.Context(), bootstrap.PolicyRequest{
		PasswordFile: "/s", Instance: "localhost", Write: true,
		Policy: config.NormalizedPolicy{MinLength: 12, StorageScheme: "PBKDF2-SHA256"},
	})
	if err == nil {
		t.Fatal("expected readback_mismatch")
	}
	if !fieldHas(err, "phase.pwpolicy", "readback_mismatch") {
		t.Fatalf("%v", err)
	}
	if !strings.Contains(err.Error(), "want") || !strings.Contains(err.Error(), "got") {
		t.Fatalf("mismatch should include want/got: %v", err)
	}
}

func TestReconcilePolicyValidateNoSet(t *testing.T) {
	sc := &pwpScript{get: sampleGet("12", "off", "off", "86400", "0", "off", "3", "3600", "PBKDF2-SHA256")}
	eng := Engine{Runner: Runner{Exec: sc.exec}}
	_, err := eng.ReconcilePolicy(t.Context(), bootstrap.PolicyRequest{
		PasswordFile: "/s", Instance: "localhost", Write: false,
		Policy: config.NormalizedPolicy{MinLength: 12, StorageScheme: "PBKDF2-SHA256"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range sc.calls {
		if strings.Contains(c, "pwpolicy set") {
			t.Fatalf("validate wrote: %s", c)
		}
	}
}

func TestReconcilePolicyUnsupportedScheme(t *testing.T) {
	eng := Engine{}
	_, err := eng.ReconcilePolicy(context.Background(), bootstrap.PolicyRequest{
		Policy: config.NormalizedPolicy{StorageScheme: "ARGON2ID"},
	})
	if err == nil || !fieldHas(err, "phase.pwpolicy", "unsupported_field") {
		t.Fatalf("%v", err)
	}
}

func TestPolicySetArgsNeverZeroMaxAge(t *testing.T) {
	args, _ := policySetArgs(config.NormalizedPolicy{StorageScheme: "PBKDF2-SHA256"})
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "--pwdmaxage 0") || strings.Contains(joined, "--pwdminlen 0") {
		t.Fatalf("invalid zero values: %s", joined)
	}
	if !strings.Contains(joined, "--pwdexpire off") || !strings.Contains(joined, "--pwdhistory off") {
		t.Fatalf("%s", joined)
	}
}

func TestPolicySetArgsNeverPasswordOnArgv(t *testing.T) {
	args, _ := policySetArgs(config.NormalizedPolicy{MinLength: 12, StorageScheme: "PBKDF2-SHA256"})
	joined := strings.Join(args, " ")
	for _, a := range args {
		if strings.Contains(strings.ToLower(a), "secret") || strings.Contains(a, "password=") {
			t.Fatalf("looks like a secret on argv: %q", a)
		}
	}
	for _, need := range []string{"--pwdmincatagories 1", "--pwdmintokenlen 64", "--pwddictcheck off", "--pwdpalindrome off"} {
		if !strings.Contains(joined, need) {
			t.Fatalf("missing syntax neutralize %q in %s", need, joined)
		}
	}
}
