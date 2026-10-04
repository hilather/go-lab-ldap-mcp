//go:build integration

package parity

import (
	"errors"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

func TestOracleRetryInvalidCredentials(t *testing.T) {
	invalid := &ldap.Error{ResultCode: ldap.LDAPResultInvalidCredentials}
	n := 0
	if err := oracleRetryInvalidCredentials(time.Second, time.Millisecond, func() error {
		n++
		if n < 3 {
			return invalid
		}
		return nil
	}); err != nil || n != 3 {
		t.Fatalf("49 then success: err=%v attempts=%d", err, n)
	}
	other := errors.New("x509: certificate signed by unknown authority")
	n = 0
	if err := oracleRetryInvalidCredentials(time.Second, time.Millisecond, func() error { n++; return other }); !errors.Is(err, other) || n != 1 {
		t.Fatalf("other error: err=%v attempts=%d", err, n)
	}
	if err := oracleRetryInvalidCredentials(20*time.Millisecond, 5*time.Millisecond, func() error { return invalid }); !errors.Is(err, errOracleDMTimeout) {
		t.Fatalf("persistent 49: err=%v", err)
	}
}
