package ds389

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

func TestWaitCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := Admin{}.Wait(ctx, bootstrap.WaitRequest{
		Host:        "192.0.2.1",
		UseLDAPS:    true,
		LDAPSPort:   3636,
		Password:    observability.Secret("x"),
		BindDN:      "cn=Directory Manager",
		DialTimeout: 50 * time.Millisecond,
		Deadline:    time.Second,
	})
	if err == nil {
		t.Fatal("expected cancel")
	}
	apperr.Assert(t, err).Code(apperr.CodeBootstrap).FieldPath("phase.wait")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestWaitDeadlineOnUnreachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	_, err := Admin{}.Wait(ctx, bootstrap.WaitRequest{
		Host:        "192.0.2.1",
		UseLDAPS:    true,
		LDAPSPort:   1,
		Password:    observability.Secret("x"),
		BindDN:      "cn=Directory Manager",
		DialTimeout: 40 * time.Millisecond,
		Deadline:    150 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("expected timeout")
	}
	apperr.Assert(t, err).Code(apperr.CodeBootstrap).FieldPath("phase.wait")
}

func TestIsBindFailure(t *testing.T) {
	le := &ldap.Error{ResultCode: ldap.LDAPResultInvalidCredentials, Err: errors.New("bad")}
	if !isBindFailure(le) {
		t.Fatal("invalid credentials should be bind failure")
	}
	if isBindFailure(errors.New("dial: connection refused")) {
		t.Fatal("dial is not bind")
	}
}

func TestWaitMissingCAFileIsTLS(t *testing.T) {
	start := time.Now()
	_, err := Admin{}.Wait(t.Context(), bootstrap.WaitRequest{
		Host:        "ldap.lab.test",
		LDAPURL:     "ldaps://127.0.0.1:1",
		UseLDAPS:    true,
		CAFile:      filepath.Join(t.TempDir(), "missing-ca.crt"),
		Password:    observability.Secret("x"),
		BindDN:      "cn=Directory Manager",
		DialTimeout: 50 * time.Millisecond,
		Deadline:    5 * time.Second,
	})
	if err == nil {
		t.Fatal("expected tls error")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("missing CA retried too long: %s", time.Since(start))
	}
	apperr.Assert(t, err).Code(apperr.CodeBootstrap).FieldPath("phase.wait")
	if got := fieldCode(err); got != "tls" {
		t.Fatalf("code = %q, want tls", got)
	}
}

func TestClassifyWait(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, "timeout"},
		{&ldap.Error{ResultCode: ldap.LDAPResultInvalidCredentials, Err: errors.New("bad")}, "bind"},
		{errors.New("tls: certificate signed by unknown authority"), "tls"},
		{bootstrap.PhaseError("wait", "tls", "directory CA file unreadable"), "tls"},
		{errors.New("dial: connection refused"), "timeout"},
	}
	for _, tc := range cases {
		got, _ := classifyWait(tc.err)
		if got != tc.want {
			t.Errorf("classifyWait(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

func fieldCode(err error) string {
	var e *apperr.Error
	if !errors.As(err, &e) {
		return ""
	}
	for _, f := range e.Fields() {
		if f.Path == "phase.wait" {
			return f.Code
		}
	}
	return ""
}

func TestDialURL(t *testing.T) {
	u, tr := dialURL(bootstrap.WaitRequest{LDAPURL: "ldaps://127.0.0.1:3636"})
	if u != "ldaps://127.0.0.1:3636" || tr != "ldaps" {
		t.Fatalf("%s %s", u, tr)
	}
	u, tr = dialURL(bootstrap.WaitRequest{Host: "h", UseLDAPS: true, LDAPSPort: 3636})
	if u != "ldaps://h:3636" || tr != "ldaps" {
		t.Fatalf("%s %s", u, tr)
	}
}
