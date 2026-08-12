package ds389

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

type tlsScript struct {
	calls    []string
	sasl     string
	dialErrs map[string]error
}

func (s *tlsScript) exec(_ context.Context, _ string, args []string) ([]byte, []byte, error) {
	joined := strings.Join(args, " ")
	s.calls = append(s.calls, joined)
	if strings.Contains(joined, "sasl get-mechs") {
		if s.sasl == "" {
			s.sasl = `{"type":"list","items":["EXTERNAL","PLAIN"]}`
		}
		return []byte(s.sasl), nil, nil
	}
	return []byte(`{"ok":true}`), nil, nil
}

func (s *tlsScript) dial(_ context.Context, mode, _ string, _ bootstrap.TLSRequest) error {
	if s.dialErrs == nil {
		return nil
	}
	return s.dialErrs[mode]
}

func baseTLSReq() bootstrap.TLSRequest {
	return bootstrap.TLSRequest{
		PasswordFile: "/secret/dm.pw",
		Instance:     "localhost",
		LDAPURL:      "ldaps://127.0.0.1:3636",
		LDAPAddr:     "127.0.0.1:3389",
		UseLDAPS:     true,
		Password:     observability.Secret("x"),
		Write:        true,
	}
}

func TestReconcileTLSSuccess(t *testing.T) {
	sc := &tlsScript{dialErrs: map[string]error{"ldap": errors.New("confidentiality required")}}
	eng := Engine{Runner: Runner{Exec: sc.exec}, Dial: sc.dial}
	res, err := eng.ReconcileTLS(t.Context(), baseTLSReq())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Transports) != 1 || res.Transports[0] != "ldaps" {
		t.Fatalf("%+v", res)
	}
	wrote := strings.Join(sc.calls, "\n")
	if !strings.Contains(wrote, "require-secure-authentication on") {
		t.Fatalf("missing secure-auth set: %s", wrote)
	}
	if !strings.Contains(wrote, "nsslapd-allow-anonymous-access=off") {
		t.Fatalf("missing anonymous off: %s", wrote)
	}
}

func TestReconcileTLSCleartextStillEnabled(t *testing.T) {
	sc := &tlsScript{dialErrs: map[string]error{}}
	eng := Engine{Runner: Runner{Exec: sc.exec}, Dial: sc.dial}
	_, err := eng.ReconcileTLS(t.Context(), baseTLSReq())
	if err == nil {
		t.Fatal("expected cleartext_enabled")
	}
	apperr.Assert(t, err).Code(apperr.CodeBootstrap).FieldPath("phase.tls")
	if !fieldHas(err, "phase.tls", "cleartext_enabled") {
		t.Fatalf("%v", err)
	}
}

func TestReconcileTLSMissingSASL(t *testing.T) {
	sc := &tlsScript{
		dialErrs: map[string]error{"ldap": errors.New("confidentiality required")},
		sasl:     `{"type":"list","items":["EXTERNAL","PLAIN"]}`,
	}
	eng := Engine{Runner: Runner{Exec: sc.exec}, Dial: sc.dial}
	req := baseTLSReq()
	req.RequiredSASL = []string{"OTP"}
	_, err := eng.ReconcileTLS(t.Context(), req)
	if err == nil {
		t.Fatal("expected sasl_missing")
	}
	if !fieldHas(err, "phase.tls", "sasl_missing") {
		t.Fatalf("%v", err)
	}
}

func TestReconcileTLSValidateDoesNotWrite(t *testing.T) {
	sc := &tlsScript{dialErrs: map[string]error{"ldap": errors.New("confidentiality required")}}
	eng := Engine{Runner: Runner{Exec: sc.exec}, Dial: sc.dial}
	req := baseTLSReq()
	req.Write = false
	if _, err := eng.ReconcileTLS(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	for _, c := range sc.calls {
		if strings.Contains(c, "security set") || strings.Contains(c, "config replace") {
			t.Fatalf("validate wrote: %s", c)
		}
	}
}

func fieldHas(err error, path, code string) bool {
	var e *apperr.Error
	if !errors.As(err, &e) {
		return false
	}
	for _, f := range e.Fields() {
		if f.Path == path && f.Code == code {
			return true
		}
	}
	return false
}
