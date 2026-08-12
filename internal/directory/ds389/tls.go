package ds389

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
)

// DialFunc opens an LDAP connection in the given mode and optionally binds.
// mode is ldap, ldaps, or starttls.
type DialFunc func(ctx context.Context, mode, addr string, req bootstrap.TLSRequest) error

func (e Engine) ReconcileTLS(ctx context.Context, req bootstrap.TLSRequest) (bootstrap.TLSResult, error) {
	if req.DialTimeout <= 0 {
		req.DialTimeout = 5 * time.Second
	}
	if req.BindDN == "" {
		req.BindDN = "cn=Directory Manager"
	}
	dial := e.Dial
	if dial == nil {
		dial = defaultDialBind
	}
	if req.Write {
		if err := e.applyBindPolicy(ctx, req); err != nil {
			return bootstrap.TLSResult{}, err
		}
	}
	var transports []string
	if req.UseLDAPS {
		if err := dial(ctx, "ldaps", ldapsDialAddr(req), req); err != nil {
			return bootstrap.TLSResult{}, bootstrap.PhaseError("tls", "tls", "LDAPS client connection failed").Wrap(err)
		}
		transports = append(transports, "ldaps")
	}
	if req.StartTLS {
		if err := dial(ctx, "starttls", ldapDialAddr(req), req); err != nil {
			return bootstrap.TLSResult{}, bootstrap.PhaseError("tls", "tls", "StartTLS client connection failed").Wrap(err)
		}
		transports = append(transports, "starttls")
	}
	if !req.AllowCleartext {
		err := dial(ctx, "ldap", ldapDialAddr(req), req)
		if err == nil {
			return bootstrap.TLSResult{}, bootstrap.PhaseError("tls", "cleartext_enabled", "cleartext simple bind is still accepted")
		}
	}
	offered, err := e.saslMechs(ctx, req)
	if err != nil {
		return bootstrap.TLSResult{}, bootstrap.PhaseError("tls", "sasl_missing", "could not read SASL mechanisms").Wrap(err)
	}
	for _, need := range req.RequiredSASL {
		if !containsFold(offered, need) {
			return bootstrap.TLSResult{}, bootstrap.PhaseError("tls", "sasl_missing", "required SASL mechanism is not offered")
		}
	}
	return bootstrap.TLSResult{Transports: transports, SASL: offered}, nil
}

func (e Engine) applyBindPolicy(ctx context.Context, req bootstrap.TLSRequest) error {
	secure := "on"
	if req.AllowCleartext {
		secure = "off"
	}
	if _, err := e.Runner.JSON(ctx, req.PasswordFile, req.Instance, []string{
		"security", "set", "--require-secure-authentication", secure,
	}); err != nil {
		return bootstrap.PhaseError("tls", "cleartext_enabled", "could not set require-secure-authentication").Wrap(err)
	}
	anon := "off"
	if req.AllowAnonymous {
		anon = "on"
	}
	if _, err := e.Runner.JSON(ctx, req.PasswordFile, req.Instance, []string{
		"config", "replace", "nsslapd-allow-anonymous-access=" + anon,
	}); err != nil {
		return bootstrap.PhaseError("tls", "cleartext_enabled", "could not set anonymous bind policy").Wrap(err)
	}
	return nil
}

func (e Engine) saslMechs(ctx context.Context, req bootstrap.TLSRequest) ([]string, error) {
	raw, err := e.Runner.JSON(ctx, req.PasswordFile, req.Instance, []string{"sasl", "get-mechs"})
	if err != nil {
		return nil, err
	}
	var doc struct {
		Items []string `json:"items"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	return doc.Items, nil
}

func defaultDialBind(ctx context.Context, mode, addr string, req bootstrap.TLSRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	tlsCfg, err := tlsConfig(bootstrap.WaitRequest{
		Host: req.Host, CAFile: req.CAFile, Insecure: req.Insecure, LDAPURL: req.LDAPURL,
	})
	if err != nil {
		return err
	}
	dialer := &net.Dialer{Timeout: req.DialTimeout}
	var conn *ldap.Conn
	switch mode {
	case "ldaps":
		url := withScheme(addr, "ldaps")
		conn, err = ldap.DialURL(url, ldap.DialWithDialer(dialer), ldap.DialWithTLSConfig(tlsCfg))
	case "starttls":
		url := withScheme(addr, "ldap")
		conn, err = ldap.DialURL(url, ldap.DialWithDialer(dialer))
		if err == nil {
			err = conn.StartTLS(tlsCfg)
		}
	default:
		url := withScheme(addr, "ldap")
		conn, err = ldap.DialURL(url, ldap.DialWithDialer(dialer))
	}
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetTimeout(req.DialTimeout)
	return conn.Bind(req.BindDN, req.Password.Reveal())
}

func withScheme(addr, scheme string) string {
	if strings.Contains(addr, "://") {
		return addr
	}
	return scheme + "://" + addr
}

func ldapsDialAddr(req bootstrap.TLSRequest) string {
	if req.LDAPURL != "" {
		return req.LDAPURL
	}
	return fmt.Sprintf("ldaps://%s", req.LDAPAddr)
}

func ldapDialAddr(req bootstrap.TLSRequest) string {
	if req.LDAPAddr != "" {
		return req.LDAPAddr
	}
	return "127.0.0.1:3389"
}

func containsFold(have []string, want string) bool {
	for _, h := range have {
		if strings.EqualFold(h, want) {
			return true
		}
	}
	return false
}
