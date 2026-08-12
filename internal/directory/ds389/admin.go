package ds389

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
)

// Admin is the bootstrap-only Directory Manager LDAP helper.
// Transports and internal/app must not import this type.
type Admin struct{}

func (Admin) Wait(ctx context.Context, req bootstrap.WaitRequest) (bootstrap.WaitResult, error) {
	if req.Deadline <= 0 {
		req.Deadline = 90 * time.Second
	}
	if req.DialTimeout <= 0 {
		req.DialTimeout = 5 * time.Second
	}
	deadline := time.Now().Add(req.Deadline)
	var last error
	for {
		if err := ctx.Err(); err != nil {
			return bootstrap.WaitResult{}, bootstrap.PhaseError("wait", "timeout", "engine wait cancelled").Wrap(err)
		}
		if time.Now().After(deadline) {
			if last == nil {
				return bootstrap.WaitResult{}, bootstrap.PhaseError("wait", "timeout", "engine did not become ready")
			}
			if keep, ok := asWaitPhase(last); ok {
				return bootstrap.WaitResult{}, keep
			}
			code, pub := classifyWait(last)
			return bootstrap.WaitResult{}, bootstrap.PhaseError("wait", code, pub).Wrap(last)
		}
		res, err := tryWaitOnce(ctx, req)
		if err == nil {
			return res, nil
		}
		last = err
		if keep, ok := asWaitPhase(err); ok && waitFieldCode(keep) == "tls" {
			return bootstrap.WaitResult{}, keep
		}
		// First-boot applies DS_DM_PASSWORD after slapd is already listening,
		// so invalid credentials must be retried until the deadline.
		if err := sleepJitter(ctx, 50*time.Millisecond, 250*time.Millisecond); err != nil {
			return bootstrap.WaitResult{}, bootstrap.PhaseError("wait", "timeout", "engine wait cancelled").Wrap(err)
		}
	}
}

func tryWaitOnce(ctx context.Context, req bootstrap.WaitRequest) (bootstrap.WaitResult, error) {
	tlsCfg, err := tlsConfig(req)
	if err != nil {
		return bootstrap.WaitResult{}, err
	}
	url, transport := dialURL(req)
	dialer := &net.Dialer{Timeout: req.DialTimeout}
	opts := []ldap.DialOpt{ldap.DialWithDialer(dialer)}
	if strings.HasPrefix(url, "ldaps://") {
		opts = append(opts, ldap.DialWithTLSConfig(tlsCfg))
	}
	conn, err := ldap.DialURL(url, opts...)
	if err != nil {
		return bootstrap.WaitResult{}, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.SetTimeout(req.DialTimeout)

	if transport == "starttls" {
		if err := conn.StartTLS(tlsCfg); err != nil {
			return bootstrap.WaitResult{}, fmt.Errorf("starttls: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return bootstrap.WaitResult{}, err
	}
	if err := conn.Bind(req.BindDN, req.Password.Reveal()); err != nil {
		return bootstrap.WaitResult{}, fmt.Errorf("bind: %w", err)
	}
	sr, err := conn.Search(&ldap.SearchRequest{
		BaseDN:     "",
		Scope:      ldap.ScopeBaseObject,
		Filter:     "(objectClass=*)",
		Attributes: []string{"namingContexts", "vendorName"},
	})
	if err != nil {
		return bootstrap.WaitResult{}, fmt.Errorf("rootdse: %w", err)
	}
	nctx := 0
	if len(sr.Entries) > 0 {
		nctx = len(sr.Entries[0].GetAttributeValues("namingContexts"))
	}
	return bootstrap.WaitResult{Transport: transport, NamingContexts: nctx}, nil
}

func dialURL(req bootstrap.WaitRequest) (url, transport string) {
	if req.LDAPURL != "" {
		if strings.HasPrefix(req.LDAPURL, "ldaps://") {
			return req.LDAPURL, "ldaps"
		}
		if req.StartTLS {
			return req.LDAPURL, "starttls"
		}
		return req.LDAPURL, "ldap"
	}
	if req.UseLDAPS {
		return fmt.Sprintf("ldaps://%s:%d", req.Host, req.LDAPSPort), "ldaps"
	}
	if req.StartTLS {
		return fmt.Sprintf("ldap://%s:%d", req.Host, req.LDAPPort), "starttls"
	}
	return fmt.Sprintf("ldap://%s:%d", req.Host, req.LDAPPort), "ldap"
}

func tlsConfig(req bootstrap.WaitRequest) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: hostName(req),
	}
	if req.Insecure {
		cfg.InsecureSkipVerify = true
		return cfg, nil
	}
	if req.CAFile != "" {
		pem, err := os.ReadFile(req.CAFile)
		if err != nil {
			return nil, bootstrap.PhaseError("wait", "tls", "directory CA file unreadable").Wrap(err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, bootstrap.PhaseError("wait", "tls", "directory CA file is not a PEM certificate")
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

func hostName(req bootstrap.WaitRequest) string {
	// Host is the certificate name (container hostname). LDAPURL may be
	// 127.0.0.1 with a remapped port and must not replace ServerName.
	if req.Host != "" {
		return req.Host
	}
	if req.LDAPURL != "" {
		u := strings.TrimPrefix(strings.TrimPrefix(req.LDAPURL, "ldaps://"), "ldap://")
		host, _, err := net.SplitHostPort(u)
		if err == nil {
			return host
		}
		return u
	}
	return ""
}

func isBindFailure(err error) bool {
	if err == nil {
		return false
	}
	var le *ldap.Error
	if errors.As(err, &le) {
		switch le.ResultCode {
		case ldap.LDAPResultInvalidCredentials, ldap.LDAPResultInappropriateAuthentication:
			return true
		}
	}
	return false
}

func classifyWait(err error) (code, public string) {
	if err == nil {
		return "timeout", "engine did not become ready"
	}
	if keep, ok := asWaitPhase(err); ok {
		return waitFieldCode(keep), keep.PublicMessage()
	}
	if isBindFailure(err) {
		return "bind", "Directory Manager bind failed"
	}
	msg := err.Error()
	if strings.Contains(msg, "certificate") || strings.Contains(msg, "starttls:") || strings.Contains(msg, "tls:") {
		return "tls", "directory TLS handshake failed"
	}
	return "timeout", "engine did not become ready"
}

func asWaitPhase(err error) (*apperr.Error, bool) {
	var e *apperr.Error
	if !errors.As(err, &e) || e == nil || e.Code() != apperr.CodeBootstrap {
		return nil, false
	}
	for _, f := range e.Fields() {
		if f.Path == "phase.wait" {
			return e, true
		}
	}
	return nil, false
}

func waitFieldCode(e *apperr.Error) string {
	for _, f := range e.Fields() {
		if f.Path == "phase.wait" && f.Code != "" {
			return f.Code
		}
	}
	return ""
}

func sleepJitter(ctx context.Context, min, max time.Duration) error {
	span := max - min
	n := min
	if span > 0 {
		r, err := rand.Int(rand.Reader, big.NewInt(int64(span)))
		if err == nil {
			n = min + time.Duration(r.Int64())
		}
	}
	t := time.NewTimer(n)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
