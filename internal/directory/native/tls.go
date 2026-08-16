package native

import (
	"context"
	"strings"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

// ReconcileTLS verifies the daemon's transport and bind policy by
// probing it exactly as a client would: every compiled-secure transport
// must accept a Directory Manager session, cleartext bind must be
// refused unless the plan allows it, and anonymous bind must be refused
// unless the plan allows it. labldapd applies the posture itself at
// start, so Write performs no mutation.
func (e Engine) ReconcileTLS(ctx context.Context, req bootstrap.TLSRequest) (bootstrap.TLSResult, error) {
	dialTimeout := req.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = e.DialTimeout
	}
	if dialTimeout <= 0 {
		dialTimeout = defaultDialTimeout
	}
	bindDN := req.BindDN
	if bindDN == "" {
		bindDN = directoryManagerDN
	}
	probe := func(mode directory.Transport, addr string) (Probe, error) {
		return e.dialProbe(ctx, ProbeConfig{
			Address:     addr,
			Mode:        mode,
			ServerName:  req.Host,
			CAFile:      req.CAFile,
			Insecure:    req.Insecure,
			DialTimeout: dialTimeout,
		})
	}

	var transports []string
	if req.UseLDAPS {
		if err := probeBind(ctx, probe, directory.TransportLDAPS, ldapsDialAddr(req), bindDN, req.Password.Reveal()); err != nil {
			return bootstrap.TLSResult{}, bootstrap.PhaseError("tls", "tls", "LDAPS client connection failed").Wrap(err)
		}
		transports = append(transports, "ldaps")
	}
	if req.StartTLS {
		if err := probeBind(ctx, probe, directory.TransportStartTLS, ldapDialAddr(req), bindDN, req.Password.Reveal()); err != nil {
			return bootstrap.TLSResult{}, bootstrap.PhaseError("tls", "tls", "StartTLS client connection failed").Wrap(err)
		}
		transports = append(transports, "starttls")
	}
	if req.AllowCleartext {
		// The plan permits cleartext: prove the daemon actually serves it,
		// otherwise the compiled posture and the applied one disagree.
		if err := probeBind(ctx, probe, directory.TransportLDAP, ldapDialAddr(req), bindDN, req.Password.Reveal()); err != nil {
			return bootstrap.TLSResult{}, bootstrap.PhaseError("tls", "tls",
				"cleartext LDAP bind failed although allowCleartextBind is set").Wrap(err)
		}
		transports = append(transports, "ldap")
	} else {
		// Fail closed: a successful cleartext bind means the daemon's
		// applied policy is weaker than the plan.
		if err := probeBind(ctx, probe, directory.TransportLDAP, ldapDialAddr(req), bindDN, req.Password.Reveal()); err == nil {
			return bootstrap.TLSResult{}, bootstrap.PhaseError("tls", "cleartext_enabled", "cleartext simple bind is still accepted")
		}
	}
	if !req.AllowAnonymous {
		if err := probeBind(ctx, probe, directory.TransportLDAP, ldapDialAddr(req), "", ""); err == nil {
			return bootstrap.TLSResult{}, bootstrap.PhaseError("tls", "cleartext_enabled", "anonymous bind is still accepted")
		}
	}
	// labldapd offers no SASL mechanisms; any required mechanism fails
	// closed rather than being silently skipped.
	if len(req.RequiredSASL) > 0 {
		return bootstrap.TLSResult{}, bootstrap.PhaseError("tls", "sasl_missing",
			"required SASL mechanisms are not offered by the native engine: "+strings.Join(req.RequiredSASL, ","))
	}
	return bootstrap.TLSResult{Transports: transports}, nil
}

const defaultDialTimeout = 5 * time.Second

func probeBind(ctx context.Context, probe func(directory.Transport, string) (Probe, error), mode directory.Transport, addr, dn, password string) error {
	pr, err := probe(mode, addr)
	if err != nil {
		return err
	}
	defer func() { _ = pr.Close() }()
	return pr.Bind(ctx, dn, password)
}

func ldapsDialAddr(req bootstrap.TLSRequest) string {
	if req.LDAPURL != "" {
		return strings.TrimPrefix(strings.TrimPrefix(req.LDAPURL, "ldaps://"), "ldap://")
	}
	if req.LDAPSAddr != "" {
		return req.LDAPSAddr
	}
	return "127.0.0.1:3636"
}

func ldapDialAddr(req bootstrap.TLSRequest) string {
	if req.LDAPAddr != "" {
		return req.LDAPAddr
	}
	return "127.0.0.1:3389"
}
