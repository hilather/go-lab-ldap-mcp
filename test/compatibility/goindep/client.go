// Package goindep is an independent go-ldap client used by T-115.
// It talks to 389 DS directly and does not use the LabLDAP pool.
package goindep

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/go-ldap/ldap/v3"
)

// Config is a single bind + search against a laboratory directory.
type Config struct {
	URL        string
	StartTLS   bool
	CAFile     string
	Insecure   bool
	ServerName string
	BindDN     string
	Password   string
	BaseDN     string
	Filter     string
	PageSize   uint32
}

// SearchWhoami binds, runs whoami when supported, and returns one paged search.
func SearchWhoami(cfg Config) (whoami string, dns []string, err error) {
	if cfg.Filter == "" {
		cfg.Filter = "(objectClass=*)"
	}
	tlsCfg, err := tlsConfig(cfg)
	if err != nil {
		return "", nil, err
	}
	var conn *ldap.Conn
	if cfg.StartTLS {
		conn, err = ldap.DialURL(cfg.URL)
		if err != nil {
			return "", nil, err
		}
		if err := conn.StartTLS(tlsCfg); err != nil {
			conn.Close()
			return "", nil, err
		}
	} else {
		conn, err = ldap.DialURL(cfg.URL, ldap.DialWithTLSConfig(tlsCfg))
		if err != nil {
			return "", nil, err
		}
	}
	defer conn.Close()
	if cfg.BindDN != "" {
		if err := conn.Bind(cfg.BindDN, cfg.Password); err != nil {
			return "", nil, err
		}
	}
	who := ""
	if res, werr := conn.WhoAmI(nil); werr == nil && res != nil {
		who = res.AuthzID
	}
	req := ldap.NewSearchRequest(
		cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		cfg.Filter,
		[]string{"dn"},
		nil,
	)
	page := cfg.PageSize
	if page == 0 {
		page = 2
	}
	res, err := conn.SearchWithPaging(req, page)
	if err != nil {
		return who, nil, err
	}
	for _, e := range res.Entries {
		dns = append(dns, e.DN)
	}
	return who, dns, nil
}

// PasswordReplace performs an LDAP modify replace of userPassword.
func PasswordReplace(cfg Config, targetDN, newPassword string) error {
	tlsCfg, err := tlsConfig(cfg)
	if err != nil {
		return err
	}
	conn, err := ldap.DialURL(cfg.URL, ldap.DialWithTLSConfig(tlsCfg))
	if err != nil {
		return err
	}
	defer conn.Close()
	if err := conn.Bind(cfg.BindDN, cfg.Password); err != nil {
		return err
	}
	mod := ldap.NewModifyRequest(targetDN, nil)
	mod.Replace("userPassword", []string{newPassword})
	return conn.Modify(mod)
}

func tlsConfig(cfg Config) (*tls.Config, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cfg.ServerName, InsecureSkipVerify: cfg.Insecure}
	if cfg.CAFile == "" {
		return tc, nil
	}
	pem, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates in %s", cfg.CAFile)
	}
	tc.RootCAs = pool
	return tc, nil
}
