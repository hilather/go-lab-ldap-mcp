package ds389

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// treeConn is the LDAP surface used by phase.tree and phase.seed. Tests replace TreeDial.
type treeConn interface {
	Search(req *ldap.SearchRequest) (*ldap.SearchResult, error)
	Add(req *ldap.AddRequest) error
	Modify(req *ldap.ModifyRequest) error
	Del(req *ldap.DelRequest) error
	Bind(username, password string) error
	Close() error
}

// TreeDialFunc opens a Directory Manager LDAP session for tree reconcile.
type TreeDialFunc func(ctx context.Context, req bootstrap.TreeRequest) (treeConn, error)

func (e Engine) ReconcileTree(ctx context.Context, req bootstrap.TreeRequest) (bootstrap.TreeResult, error) {
	if req.DialTimeout <= 0 {
		req.DialTimeout = 5 * time.Second
	}
	dial := e.TreeDial
	if dial == nil {
		dial = defaultTreeDial
	}
	conn, err := dial(ctx, req)
	if err != nil {
		return bootstrap.TreeResult{}, bootstrap.PhaseError("tree", "parent_failed", "could not bind as Directory Manager to apply the tree").Wrap(err)
	}
	defer conn.Close()

	var res bootstrap.TreeResult
	parents := []string{req.Suffix, req.PeopleDN, req.GroupsDN}
	for _, dn := range parents {
		if dn == "" {
			return res, bootstrap.PhaseError("tree", "parent_failed", "compiled tree DN is empty")
		}
		action, err := e.ensureEntry(conn, req, dn, "")
		if err != nil {
			return res, err
		}
		switch action {
		case "created":
			res.Created = append(res.Created, dn)
		case "matched":
			res.Matched = append(res.Matched, dn)
		}
	}
	if req.RuntimeDN == "" {
		return res, bootstrap.PhaseError("tree", "account_bind", "compiled runtime account DN is empty")
	}
	action, err := e.ensureEntry(conn, req, req.RuntimeDN, req.RuntimePassword.Reveal())
	if err != nil {
		return res, err
	}
	switch action {
	case "created":
		res.Created = append(res.Created, req.RuntimeDN)
	case "matched":
		res.Matched = append(res.Matched, req.RuntimeDN)
	}
	if req.Write && action == "matched" {
		if err := replacePassword(conn, req.RuntimeDN, req.RuntimePassword.Reveal()); err != nil {
			return res, bootstrap.PhaseError("tree", "account_bind", "could not set the runtime account password").Wrap(err)
		}
	}
	if err := e.bindRuntime(ctx, req); err != nil {
		return res, err
	}
	return res, nil
}

func (e Engine) ensureEntry(conn treeConn, req bootstrap.TreeRequest, dn, password string) (string, error) {
	ok, err := entryExists(conn, dn)
	if err != nil {
		code := "parent_failed"
		if dn == req.RuntimeDN {
			code = "account_bind"
		}
		return "", bootstrap.PhaseError("tree", code, "could not read directory entry").Wrap(err)
	}
	if ok {
		return "matched", nil
	}
	if !req.Write {
		if dn == req.RuntimeDN {
			return "", bootstrap.PhaseError("tree", "account_bind", "runtime account is not present")
		}
		return "", bootstrap.PhaseError("tree", "parent_failed", "planned parent is not present")
	}
	attrs, err := createAttrs(dn, password)
	if err != nil {
		return "", err
	}
	add := ldap.NewAddRequest(dn, nil)
	for _, a := range attrs {
		add.Attribute(a.Type, a.Vals)
	}
	if err := conn.Add(add); err != nil {
		if isAlreadyExists(err) {
			return "matched", nil
		}
		code := "parent_failed"
		pub := "could not create parent entry"
		if dn == req.RuntimeDN {
			code = "account_bind"
			pub = "could not create the runtime account"
		}
		return "", bootstrap.PhaseError("tree", code, pub).Wrap(err)
	}
	return "created", nil
}

func replacePassword(conn treeConn, dn, password string) error {
	if password == "" {
		return errors.New("password is empty")
	}
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Replace("userPassword", []string{password})
	return conn.Modify(mod)
}

func (e Engine) bindRuntime(ctx context.Context, req bootstrap.TreeRequest) error {
	if req.RuntimePassword.Reveal() == "" {
		return bootstrap.PhaseError("tree", "account_bind", "runtime account password is empty")
	}
	if e.RuntimeBind != nil {
		if err := e.RuntimeBind(ctx, req); err != nil {
			return bootstrap.PhaseError("tree", "account_bind", "runtime account LDAPS bind failed").Wrap(err)
		}
		return nil
	}
	if err := defaultRuntimeBind(ctx, req); err != nil {
		return bootstrap.PhaseError("tree", "account_bind", "runtime account LDAPS bind failed").Wrap(err)
	}
	return nil
}

func defaultRuntimeBind(ctx context.Context, req bootstrap.TreeRequest) error {
	conn, err := dialLDAP(ctx, req)
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.Bind(req.RuntimeDN, req.RuntimePassword.Reveal())
}

func defaultTreeDial(ctx context.Context, req bootstrap.TreeRequest) (treeConn, error) {
	conn, err := dialLDAP(ctx, req)
	if err != nil {
		return nil, err
	}
	if err := conn.Bind("cn=Directory Manager", req.DMPassword.Reveal()); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func dialLDAP(ctx context.Context, req bootstrap.TreeRequest) (*ldap.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	tlsCfg, err := tlsConfig(bootstrap.WaitRequest{
		Host: req.Host, CAFile: req.CAFile, Insecure: req.Insecure, LDAPURL: req.LDAPURL,
	})
	if err != nil {
		return nil, err
	}
	url, mode := treeDialTarget(req)
	dialer := &net.Dialer{Timeout: req.DialTimeout}
	var conn *ldap.Conn
	switch mode {
	case "ldaps":
		conn, err = ldap.DialURL(url, ldap.DialWithDialer(dialer), ldap.DialWithTLSConfig(tlsCfg))
	case "starttls":
		conn, err = ldap.DialURL(url, ldap.DialWithDialer(dialer))
		if err == nil {
			err = conn.StartTLS(tlsCfg)
		}
	default:
		conn, err = ldap.DialURL(url, ldap.DialWithDialer(dialer))
	}
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		return nil, err
	}
	conn.SetTimeout(req.DialTimeout)
	return conn, nil
}

func treeDialTarget(req bootstrap.TreeRequest) (url, mode string) {
	if req.LDAPURL != "" {
		if strings.HasPrefix(req.LDAPURL, "ldaps://") {
			return req.LDAPURL, "ldaps"
		}
		if req.StartTLS {
			return req.LDAPURL, "starttls"
		}
		return req.LDAPURL, "ldap"
	}
	if req.UseLDAPS || !req.StartTLS {
		addr := req.LDAPSAddr
		if addr == "" {
			addr = "127.0.0.1:3636"
		}
		return withScheme(addr, "ldaps"), "ldaps"
	}
	addr := req.LDAPAddr
	if addr == "" {
		addr = "127.0.0.1:3389"
	}
	return withScheme(addr, "ldap"), "starttls"
}

func entryExists(conn treeConn, dn string) (bool, error) {
	sr, err := conn.Search(&ldap.SearchRequest{
		BaseDN:     dn,
		Scope:      ldap.ScopeBaseObject,
		Filter:     "(objectClass=*)",
		Attributes: []string{"dn", "objectClass", "memberOf"},
	})
	if err != nil {
		if isNoSuchObject(err) {
			return false, nil
		}
		return false, err
	}
	return len(sr.Entries) > 0, nil
}

func createAttrs(dn, password string) ([]ldap.Attribute, error) {
	attr, value, err := leafAV(dn)
	if err != nil {
		return nil, bootstrap.PhaseError("tree", "parent_failed", "compiled DN is not valid").Wrap(err)
	}
	switch strings.ToLower(attr) {
	case "dc":
		return []ldap.Attribute{
			{Type: "objectClass", Vals: []string{"top", "domain"}},
			{Type: "dc", Vals: []string{value}},
		}, nil
	case "ou":
		return []ldap.Attribute{
			{Type: "objectClass", Vals: []string{"top", "organizationalUnit"}},
			{Type: "ou", Vals: []string{value}},
		}, nil
	case "uid":
		if password == "" {
			return nil, bootstrap.PhaseError("tree", "account_bind", "runtime account password is empty")
		}
		return []ldap.Attribute{
			{Type: "objectClass", Vals: []string{"top", "person", "organizationalPerson", "inetOrgPerson"}},
			{Type: "uid", Vals: []string{value}},
			{Type: "cn", Vals: []string{value}},
			{Type: "sn", Vals: []string{"runtime"}},
			{Type: "userPassword", Vals: []string{password}},
		}, nil
	default:
		return nil, bootstrap.PhaseError("tree", "parent_failed", "compiled DN uses an unsupported RDN attribute")
	}
}

func leafAV(dn string) (attr, value string, err error) {
	parsed, err := config.ParseDN(dn)
	if err != nil {
		return "", "", err
	}
	attr, value, ok := parsed.Leaf()
	if !ok {
		return "", "", errors.New("DN has no RDN")
	}
	return attr, value, nil
}

func isAlreadyExists(err error) bool {
	var le *ldap.Error
	return errors.As(err, &le) && le.ResultCode == ldap.LDAPResultEntryAlreadyExists
}

func isNoSuchObject(err error) bool {
	var le *ldap.Error
	return errors.As(err, &le) && le.ResultCode == ldap.LDAPResultNoSuchObject
}
