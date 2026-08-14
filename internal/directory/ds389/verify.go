package ds389

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

const (
	probeUserUID    = "labldap-probe-user"
	probeGroupCN    = "labldap-probe-group"
	probeMarkerCN   = "labldap-probe-marker"
	probeLockoutUID = "labldap-probe-lockout"
	probeDisableUID = "labldap-probe-disable"
	probeOutsideDN  = "cn=labldap-probe,dc=unmanaged"
	probeWidenACI   = `(targetattr="description")(version 3.0; acl "labldap:probe-widen"; allow (write) userdn="ldap:///anyone";)`
)

func (e Engine) VerifyRuntime(ctx context.Context, req bootstrap.VerifyRequest) (bootstrap.VerifyResult, error) {
	if req.DialTimeout <= 0 {
		req.DialTimeout = 5 * time.Second
	}
	if req.SizeLimit <= 0 {
		req.SizeLimit = 8
	}
	if req.TimeLimit <= 0 {
		req.TimeLimit = 5 * time.Second
	}
	if err := e.bindRuntimeCheck(ctx, req.TreeRequest); err != nil {
		return bootstrap.VerifyResult{}, runtimeAllow("runtime account LDAPS bind failed").Wrap(secretFreeErr(err, req))
	}
	dm, err := e.dialDM(ctx, req.TreeRequest)
	if err != nil {
		return bootstrap.VerifyResult{}, runtimeAllow("could not bind as Directory Manager to stage runtime probes").Wrap(secretFreeErr(err, req))
	}
	defer dm.Close()
	rt, err := e.dialRuntime(ctx, req.TreeRequest)
	if err != nil {
		return bootstrap.VerifyResult{}, runtimeAllow("runtime account LDAPS bind failed").Wrap(secretFreeErr(err, req))
	}
	defer rt.Close()

	probeUser := "uid=" + probeUserUID + "," + req.PeopleDN
	probeGroup := "cn=" + probeGroupCN + "," + req.GroupsDN
	probeMarker := "cn=" + probeMarkerCN + "," + req.Suffix
	defer func() {
		_ = delIgnoreMissing(dm, probeGroup)
		_ = delIgnoreMissing(dm, probeUser)
		_ = delIgnoreMissing(dm, probeMarker)
	}()
	_ = delIgnoreMissing(dm, probeGroup)
	_ = delIgnoreMissing(dm, probeUser)
	_ = delIgnoreMissing(dm, probeMarker)

	var res bootstrap.VerifyResult
	if err := allowSearch(rt, req.Suffix, ldap.ScopeWholeSubtree, []string{"dn"}, req.SizeLimit, req.TimeLimit); err != nil {
		return res, runtimeAllow("runtime search of the managed suffix failed").Wrap(secretFreeErr(err, req))
	}
	res.Allowed++

	markerDN := req.MarkerDN
	if markerDN == "" {
		markerDN = "cn=labldap-baseline," + req.Suffix
	}
	entry, err := searchBase(rt, markerDN, []string{"cn", "objectClass", "serialNumber", "owner", "description"})
	if err != nil {
		if isNoSuchObject(err) {
			res.Skipped++
		} else {
			return res, runtimeAllow("runtime read of the baseline marker failed").Wrap(secretFreeErr(err, req))
		}
	} else if entry == nil || (entry.GetAttributeValue("cn") == "" && len(entry.GetAttributeValues("objectClass")) == 0) {
		return res, runtimeAllow("runtime read of the baseline marker returned no non-secret attributes")
	} else {
		res.Allowed++
	}

	if err := allowSearch(rt, "", ldap.ScopeBaseObject, []string{"namingContexts", "vendorName"}, 1, req.TimeLimit); err != nil {
		return res, runtimeAllow("runtime Root DSE read failed").Wrap(secretFreeErr(err, req))
	}
	if err := allowSearch(rt, "cn=schema", ldap.ScopeBaseObject, []string{"objectClass"}, 1, req.TimeLimit); err != nil {
		return res, runtimeAllow("runtime schema read failed").Wrap(secretFreeErr(err, req))
	}
	res.Allowed++

	if err := denyUserPasswordRead(rt, req); err != nil {
		return res, err
	}
	res.Denied++

	if err := expectDenied(rt.Modify(configReplace("cn=config", "nsslapd-listenhost", "127.0.0.1")), "runtime modified cn=config"); err != nil {
		return res, err
	}
	res.Denied++

	if err := expectOutsideDenied(rt.Add(outsideAdd())); err != nil {
		return res, err
	}
	res.Denied++

	if err := addProbeMarker(dm, probeMarker); err != nil {
		return res, runtimeAllow("could not stage the probe marker").Wrap(secretFreeErr(err, req))
	}
	if err := expectDenied(rt.Modify(attrReplace(probeMarker, "description", "probe-write")), "runtime modified the probe marker"); err != nil {
		return res, err
	}
	res.Denied++

	for _, dn := range []string{req.PeopleDN, req.GroupsDN, probeMarker} {
		mod := ldap.NewModifyRequest(dn, nil)
		mod.Add("aci", []string{probeWidenACI})
		if err := rt.Modify(mod); err == nil {
			_ = modifyACI(dm, dn, ldap.Change{Operation: ldap.DeleteAttribute, Modification: ldap.PartialAttribute{Type: "aci", Vals: []string{probeWidenACI}}})
			return res, runtimeDeny("runtime rewrote an ACI")
		}
	}
	res.Denied++

	pw := probeSecret()
	if err := addProbeUser(rt, probeUser, pw); err != nil {
		return res, runtimeAllow("runtime could not create a temporary user").Wrap(secretFreeErr(err, req))
	}
	if err := rt.Modify(attrReplace(probeUser, "description", "probe")); err != nil {
		return res, runtimeAllow("runtime could not modify a temporary user").Wrap(secretFreeErr(err, req))
	}
	res.Allowed++
	if err := replacePassword(rt, probeUser, pw); err != nil {
		return res, runtimeAllow("runtime could not set a temporary user password").Wrap(secretFreeErr(err, req))
	}
	res.Allowed++
	if err := addProbeGroup(rt, probeGroup, probeUser); err != nil {
		return res, runtimeAllow("runtime could not create a temporary group").Wrap(secretFreeErr(err, req))
	}
	if err := rt.Modify(attrReplace(probeGroup, "description", "probe")); err != nil {
		return res, runtimeAllow("runtime could not modify a temporary group").Wrap(secretFreeErr(err, req))
	}
	if err := rt.Del(ldap.NewDelRequest(probeGroup, nil)); err != nil {
		return res, runtimeAllow("runtime could not delete a temporary group").Wrap(secretFreeErr(err, req))
	}
	if err := rt.Del(ldap.NewDelRequest(probeUser, nil)); err != nil {
		return res, runtimeAllow("runtime could not delete a temporary user").Wrap(secretFreeErr(err, req))
	}
	res.Allowed++
	return res, nil
}

func (e Engine) VerifyApp(ctx context.Context, req bootstrap.VerifyRequest) (bootstrap.VerifyResult, error) {
	if req.DialTimeout <= 0 {
		req.DialTimeout = 5 * time.Second
	}
	dm, err := e.dialDM(ctx, req.TreeRequest)
	if err != nil {
		return bootstrap.VerifyResult{}, appErr("bind", "could not bind as Directory Manager to stage application probes").Wrap(secretFreeErr(err, req))
	}
	defer dm.Close()

	lockoutDN := "uid=" + probeLockoutUID + "," + req.PeopleDN
	disableDN := "uid=" + probeDisableUID + "," + req.PeopleDN
	defer func() {
		_ = delIgnoreMissing(dm, lockoutDN)
		_ = delIgnoreMissing(dm, disableDN)
	}()

	var res bootstrap.VerifyResult
	for _, u := range req.Users {
		if !u.Enabled {
			continue
		}
		pw, err := seedPassword(u)
		if err != nil {
			return res, appErr("bind", "enabled seed user password is not resolved")
		}
		if err := e.bindUser(ctx, req.TreeRequest, u.DN, pw); err != nil {
			return res, appErr("bind", "enabled seed user could not bind").Wrap(secretFreeErr(err, req))
		}
		res.Binds++
	}

	wrong := probeSecret()
	unknownDN := "uid=labldap-unknown," + req.PeopleDN
	sampleDN := unknownDN
	if u, ok := firstEnabled(req.Users); ok {
		sampleDN = u.DN
	}
	errWrong := e.bindUser(ctx, req.TreeRequest, sampleDN, wrong)
	errUnknown := e.bindUser(ctx, req.TreeRequest, unknownDN, wrong)
	if !isInvalidCredentials(errWrong) || !isInvalidCredentials(errUnknown) {
		return res, appErr("bind", "failed authentication must return generic invalid credentials")
	}

	if req.Policy.LockoutEnabled {
		if err := e.probeLockout(ctx, dm, req, lockoutDN); err != nil {
			return res, err
		}
	} else {
		res.SkippedLockout = 1
	}

	if err := e.probeDisablement(ctx, dm, req, disableDN); err != nil {
		return res, err
	}

	for _, g := range req.Groups {
		live, err := readEntry(dm, g.DN, []string{"cn", "member", "objectClass"})
		if err != nil {
			return res, appErr("memberof", "configured group is not present").Wrap(secretFreeErr(err, req))
		}
		if groupNeedsUpdate(live, g, memberDNs(g)) {
			return res, appErr("memberof", "configured group membership does not match the plan")
		}
		res.Groups++
		if len(g.Members) == 0 {
			continue
		}
		member := g.Members[0].DN
		uent, err := readEntry(dm, member, []string{"memberOf"})
		if err != nil {
			return res, appErr("memberof", "group member is not present").Wrap(secretFreeErr(err, req))
		}
		if !hasValue(uent, "memberOf", g.DN) {
			return res, appErr("memberof", "memberOf is missing after MemberOf fix-up")
		}
	}
	return res, nil
}

func (e Engine) probeLockout(ctx context.Context, dm treeConn, req bootstrap.VerifyRequest, dn string) error {
	pw := probeSecret()
	if err := addThrowawayUser(dm, dn, probeLockoutUID, pw); err != nil {
		return appErr("lockout", "could not create the isolated lockout user").Wrap(secretFreeErr(err, req))
	}
	max := req.Policy.MaxFailures
	if max <= 0 {
		max = 1
	}
	wrong := probeSecret()
	for i := 0; i < max; i++ {
		err := e.bindUser(ctx, req.TreeRequest, dn, wrong)
		if !isInvalidCredentials(err) && !isUnwillingToPerform(err) {
			return appErr("lockout", "lockout probe failed authentication did not return invalid credentials")
		}
	}
	if err := e.bindUser(ctx, req.TreeRequest, dn, pw); err == nil {
		return appErr("lockout", "isolated lockout user still bound after failure threshold")
	}
	if err := delIgnoreMissing(dm, dn); err != nil {
		return appErr("lockout", "could not remove the isolated lockout user").Wrap(secretFreeErr(err, req))
	}
	return nil
}

func (e Engine) probeDisablement(ctx context.Context, dm treeConn, req bootstrap.VerifyRequest, throwaway string) error {
	dn, pw, created, err := e.disableTarget(dm, req, throwaway)
	if err != nil {
		return err
	}
	if created {
		defer func() { _ = delIgnoreMissing(dm, throwaway) }()
	} else {
		defer func() { _ = unlockAccount(dm, dn) }()
	}
	if err := lockAccount(dm, dn); err != nil {
		return appErr("bind", "could not disable the probe account").Wrap(secretFreeErr(err, req))
	}
	err = e.bindUser(ctx, req.TreeRequest, dn, pw)
	if !isUnwillingToPerform(err) {
		return appErr("bind", "disabled account bind must return unwilling to perform")
	}
	if created {
		return delIgnoreMissing(dm, throwaway)
	}
	if err := unlockAccount(dm, dn); err != nil {
		return appErr("bind", "could not re-enable the probe account").Wrap(secretFreeErr(err, req))
	}
	return nil
}

func (e Engine) disableTarget(dm treeConn, req bootstrap.VerifyRequest, throwaway string) (dn, pw string, created bool, err error) {
	if u, ok := firstEnabled(req.Users); ok {
		p, e := seedPassword(u)
		if e != nil {
			return "", "", false, appErr("bind", "enabled seed user password is not resolved")
		}
		return u.DN, p, false, nil
	}
	pw = probeSecret()
	if err := addThrowawayUser(dm, throwaway, probeDisableUID, pw); err != nil {
		return "", "", false, appErr("bind", "could not create the isolated disablement user").Wrap(secretFreeErr(err, req))
	}
	return throwaway, pw, true, nil
}

func (e Engine) bindRuntimeCheck(ctx context.Context, req bootstrap.TreeRequest) error {
	if e.RuntimeBind != nil {
		return e.RuntimeBind(ctx, req)
	}
	return defaultRuntimeBind(ctx, req)
}

func (e Engine) dialDM(ctx context.Context, req bootstrap.TreeRequest) (treeConn, error) {
	dial := e.TreeDial
	if dial == nil {
		dial = defaultTreeDial
	}
	return dial(ctx, req)
}

func (e Engine) dialRuntime(ctx context.Context, req bootstrap.TreeRequest) (treeConn, error) {
	if e.RuntimeDial != nil {
		return e.RuntimeDial(ctx, req)
	}
	return defaultRuntimeDial(ctx, req)
}

func defaultRuntimeDial(ctx context.Context, req bootstrap.TreeRequest) (treeConn, error) {
	conn, err := dialLDAP(ctx, req)
	if err != nil {
		return nil, err
	}
	if err := conn.Bind(req.RuntimeDN, req.RuntimePassword.Reveal()); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (e Engine) bindUser(ctx context.Context, req bootstrap.TreeRequest, dn, password string) error {
	if e.UserBind != nil {
		return e.UserBind(ctx, req, dn, password)
	}
	if e.SeedBind != nil {
		return e.SeedBind(ctx, req, dn, password)
	}
	return defaultSeedBind(ctx, req, dn, password)
}

func allowSearch(conn treeConn, base string, scope int, attrs []string, size int, limit time.Duration) error {
	sec := int(limit.Seconds())
	if sec <= 0 {
		sec = 5
	}
	_, err := conn.Search(&ldap.SearchRequest{
		BaseDN:     base,
		Scope:      scope,
		Filter:     "(objectClass=*)",
		Attributes: attrs,
		SizeLimit:  size,
		TimeLimit:  sec,
	})
	if err != nil && isSizeOrTimeLimit(err) {
		return nil
	}
	return err
}

func searchBase(conn treeConn, dn string, attrs []string) (*ldap.Entry, error) {
	sr, err := conn.Search(&ldap.SearchRequest{
		BaseDN:     dn,
		Scope:      ldap.ScopeBaseObject,
		Filter:     "(objectClass=*)",
		Attributes: attrs,
	})
	if err != nil {
		return nil, err
	}
	if len(sr.Entries) == 0 {
		return nil, ldap.NewError(ldap.LDAPResultNoSuchObject, nil)
	}
	return sr.Entries[0], nil
}

func denyUserPasswordRead(conn treeConn, req bootstrap.VerifyRequest) error {
	// suffix-read denies userPassword. People-write still grants read of
	// non-aci attributes under ou=people, so this probe is base-scope on
	// the suffix (and marker when present), not on a user entry.
	dns := []string{req.Suffix}
	if req.MarkerDN != "" {
		dns = append(dns, req.MarkerDN)
	}
	for _, dn := range dns {
		sr, err := conn.Search(&ldap.SearchRequest{
			BaseDN:     dn,
			Scope:      ldap.ScopeBaseObject,
			Filter:     "(objectClass=*)",
			Attributes: []string{"userPassword"},
		})
		if err != nil {
			if isInsufficientAccess(err) || isNoSuchObject(err) {
				continue
			}
			return runtimeDeny("runtime userPassword read failed unexpectedly").Wrap(secretFreeErr(err, req))
		}
		if len(sr.Entries) == 0 {
			continue
		}
		if vals := sr.Entries[0].GetAttributeValues("userPassword"); len(vals) > 0 && strings.TrimSpace(vals[0]) != "" {
			return runtimeDeny("runtime read userPassword via suffix-read")
		}
	}
	return nil
}

func expectDenied(err error, public string) error {
	if err == nil {
		return runtimeDeny(public)
	}
	return nil
}

func expectOutsideDenied(err error) error {
	if err == nil {
		return runtimeDeny("runtime created an entry outside the managed suffix")
	}
	if isNoSuchObject(err) || isNamingViolation(err) || isInsufficientAccess(err) || isUnwillingToPerform(err) {
		return nil
	}
	return nil
}

func addProbeMarker(conn treeConn, dn string) error {
	add := ldap.NewAddRequest(dn, nil)
	add.Attribute("objectClass", []string{"top", "device"})
	add.Attribute("cn", []string{probeMarkerCN})
	add.Attribute("serialNumber", []string{"probe"})
	add.Attribute("description", []string{"probe"})
	return conn.Add(add)
}

func addProbeUser(conn treeConn, dn, password string) error {
	add := ldap.NewAddRequest(dn, nil)
	add.Attribute("objectClass", config.RequiredUserObjectClasses())
	add.Attribute("uid", []string{probeUserUID})
	add.Attribute("cn", []string{probeUserUID})
	add.Attribute("sn", []string{probeUserUID})
	add.Attribute("userPassword", []string{password})
	return conn.Add(add)
}

func addProbeGroup(conn treeConn, dn, member string) error {
	add := ldap.NewAddRequest(dn, nil)
	add.Attribute("objectClass", []string{"top", "groupOfNames"})
	add.Attribute("cn", []string{probeGroupCN})
	add.Attribute("member", []string{member})
	return conn.Add(add)
}

func addThrowawayUser(conn treeConn, dn, uid, password string) error {
	add := ldap.NewAddRequest(dn, nil)
	add.Attribute("objectClass", config.RequiredUserObjectClasses())
	add.Attribute("uid", []string{uid})
	add.Attribute("cn", []string{uid})
	add.Attribute("sn", []string{uid})
	add.Attribute("userPassword", []string{password})
	return conn.Add(add)
}

func lockAccount(conn treeConn, dn string) error {
	return conn.Modify(attrReplace(dn, "nsAccountLock", "true"))
}

func unlockAccount(conn treeConn, dn string) error {
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Delete("nsAccountLock", nil)
	err := conn.Modify(mod)
	if err != nil && isNoSuchAttribute(err) {
		return nil
	}
	return err
}

func attrReplace(dn, name, value string) *ldap.ModifyRequest {
	mod := ldap.NewModifyRequest(dn, nil)
	mod.Replace(name, []string{value})
	return mod
}

func configReplace(dn, name, value string) *ldap.ModifyRequest {
	return attrReplace(dn, name, value)
}

func outsideAdd() *ldap.AddRequest {
	add := ldap.NewAddRequest(probeOutsideDN, nil)
	add.Attribute("objectClass", []string{"top", "device"})
	add.Attribute("cn", []string{"labldap-probe"})
	return add
}

func firstEnabled(users []config.NormalizedUser) (config.NormalizedUser, bool) {
	for _, u := range users {
		if u.Enabled {
			return u, true
		}
	}
	return config.NormalizedUser{}, false
}

func probeSecret() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return "probe-" + hex.EncodeToString(b[:])
}

func runtimeAllow(public string) *apperr.Error {
	return bootstrap.PhaseError("verify_runtime", "allow_failed", public)
}

func runtimeDeny(public string) *apperr.Error {
	return bootstrap.PhaseError("verify_runtime", "deny_failed", public)
}

func appErr(code, public string) *apperr.Error {
	return bootstrap.PhaseError("verify_app", code, public)
}

func secretFreeErr(err error, req bootstrap.VerifyRequest) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	secrets := []string{req.RuntimePassword.Reveal(), req.DMPassword.Reveal()}
	for _, u := range req.Users {
		if u.Password != nil {
			secrets = append(secrets, u.Password.Value.Reveal())
		}
	}
	for _, s := range secrets {
		if s != "" && strings.Contains(msg, s) {
			return errors.New("directory operation failed")
		}
	}
	return err
}

func isInsufficientAccess(err error) bool {
	return ldapCode(err) == ldap.LDAPResultInsufficientAccessRights
}

func isInvalidCredentials(err error) bool {
	return ldapCode(err) == ldap.LDAPResultInvalidCredentials
}

func isUnwillingToPerform(err error) bool {
	return ldapCode(err) == ldap.LDAPResultUnwillingToPerform
}

func isNamingViolation(err error) bool {
	return ldapCode(err) == ldap.LDAPResultNamingViolation
}

func isSizeOrTimeLimit(err error) bool {
	c := ldapCode(err)
	return c == ldap.LDAPResultSizeLimitExceeded || c == ldap.LDAPResultTimeLimitExceeded
}

func isNoSuchAttribute(err error) bool {
	return ldapCode(err) == ldap.LDAPResultNoSuchAttribute
}

func ldapCode(err error) uint16 {
	var le *ldap.Error
	if errors.As(err, &le) {
		return le.ResultCode
	}
	return 0
}
