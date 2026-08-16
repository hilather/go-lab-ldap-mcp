package parity

import (
	"errors"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config/v1alpha1"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ds389"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ldapclient"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

// Control-plane fixture secrets. Dedicated from userPasswords so these
// cases can run on an engine that already executed the LDAP contract
// list. Never recorded in outcomes, logs, or the ledger.
const (
	cpUserPass    = "parity-cp-user-001"
	cpUserPassNew = "parity-cp-new-pass1"
	cpShortPass   = "short1"
)

// controlPlaneCase is one Contract-tier sequence executed through
// internal/app + ds389.Runtime (no HTTP) against each engine. 389 is
// oracle. Outcomes use the same opOutcome shape as the LDAP cases
// (field codes, bind-test outcomes, secret-stripped entries).
type controlPlaneCase struct {
	id   string
	name string
	run  func(c *cpEnv) []opOutcome
}

// controlPlaneCases is the contract §5 rule 2 list. Dedicated entry IDs
// keep these mutations off the LDAP contract fixture tree.
var controlPlaneCases = []controlPlaneCase{
	{"C13", "cp-create-user-visible", cpCreateUserVisible},
	{"C13", "cp-ldapadd-visible", cpLDAPAddVisible},
	{"C4/C11", "cp-set-password", cpSetPassword},
	{"C3", "cp-bind-test", cpBindTest},
	{"C9/D7", "cp-if-match", cpIfMatch},
	{"C7/D26", "cp-memberof", cpMemberOf},
}

// cpEnv is one engine with a Runtime pool and app.Services pointed at it.
type cpEnv struct {
	t    *testing.T
	fx   *fixture
	e    engine
	rt   *ds389.Runtime
	pool *ldapclient.Pool
	svc  *app.Services
	p    app.Principal
}

// startControlPlane wires ds389.Runtime + app.New against a running
// engine using the fixture runtime account (contract §5 rule 2).
func startControlPlane(t *testing.T, fx *fixture, e engine) *cpEnv {
	t.Helper()
	cfg := ldapclient.Config{
		Address:      e.addr(true),
		Transport:    directory.TransportLDAPS,
		CAFile:       e.caFile(t),
		ServerName:   e.serverName(),
		BindDN:       runtimeDN,
		BindPassword: observability.Secret(runtimePassword),
		DialTimeout:  8 * time.Second,
		PoolSize:     4,
	}
	pool, err := ldapclient.NewPool(cfg)
	if err != nil {
		t.Fatalf("parity: control-plane pool: %v", err)
	}
	t.Cleanup(func() { _ = pool.Close() })
	if err := pool.Do(t.Context(), func(c *ldapclient.Conn) error {
		return c.Ping(t.Context())
	}); err != nil {
		t.Fatalf("parity: control-plane runtime bind (%s): %v", e.name(), err)
	}
	rt, err := ds389.NewRuntime(pool, ds389.RuntimeConfig{
		Suffix:    suffixDN,
		PeopleDN:  peopleDN,
		GroupsDN:  groupsDN,
		RuntimeDN: runtimeDN,
		MarkerDN:  markerDN,
		Client:    cfg,
		SchemaTTL: time.Minute,
	})
	if err != nil {
		t.Fatalf("parity: control-plane runtime: %v", err)
	}
	svc := app.New(app.Deps{
		Users:     rt.Users(),
		Groups:    rt.Groups(),
		Search:    rt,
		Bind:      rt,
		Schema:    rt,
		Caps:      rt,
		Marker:    rt,
		PeopleDN:  peopleDN,
		GroupsDN:  groupsDN,
		Suffix:    suffixDN,
		RuntimeDN: runtimeDN,
		MarkerDN:  markerDN,
	})
	return &cpEnv{
		t: t, fx: fx, e: e, rt: rt, pool: pool, svc: svc,
		p: app.Principal{Kind: app.KindToken, ID: "parity-cp", Scopes: directory.ScopeSet{
			v1alpha1.ScopeDirectoryRead,
			v1alpha1.ScopeDirectoryWrite,
			v1alpha1.ScopeDirectoryPassword,
			v1alpha1.ScopeSchemaRead,
		}},
	}
}

// cpCreateUserVisible is C13: Users.Create is visible via Users.Get,
// app Search, and direct LDAP as DM.
func cpCreateUserVisible(c *cpEnv) []opOutcome {
	t, ctx, p := c.t, c.t.Context(), c.p
	_, err := c.svc.Users.Create(ctx, p, app.CreateUser{
		ID:       "cpalice",
		Password: observability.Secret(cpUserPass),
		Attributes: map[string]string{
			"sn": "Control", "givenName": "Alice", "description": "cp-create",
		},
	})
	out := []opOutcome{appErrOutcome(err)}
	if err != nil {
		return out
	}
	got, err := c.svc.Users.Get(ctx, p, "cpalice")
	out = append(out, appUserOutcome(got, err))

	page, err := c.svc.Query.Search(ctx, p, directory.SearchQuery{
		Base: peopleDN, Scope: directory.SearchScopeOne,
		Filter: "(uid=cpalice)", Attributes: []string{"uid"},
	})
	out = append(out, appSearchOutcome(page, err))

	dm := c.e.dm(t)
	defer dm.Close()
	out = append(out, readOutcome(dm, userDN("cpalice"), "uid"))
	return out
}

// cpLDAPAddVisible is C13: a DM ldapadd is visible through Users.Get.
func cpLDAPAddVisible(c *cpEnv) []opOutcome {
	t := c.t
	dm := c.e.dm(t)
	defer dm.Close()
	add := ldap.NewAddRequest(userDN("cpldapadd"), nil)
	add.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"})
	add.Attribute("uid", []string{"cpldapadd"})
	add.Attribute("cn", []string{"CP LDAP Add"})
	add.Attribute("sn", []string{"Add"})
	add.Attribute("userPassword", []string{cpUserPass})
	out := []opOutcome{codeOutcome(dm.Add(add))}

	got, err := c.svc.Users.Get(t.Context(), c.p, "cpldapadd")
	out = append(out, appUserOutcome(got, err))
	return out
}

// cpSetPassword is C4/C11: too-short → FieldConstraint; valid replace
// binds with the new secret and the old secret does not.
func cpSetPassword(c *cpEnv) []opOutcome {
	ctx, p := c.t.Context(), c.p
	u, err := c.svc.Users.Create(ctx, p, app.CreateUser{
		ID: "cppw", Password: observability.Secret(cpUserPass),
		Attributes: map[string]string{"sn": "Password"},
	})
	out := []opOutcome{appErrOutcome(err)}
	if err != nil {
		return out
	}
	err = c.svc.Users.SetPassword(ctx, p, "cppw", observability.Secret(cpShortPass), u.Revision)
	out = append(out, appErrOutcome(err))

	oldOK, err := c.svc.Query.BindTest(ctx, p, "cppw", observability.Secret(cpUserPass), directory.TransportLDAPS)
	out = append(out, appBindOutcome(oldOK, err))

	err = c.svc.Users.SetPassword(ctx, p, "cppw", observability.Secret(cpUserPassNew), u.Revision)
	out = append(out, appErrOutcome(err))

	newOK, err := c.svc.Query.BindTest(ctx, p, "cppw", observability.Secret(cpUserPassNew), directory.TransportLDAPS)
	out = append(out, appBindOutcome(newOK, err))
	oldDead, err := c.svc.Query.BindTest(ctx, p, "cppw", observability.Secret(cpUserPass), directory.TransportLDAPS)
	out = append(out, appBindOutcome(oldDead, err))
	return out
}

// cpBindTest is C3: unknown ≡ wrong password; malformed identity is
// invalid_credentials; nsAccountLock surfaces as disabled. Lockout
// (D19 marker union) is not asserted here — that is a PR-4 flip-checklist
// item once lookupBindIdentity reads accountUnlockTime.
func cpBindTest(c *cpEnv) []opOutcome {
	ctx, p := c.t.Context(), c.p
	u, err := c.svc.Users.Create(ctx, p, app.CreateUser{
		ID: "cpbind", Password: observability.Secret(cpUserPass),
		Attributes: map[string]string{"sn": "Bind"},
	})
	out := []opOutcome{appErrOutcome(err)}
	if err != nil {
		return out
	}
	ok, err := c.svc.Query.BindTest(ctx, p, "cpbind", observability.Secret(cpUserPass), directory.TransportLDAPS)
	out = append(out, appBindOutcome(ok, err))
	wrong, err := c.svc.Query.BindTest(ctx, p, "cpbind", observability.Secret("parity-cp-WRONG-00"), directory.TransportLDAPS)
	out = append(out, appBindOutcome(wrong, err))
	unknown, err := c.svc.Query.BindTest(ctx, p, "cpghost", observability.Secret("parity-cp-WRONG-00"), directory.TransportLDAPS)
	out = append(out, appBindOutcome(unknown, err))
	malformed, err := c.svc.Query.BindTest(ctx, p, "not a dn===", observability.Secret(cpUserPass), directory.TransportLDAPS)
	out = append(out, appBindOutcome(malformed, err))

	disabled, err := c.svc.Users.SetEnabled(ctx, p, "cpbind", false, u.Revision)
	out = append(out, appErrOutcome(err))
	lockedBind, berr := c.svc.Query.BindTest(ctx, p, "cpbind", observability.Secret(cpUserPass), directory.TransportLDAPS)
	out = append(out, appBindOutcome(lockedBind, berr))

	var reenable error
	if err == nil {
		_, reenable = c.svc.Users.SetEnabled(ctx, p, "cpbind", true, disabled.Revision)
	} else {
		reenable = err
	}
	out = append(out, appErrOutcome(reenable))
	restored, err := c.svc.Query.BindTest(ctx, p, "cpbind", observability.Secret(cpUserPass), directory.TransportLDAPS)
	out = append(out, appBindOutcome(restored, err))
	return out
}

// cpIfMatch is C9/D7: checkRev rejects a stale revision with FieldConflict
// on both engines; a matching revision commits.
func cpIfMatch(c *cpEnv) []opOutcome {
	ctx, p := c.t.Context(), c.p
	u, err := c.svc.Users.Create(ctx, p, app.CreateUser{
		ID: "cpifm", Password: observability.Secret(cpUserPass),
		Attributes: map[string]string{"sn": "Ifmatch", "description": "orig"},
	})
	out := []opOutcome{appErrOutcome(err)}
	if err != nil {
		return out
	}
	_, err = c.svc.Users.Update(ctx, p, "cpifm", app.UpdateUser{
		Revision:  "deadbeef",
		UserPatch: directory.UserPatch{Attributes: map[string]string{"description": "stale"}},
	})
	out = append(out, appErrOutcome(err))

	patched, err := c.svc.Users.Update(ctx, p, "cpifm", app.UpdateUser{
		Revision:  u.Revision,
		UserPatch: directory.UserPatch{Attributes: map[string]string{"description": "next"}},
	})
	out = append(out, appErrOutcome(err))
	_ = patched

	_, err = c.svc.Users.Update(ctx, p, "cpifm", app.UpdateUser{
		Revision:  u.Revision,
		UserPatch: directory.UserPatch{Attributes: map[string]string{"description": "again"}},
	})
	out = append(out, appErrOutcome(err))
	return out
}

// cpMemberOf is C7 plus D26 retain: membership appears on User.Groups;
// leftover nsmemberof stays after the last-member retract of this user.
func cpMemberOf(c *cpEnv) []opOutcome {
	ctx, p := c.t.Context(), c.p
	_, err := c.svc.Users.Create(ctx, p, app.CreateUser{
		ID: "cpmem", Password: observability.Secret(cpUserPass),
		Attributes: map[string]string{"sn": "Member"},
	})
	out := []opOutcome{appErrOutcome(err)}
	if err != nil {
		return out
	}
	_, err = c.svc.Users.Create(ctx, p, app.CreateUser{
		ID: "cpother", Password: observability.Secret(cpUserPass),
		Attributes: map[string]string{"sn": "Other"},
	})
	out = append(out, appErrOutcome(err))
	if err != nil {
		return out
	}
	g, err := c.svc.Groups.Create(ctx, p, directory.GroupSpec{
		ID:      "cpmemgrp",
		Members: []directory.MemberRef{{Kind: "user", ID: "cpother"}},
	})
	out = append(out, appErrOutcome(err))
	if err != nil {
		return out
	}
	sum, err := c.svc.Groups.AddMembers(ctx, p, "cpmemgrp",
		[]directory.MemberRef{{Kind: "user", ID: "cpmem"}}, g.Revision)
	out = append(out, appErrOutcome(err))
	if err != nil {
		return out
	}
	got, err := c.svc.Users.Get(ctx, p, "cpmem")
	out = append(out, appUserOutcome(got, err))

	_, err = c.svc.Groups.RemoveMembers(ctx, p, "cpmemgrp",
		[]directory.MemberRef{{Kind: "user", ID: "cpmem"}}, sum.Revision)
	out = append(out, appErrOutcome(err))
	got, err = c.svc.Users.Get(ctx, p, "cpmem")
	out = append(out, appUserOutcome(got, err))
	return out
}

// wantControlPlane is the engine-neutral expected sequence for a
// control-plane case. Hermetic native and the dual-engine runner both
// compare against this (389 remains the live oracle for mismatches).
func wantControlPlane(name string) []opOutcome {
	ok := appErrOutcome(nil)
	switch name {
	case "cp-create-user-visible":
		return []opOutcome{
			ok,
			wantUser("cpalice", true, false),
			opOutcome{Code: 0, Note: "ok", Entries: []canonEntry{{
				DN:    canonDN(userDN("cpalice")),
				Attrs: map[string][]string{"uid": {"cpalice"}},
			}}},
			opOutcome{Code: 0, Entries: []canonEntry{{
				DN:    canonDN(userDN("cpalice")),
				Attrs: map[string][]string{"uid": {"cpalice"}},
			}}},
		}
	case "cp-ldapadd-visible":
		return []opOutcome{
			{Code: 0},
			wantUser("cpldapadd", true, false),
		}
	case "cp-set-password":
		return []opOutcome{
			ok,
			{Code: -100, Note: directory.FieldConstraint},
			{Code: 0, Value: directory.BindOutcomeSuccess},
			ok,
			{Code: 0, Value: directory.BindOutcomeSuccess},
			{Code: 0, Value: directory.BindOutcomeInvalidCredentials},
		}
	case "cp-bind-test":
		inv := opOutcome{Code: 0, Value: directory.BindOutcomeInvalidCredentials}
		return []opOutcome{
			ok,
			{Code: 0, Value: directory.BindOutcomeSuccess},
			inv, inv, inv,
			ok,
			{Code: 0, Value: directory.BindOutcomeDisabled},
			ok,
			{Code: 0, Value: directory.BindOutcomeSuccess},
		}
	case "cp-if-match":
		return []opOutcome{
			ok,
			{Code: -100, Note: directory.FieldConflict},
			ok,
			{Code: -100, Note: directory.FieldConflict},
		}
	case "cp-memberof":
		return []opOutcome{
			ok, ok, ok, ok,
			wantUser("cpmem", true, true, "cpmemgrp"),
			ok,
			wantUser("cpmem", true, true),
		}
	default:
		return nil
	}
}

func wantUser(id string, enabled, memberOf bool, groups ...string) opOutcome {
	sort.Strings(groups)
	attrs := map[string][]string{
		"uid":        {id},
		"id":         {id},
		"enabled":    {strconv.FormatBool(enabled)},
		"nsmemberof": {strconv.FormatBool(memberOf)},
	}
	if len(groups) > 0 {
		attrs["groups"] = groups
	}
	return opOutcome{
		Code: 0, Note: "ok",
		Entries: []canonEntry{{DN: canonDN(userDN(id)), Attrs: attrs}},
	}
}

func appErrOutcome(err error) opOutcome {
	if err == nil {
		return opOutcome{Code: 0, Note: "ok"}
	}
	return opOutcome{Code: -100, Note: firstFieldCode(err)}
}

func appUserOutcome(u directory.User, err error) opOutcome {
	if err != nil {
		return appErrOutcome(err)
	}
	groups := make([]string, 0, len(u.Groups))
	for _, g := range u.Groups {
		groups = append(groups, string(g))
	}
	hasMO := false
	for _, oc := range u.ObjectClasses {
		if strings.EqualFold(oc, "nsmemberof") {
			hasMO = true
			break
		}
	}
	return wantUser(u.ID, u.Enabled, hasMO, groups...)
}

func appSearchOutcome(page directory.SearchPage, err error) opOutcome {
	if err != nil {
		return appErrOutcome(err)
	}
	entries := make([]canonEntry, 0, len(page.Entries))
	for _, e := range page.Entries {
		ce := canonEntry{DN: canonDN(e.DN), Attrs: map[string][]string{}}
		for _, a := range e.Attributes {
			name := strings.ToLower(a.Name)
			if secretAttrs[name] {
				continue
			}
			ce.Attrs[name] = append(ce.Attrs[name], a.Value)
		}
		for k := range ce.Attrs {
			sort.Strings(ce.Attrs[k])
		}
		entries = append(entries, ce)
	}
	sortCanon(entries)
	return opOutcome{Code: 0, Note: "ok", Entries: entries}
}

func appBindOutcome(res directory.BindTestResult, err error) opOutcome {
	if err != nil {
		return appErrOutcome(err)
	}
	return opOutcome{Code: 0, Value: res.Outcome}
}

func firstFieldCode(err error) string {
	if err == nil {
		return "ok"
	}
	var e *apperr.Error
	if !errors.As(err, &e) || e == nil {
		return "error"
	}
	for _, f := range e.Fields() {
		if f.Code != "" {
			return f.Code
		}
	}
	if e.Code() != "" {
		return string(e.Code())
	}
	return "error"
}
