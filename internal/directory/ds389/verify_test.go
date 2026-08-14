package ds389

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

type verifyMem struct {
	*seedMem
	configModOK  bool
	aciModOK     bool
	markerModOK  bool
	outsideOK    bool
	showPassword bool
}

func newVerifyMem() *verifyMem {
	return &verifyMem{seedMem: &seedMem{entries: baseEntries()}}
}

func (m *verifyMem) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	if req.BaseDN == "" || strings.EqualFold(req.BaseDN, "cn=schema") {
		return &ldap.SearchResult{Entries: []*ldap.Entry{{DN: req.BaseDN, Attributes: []*ldap.EntryAttribute{
			{Name: "objectClass", Values: []string{"top"}},
			{Name: "namingContexts", Values: []string{"dc=example,dc=test"}},
		}}}}, nil
	}
	sr, err := m.seedMem.Search(req)
	if err != nil {
		return sr, err
	}
	if !m.showPassword {
		for _, e := range sr.Entries {
			setAttr(e, "userPassword", nil)
		}
	}
	return sr, nil
}

func (m *verifyMem) Add(req *ldap.AddRequest) error {
	if strings.EqualFold(req.DN, probeOutsideDN) {
		if m.outsideOK {
			return m.seedMem.Add(req)
		}
		return ldap.NewError(ldap.LDAPResultNoSuchObject, errors.New("no such object"))
	}
	return m.seedMem.Add(req)
}

func (m *verifyMem) Modify(req *ldap.ModifyRequest) error {
	if strings.EqualFold(req.DN, "cn=config") {
		if m.configModOK {
			return nil
		}
		return ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("denied"))
	}
	if isACIChange(req) && !m.aciModOK {
		return ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("denied"))
	}
	if strings.HasPrefix(strings.ToLower(req.DN), "cn="+probeMarkerCN) && !m.markerModOK && !isACIChange(req) {
		return ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("denied"))
	}
	return m.seedMem.Modify(req)
}

func isACIChange(req *ldap.ModifyRequest) bool {
	for _, ch := range req.Changes {
		if strings.EqualFold(ch.Modification.Type, "aci") {
			return true
		}
	}
	return false
}

func sampleVerifyReq() bootstrap.VerifyRequest {
	pw := config.ResolvedSecret{Value: observability.Secret("alice-seed-secret")}
	return bootstrap.VerifyRequest{
		TreeRequest: bootstrap.TreeRequest{
			Suffix:          "dc=example,dc=test",
			PeopleDN:        "ou=people,dc=example,dc=test",
			GroupsDN:        "ou=groups,dc=example,dc=test",
			RuntimeDN:       "uid=rt,ou=people,dc=example,dc=test",
			RuntimePassword: observability.Secret("runtime-secret"),
			DMPassword:      observability.Secret("dm-secret"),
			Write:           true,
		},
		MarkerDN: "cn=labldap-baseline,dc=example,dc=test",
		Users: []config.NormalizedUser{{
			ID: "alice", UID: "alice", DN: "uid=alice,ou=people,dc=example,dc=test",
			Enabled: true, Password: &pw, ObjectClasses: config.RequiredUserObjectClasses(),
		}},
		Groups: []config.NormalizedGroup{{
			ID: "staff", DN: "cn=staff,ou=groups,dc=example,dc=test",
			Members: []config.MemberRef{{Kind: "user", ID: "alice", DN: "uid=alice,ou=people,dc=example,dc=test"}},
		}},
		Policy: config.NormalizedPolicy{LockoutEnabled: false},
	}
}

func testVerifyEngine(mem *verifyMem, bind func(dn, password string) error) Engine {
	return Engine{
		TreeDial:    func(context.Context, bootstrap.TreeRequest) (treeConn, error) { return mem, nil },
		RuntimeDial: func(context.Context, bootstrap.TreeRequest) (treeConn, error) { return mem, nil },
		RuntimeBind: func(context.Context, bootstrap.TreeRequest) error { return nil },
		UserBind: func(_ context.Context, _ bootstrap.TreeRequest, dn, password string) error {
			if bind != nil {
				return bind(dn, password)
			}
			return nil
		},
	}
}

func TestVerifyRuntimeAllowAndDeny(t *testing.T) {
	mem := newVerifyMem()
	res, err := testVerifyEngine(mem, nil).VerifyRuntime(t.Context(), sampleVerifyReq())
	if err != nil {
		t.Fatal(err)
	}
	if res.Allowed == 0 || res.Denied == 0 {
		t.Fatalf("counts = %+v", res)
	}
	if res.Skipped != 1 {
		t.Fatalf("missing marker should skip: %+v", res)
	}
	for _, dn := range []string{
		"uid=" + probeUserUID + ",ou=people,dc=example,dc=test",
		"cn=" + probeGroupCN + ",ou=groups,dc=example,dc=test",
		"cn=" + probeMarkerCN + ",dc=example,dc=test",
	} {
		if _, ok := mem.entries[strings.ToLower(dn)]; ok {
			t.Fatalf("probe left behind: %s", dn)
		}
	}
}

func TestVerifyRuntimeDenyFailedConfig(t *testing.T) {
	mem := newVerifyMem()
	mem.configModOK = true
	_, err := testVerifyEngine(mem, nil).VerifyRuntime(t.Context(), sampleVerifyReq())
	if err == nil || !fieldHas(err, "phase.verify_runtime", "deny_failed") {
		t.Fatalf("%v", err)
	}
	apperr.Assert(t, err).Code(apperr.CodeBootstrap).FieldPath("phase.verify_runtime")
	if strings.Contains(err.Error(), "runtime-secret") || strings.Contains(err.Error(), "dm-secret") {
		t.Fatal("error leaked password")
	}
}

func TestVerifyRuntimeDenyFailedACI(t *testing.T) {
	mem := newVerifyMem()
	mem.aciModOK = true
	_, err := testVerifyEngine(mem, nil).VerifyRuntime(t.Context(), sampleVerifyReq())
	if err == nil || !fieldHas(err, "phase.verify_runtime", "deny_failed") {
		t.Fatalf("%v", err)
	}
}

func TestVerifyRuntimeDenyFailedPasswordRead(t *testing.T) {
	mem := newVerifyMem()
	mem.showPassword = true
	mem.entries["dc=example,dc=test"].Attributes = append(
		mem.entries["dc=example,dc=test"].Attributes,
		&ldap.EntryAttribute{Name: "userPassword", Values: []string{"hidden"}},
	)
	_, err := testVerifyEngine(mem, nil).VerifyRuntime(t.Context(), sampleVerifyReq())
	if err == nil || !fieldHas(err, "phase.verify_runtime", "deny_failed") {
		t.Fatalf("%v", err)
	}
}

func TestVerifyRuntimeCleansProbesOnAllowFailure(t *testing.T) {
	mem := newVerifyMem()
	mem.seedMem.failPWAfterAdd = true
	_, err := testVerifyEngine(mem, nil).VerifyRuntime(t.Context(), sampleVerifyReq())
	if err == nil || !fieldHas(err, "phase.verify_runtime", "allow_failed") {
		t.Fatalf("%v", err)
	}
	if _, ok := mem.entries["uid="+probeUserUID+",ou=people,dc=example,dc=test"]; ok {
		t.Fatal("probe user left after allow_failed")
	}
	if _, ok := mem.entries["cn="+probeMarkerCN+",dc=example,dc=test"]; ok {
		t.Fatal("probe marker left after allow_failed")
	}
}

func TestVerifyAppBindsAndSkipLockout(t *testing.T) {
	mem := newVerifyMem()
	mem.entries["uid=alice,ou=people,dc=example,dc=test"] = &ldap.Entry{
		DN: "uid=alice,ou=people,dc=example,dc=test",
		Attributes: []*ldap.EntryAttribute{
			{Name: "uid", Values: []string{"alice"}},
			{Name: "memberOf", Values: []string{"cn=staff,ou=groups,dc=example,dc=test"}},
		},
	}
	mem.entries["cn=staff,ou=groups,dc=example,dc=test"] = &ldap.Entry{
		DN: "cn=staff,ou=groups,dc=example,dc=test",
		Attributes: []*ldap.EntryAttribute{
			{Name: "cn", Values: []string{"staff"}},
			{Name: "objectClass", Values: []string{"groupOfNames"}},
			{Name: "member", Values: []string{"uid=alice,ou=people,dc=example,dc=test"}},
		},
	}
	res, err := testVerifyEngine(mem, func(dn, password string) error {
		if e := mem.entries[strings.ToLower(dn)]; e != nil && accountLocked(e) {
			return ldap.NewError(ldap.LDAPResultUnwillingToPerform, errors.New("locked"))
		}
		if password == "alice-seed-secret" && strings.Contains(dn, "alice") {
			return nil
		}
		return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid"))
	}).VerifyApp(t.Context(), sampleVerifyReq())
	if err != nil {
		t.Fatal(err)
	}
	if res.Binds != 1 || res.SkippedLockout != 1 || res.Groups != 1 {
		t.Fatalf("res=%+v", res)
	}
}

func TestVerifyAppBindFailure(t *testing.T) {
	mem := newVerifyMem()
	_, err := testVerifyEngine(mem, func(dn, password string) error {
		return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid"))
	}).VerifyApp(t.Context(), sampleVerifyReq())
	if err == nil || !fieldHas(err, "phase.verify_app", "bind") {
		t.Fatalf("%v", err)
	}
	if strings.Contains(err.Error(), "alice-seed-secret") {
		t.Fatal("error leaked password")
	}
}

func TestVerifyAppLockoutIsolated(t *testing.T) {
	mem := newVerifyMem()
	mem.entries["uid=alice,ou=people,dc=example,dc=test"] = &ldap.Entry{
		DN: "uid=alice,ou=people,dc=example,dc=test",
		Attributes: []*ldap.EntryAttribute{
			{Name: "uid", Values: []string{"alice"}},
			{Name: "memberOf", Values: []string{"cn=staff,ou=groups,dc=example,dc=test"}},
		},
	}
	mem.entries["cn=staff,ou=groups,dc=example,dc=test"] = &ldap.Entry{
		DN: "cn=staff,ou=groups,dc=example,dc=test",
		Attributes: []*ldap.EntryAttribute{
			{Name: "cn", Values: []string{"staff"}},
			{Name: "objectClass", Values: []string{"groupOfNames"}},
			{Name: "member", Values: []string{"uid=alice,ou=people,dc=example,dc=test"}},
		},
	}
	fails := map[string]int{}
	req := sampleVerifyReq()
	req.Policy = config.NormalizedPolicy{LockoutEnabled: true, MaxFailures: 2, LockoutDuration: 60}
	_, err := testVerifyEngine(mem, func(dn, password string) error {
		if strings.Contains(dn, probeLockoutUID) {
			fails[dn]++
			if fails[dn] > 2 {
				return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("locked"))
			}
			if password != "alice-seed-secret" {
				return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid"))
			}
			return nil
		}
		if accountLocked(mem.entries[strings.ToLower(dn)]) {
			return ldap.NewError(ldap.LDAPResultUnwillingToPerform, errors.New("locked"))
		}
		if password == "alice-seed-secret" && strings.Contains(dn, "alice") {
			return nil
		}
		return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid"))
	}).VerifyApp(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := mem.entries["uid="+probeLockoutUID+",ou=people,dc=example,dc=test"]; ok {
		t.Fatal("lockout probe user left behind")
	}
	if _, ok := mem.entries["uid=alice,ou=people,dc=example,dc=test"]; !ok {
		t.Fatal("lockout probe deleted alice")
	}
}

func TestVerifyAppMemberOfMissing(t *testing.T) {
	mem := newVerifyMem()
	mem.entries["uid=alice,ou=people,dc=example,dc=test"] = &ldap.Entry{
		DN:         "uid=alice,ou=people,dc=example,dc=test",
		Attributes: []*ldap.EntryAttribute{{Name: "uid", Values: []string{"alice"}}},
	}
	mem.entries["cn=staff,ou=groups,dc=example,dc=test"] = &ldap.Entry{
		DN: "cn=staff,ou=groups,dc=example,dc=test",
		Attributes: []*ldap.EntryAttribute{
			{Name: "cn", Values: []string{"staff"}},
			{Name: "objectClass", Values: []string{"groupOfNames"}},
			{Name: "member", Values: []string{"uid=alice,ou=people,dc=example,dc=test"}},
		},
	}
	_, err := testVerifyEngine(mem, func(dn, password string) error {
		if e := mem.entries[strings.ToLower(dn)]; e != nil && accountLocked(e) {
			return ldap.NewError(ldap.LDAPResultUnwillingToPerform, errors.New("locked"))
		}
		if password == "alice-seed-secret" && strings.Contains(dn, "alice") {
			return nil
		}
		return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid"))
	}).VerifyApp(t.Context(), sampleVerifyReq())
	if err == nil || !fieldHas(err, "phase.verify_app", "memberof") {
		t.Fatalf("%v", err)
	}
}
