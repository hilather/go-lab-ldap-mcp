package ds389

import (
	"context"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

func capEntries() map[string]*ldap.Entry {
	e := baseEntries()
	e[""] = &ldap.Entry{DN: "", Attributes: []*ldap.EntryAttribute{
		{Name: "vendorName", Values: []string{"389 Project"}},
		{Name: "vendorVersion", Values: []string{"389-Directory/2.4.6 B2024.212.0000"}},
		{Name: "supportedControl", Values: []string{"1.2.840.113556.1.4.319", "1.3.6.1.1.12"}},
	}}
	e["cn=config"] = &ldap.Entry{DN: "cn=config", Attributes: []*ldap.EntryAttribute{
		{Name: "nsslapd-securePort", Values: []string{"3636"}},
		{Name: "nsslapd-security", Values: []string{"on"}},
		{Name: "passwordStorageScheme", Values: []string{"PBKDF2-SHA256"}},
	}}
	e["cn=schema"] = &ldap.Entry{DN: "cn=schema", Attributes: []*ldap.EntryAttribute{
		{Name: "attributeTypes", Values: []string{"( 2.16.840.1.113730.3.1.610 NAME 'nsAccountLock' )"}},
	}}
	e["cn=memberof plugin,cn=plugins,cn=config"] = &ldap.Entry{
		DN: "cn=MemberOf Plugin,cn=plugins,cn=config",
		Attributes: []*ldap.EntryAttribute{
			{Name: "nsslapd-pluginEnabled", Values: []string{"on"}},
			{Name: "cn", Values: []string{"MemberOf Plugin"}},
		},
	}
	e["cn=referential integrity postoperation,cn=plugins,cn=config"] = &ldap.Entry{
		DN: "cn=referential integrity postoperation,cn=plugins,cn=config",
		Attributes: []*ldap.EntryAttribute{
			{Name: "nsslapd-pluginEnabled", Values: []string{"on"}},
			{Name: "cn", Values: []string{"referential integrity postoperation"}},
		},
	}
	return e
}

func TestCapabilitiesFromInspection(t *testing.T) {
	mem := &seedMem{entries: capEntries()}
	eng := Engine{TreeDial: func(context.Context, bootstrap.TreeRequest) (treeConn, error) { return mem, nil }}
	caps, err := eng.Capabilities(t.Context(), bootstrap.CapabilityRequest{
		TreeRequest: bootstrap.TreeRequest{
			UseLDAPS:   true,
			LDAPURL:    "ldaps://127.0.0.1:3636",
			DMPassword: observability.Secret("dm-secret"),
		},
		RequiredPlugins:    []string{"memberof", "referint", "account-disable"},
		RequiredTransports: []string{"ldaps"},
		RequiredScheme:     "PBKDF2-SHA256",
		Phase:              "inspect",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !caps.RequiredOK {
		t.Fatalf("required not ok: %+v", caps)
	}
	if caps.EngineVendor != "389 Project" || !strings.Contains(caps.EngineVersion, "389-Directory") {
		t.Fatalf("vendor/version not inspected: %+v", caps)
	}
	if caps.AdapterVersion == "" {
		t.Fatal("missing adapter version")
	}
	if !containsFold(caps.Plugins, "memberof") || !containsFold(caps.Plugins, "referint") || !containsFold(caps.Plugins, "account-disable") {
		t.Fatalf("plugins = %v", caps.Plugins)
	}
	if !containsFold(caps.Transports, "ldaps") {
		t.Fatalf("transports = %v", caps.Transports)
	}
	if !containsFold(caps.Controls, "1.3.6.1.1.12") {
		t.Fatalf("controls = %v", caps.Controls)
	}
	if strings.Contains(caps.EngineVendor, "dm-secret") || strings.Contains(caps.PasswordScheme, "dm-secret") {
		t.Fatal("capabilities leaked secret")
	}
}

func TestCapabilitiesRequiredMissingFails(t *testing.T) {
	mem := &seedMem{entries: capEntries()}
	delete(mem.entries, "cn=memberof plugin,cn=plugins,cn=config")
	eng := Engine{TreeDial: func(context.Context, bootstrap.TreeRequest) (treeConn, error) { return mem, nil }}
	caps, err := eng.Capabilities(t.Context(), bootstrap.CapabilityRequest{
		TreeRequest:        bootstrap.TreeRequest{UseLDAPS: true, DMPassword: observability.Secret("dm-secret")},
		RequiredPlugins:    []string{"memberof", "referint", "account-disable"},
		RequiredTransports: []string{"ldaps"},
		RequiredScheme:     "PBKDF2-SHA256",
		Phase:              "verify_app",
	})
	if err != nil {
		t.Fatal(err)
	}
	if caps.RequiredOK {
		t.Fatal("missing memberof must fail RequiredOK")
	}
	if containsFold(caps.Plugins, "memberof") {
		t.Fatal("assumed memberof without inspection")
	}
}

func TestCapabilitiesNoVendorAssumption(t *testing.T) {
	mem := &seedMem{entries: capEntries()}
	mem.entries[""] = &ldap.Entry{DN: "", Attributes: []*ldap.EntryAttribute{
		{Name: "vendorName", Values: []string{"Other Directory"}},
		{Name: "vendorVersion", Values: []string{"1.0"}},
	}}
	eng := Engine{TreeDial: func(context.Context, bootstrap.TreeRequest) (treeConn, error) { return mem, nil }}
	caps, err := eng.Capabilities(t.Context(), bootstrap.CapabilityRequest{
		TreeRequest: bootstrap.TreeRequest{UseLDAPS: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if caps.EngineVendor != "Other Directory" {
		t.Fatalf("invented vendor: %+v", caps)
	}
}

func TestCapabilitiesDialFailureUsesPhase(t *testing.T) {
	eng := Engine{TreeDial: func(context.Context, bootstrap.TreeRequest) (treeConn, error) {
		return nil, ldap.NewError(ldap.LDAPResultInvalidCredentials, nil)
	}}
	_, err := eng.Capabilities(t.Context(), bootstrap.CapabilityRequest{Phase: "verify_app"})
	if err == nil {
		t.Fatal("expected error")
	}
	apperr.Assert(t, err).Code(apperr.CodeBootstrap).FieldPath("phase.verify_app")
}
