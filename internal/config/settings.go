package config

import (
	"fmt"
	"net"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config/v1alpha1"
)

func applyDefaults(f *v1alpha1.File) {
	d := &f.Spec.Directory
	if d.PeopleRDN == "" {
		d.PeopleRDN = "ou=people"
	}
	if d.GroupsRDN == "" {
		d.GroupsRDN = "ou=groups"
	}
	lc := &f.Spec.Lifecycle
	if lc.StorageMode == "" {
		lc.StorageMode = v1alpha1.StorageEphemeral
	}
	if lc.StartupMode == "" {
		lc.StartupMode = v1alpha1.StartupMerge
	}
	if lc.SoftReset == nil {
		t := true
		lc.SoftReset = &t
	}
	tr := &f.Spec.Transport
	if !tr.LDAP.Enabled && !tr.LDAPS.Enabled && !tr.StartTLS {
		tr.LDAPS.Enabled = true
	}
	if tr.LDAP.Port == 0 {
		tr.LDAP.Port = 3389
	}
	if tr.LDAPS.Port == 0 {
		tr.LDAPS.Port = 3636
	}
	mg := &f.Spec.Management
	if mg.Listen == "" {
		mg.Listen = "127.0.0.1:8443"
	}
	if mg.TLS.Mode == "" {
		mg.TLS.Mode = v1alpha1.TLSGenerated
	}
	if mg.Session.IdleTimeout == "" {
		mg.Session.IdleTimeout = "30m"
	}
	if mg.Session.AbsoluteTimeout == "" {
		mg.Session.AbsoluteTimeout = "8h"
	}
	if mg.Session.MaxSessions == 0 {
		mg.Session.MaxSessions = 64
	}
	if mg.Metrics.Enabled == nil {
		t := true
		mg.Metrics.Enabled = &t
	}
	lim := &f.Spec.Limits
	if lim.RequestTimeout == "" {
		lim.RequestTimeout = "30s"
	}
	if lim.ShutdownTimeout == "" {
		lim.ShutdownTimeout = "15s"
	}
	if lim.MaxRequestBodyBytes == 0 {
		lim.MaxRequestBodyBytes = 1 << 20
	}
	if lim.PageSizeDefault == 0 {
		lim.PageSizeDefault = 50
	}
	if lim.PageSizeMax == 0 {
		lim.PageSizeMax = 500
	}
	if lim.LDAPPoolSize == 0 {
		lim.LDAPPoolSize = 16
	}
}

func validateSettings(f *v1alpha1.File) error {
	var acc []*apperr.Error
	if f.Metadata.Name == "" {
		acc = append(acc, fieldErr("metadata.name", "required", "name is required"))
	}
	if f.Spec.Directory.Suffix == "" {
		acc = append(acc, fieldErr("spec.directory.suffix", "required", "suffix is required"))
	} else if _, err := ParseDN(f.Spec.Directory.Suffix); err != nil {
		acc = append(acc, fieldErr("spec.directory.suffix", "invalid_dn", "suffix is not a valid DN"))
	}
	if !contains(v1alpha1.StorageModes(), f.Spec.Lifecycle.StorageMode) {
		acc = append(acc, fieldErr("spec.lifecycle.storageMode", "invalid_enum", "unknown storageMode"))
	}
	if !contains(v1alpha1.StartupModes(), f.Spec.Lifecycle.StartupMode) {
		acc = append(acc, fieldErr("spec.lifecycle.startupMode", "invalid_enum", "unknown startupMode"))
	}
	tr := f.Spec.Transport
	secure := tr.LDAPS.Enabled || tr.StartTLS
	if !tr.InsecureLabMode && !secure {
		acc = append(acc, fieldErr("spec.transport", "insecure", "LDAPS or StartTLS is required unless insecureLabMode is true"))
	}
	if tr.AllowCleartextBind && !tr.InsecureLabMode {
		acc = append(acc, fieldErr("spec.transport.allowCleartextBind", "insecure", "cleartext bind requires insecureLabMode"))
	}
	if f.Spec.Management.TLS.Mode == v1alpha1.TLSDisabled && !tr.InsecureLabMode {
		acc = append(acc, fieldErr("spec.management.tls.mode", "insecure", "disabled management TLS requires insecureLabMode"))
	}
	if !contains(v1alpha1.TLSModes(), f.Spec.Management.TLS.Mode) {
		acc = append(acc, fieldErr("spec.management.tls.mode", "invalid_enum", "unknown tls.mode"))
	}
	if _, _, err := net.SplitHostPort(f.Spec.Management.Listen); err != nil {
		acc = append(acc, fieldErr("spec.management.listen", "invalid_address", "listen must be host:port"))
	}
	acc = append(acc, checkPort("spec.transport.ldap.port", tr.LDAP.Port)...)
	acc = append(acc, checkPort("spec.transport.ldaps.port", tr.LDAPS.Port)...)
	acc = append(acc, checkDuration("spec.management.session.idleTimeout", f.Spec.Management.Session.IdleTimeout)...)
	acc = append(acc, checkDuration("spec.management.session.absoluteTimeout", f.Spec.Management.Session.AbsoluteTimeout)...)
	acc = append(acc, checkDuration("spec.limits.requestTimeout", f.Spec.Limits.RequestTimeout)...)
	acc = append(acc, checkPositive("spec.limits.pageSizeDefault", f.Spec.Limits.PageSizeDefault)...)
	acc = append(acc, checkPositive("spec.limits.pageSizeMax", f.Spec.Limits.PageSizeMax)...)
	if f.Spec.Limits.PageSizeDefault > f.Spec.Limits.PageSizeMax && f.Spec.Limits.PageSizeMax > 0 {
		acc = append(acc, fieldErr("spec.limits.pageSizeDefault", "invalid_limit", "pageSizeDefault exceeds pageSizeMax"))
	}
	if f.Spec.RuntimeAccount.PasswordFile == "" {
		acc = append(acc, fieldErr("spec.runtimeAccount.passwordFile", "required", "runtime account passwordFile is required"))
	}
	if len(acc) == 0 {
		return nil
	}
	out := apperr.New(apperr.CodeConfiguration, "invalid configuration")
	for _, e := range acc {
		for _, f := range e.Fields() {
			out = out.WithField(f)
		}
	}
	return out
}

func requireUserSeeds(f *v1alpha1.File, caller LoadCaller) bool {
	soft := f.Spec.Lifecycle.SoftReset == nil || *f.Spec.Lifecycle.SoftReset
	return soft || caller == CallerBootstrap
}

func checkPort(path string, port int) []*apperr.Error {
	if port < 1 || port > 65535 {
		return []*apperr.Error{fieldErr(path, "invalid_port", "port must be 1-65535")}
	}
	return nil
}

func checkDuration(path, raw string) []*apperr.Error {
	if raw == "" {
		return nil
	}
	if _, err := time.ParseDuration(raw); err != nil {
		return []*apperr.Error{fieldErr(path, "invalid_duration", "not a Go duration")}
	}
	return nil
}

func checkPositive(path string, n int) []*apperr.Error {
	if n < 0 {
		return []*apperr.Error{fieldErr(path, "invalid_limit", "must not be negative")}
	}
	return nil
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func warnPersistentReset(f *v1alpha1.File) string {
	if f.Spec.Lifecycle.StorageMode == v1alpha1.StoragePersistent && f.Spec.Lifecycle.StartupMode == v1alpha1.StartupReset {
		return fmt.Sprintf("startupMode reset on persistent storage is destructive")
	}
	return ""
}
