package config

import (
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config/v1alpha1"
)

func normalizePolicy(p v1alpha1.PasswordPolicy) (NormalizedPolicy, error) {
	var acc []*apperr.Error
	scheme := p.StorageScheme
	if scheme == "" {
		scheme = v1alpha1.SchemePBKDF2SHA256
	}
	if scheme == v1alpha1.SchemePBKDF2Alias {
		scheme = v1alpha1.SchemePBKDF2SHA256
	}
	switch scheme {
	case v1alpha1.SchemePBKDF2SHA256, v1alpha1.SchemeSSHA512:
	default:
		acc = append(acc, fieldErr("spec.passwordPolicy.storageScheme", "unsupported_scheme", "unknown password storage scheme"))
	}
	var maxAge, warn time.Duration
	var err error
	if p.MaxAge != "" && p.MaxAge != "0s" && p.MaxAge != "0" {
		maxAge, err = time.ParseDuration(p.MaxAge)
		if err != nil {
			acc = append(acc, fieldErr("spec.passwordPolicy.maxAge", "invalid_duration", "not a Go duration"))
		}
	}
	if p.WarningAge != "" && p.WarningAge != "0s" && p.WarningAge != "0" {
		warn, err = time.ParseDuration(p.WarningAge)
		if err != nil {
			acc = append(acc, fieldErr("spec.passwordPolicy.warningAge", "invalid_duration", "not a Go duration"))
		}
	}
	if maxAge > 0 && warn > maxAge {
		acc = append(acc, fieldErr("spec.passwordPolicy.warningAge", "invalid_policy", "warningAge cannot exceed maxAge"))
	}
	out := NormalizedPolicy{
		MinLength:      p.MinLength,
		HistoryCount:   p.HistoryCount,
		MaxAge:         maxAge,
		WarningAge:     warn,
		LockoutEnabled: p.Lockout.Enabled,
		MaxFailures:    p.Lockout.MaxFailures,
		StorageScheme:  scheme,
	}
	if p.Lockout.Enabled {
		if p.Lockout.MaxFailures <= 0 {
			acc = append(acc, fieldErr("spec.passwordPolicy.lockout.maxFailures", "required", "maxFailures must be positive when lockout is enabled"))
		}
		if p.Lockout.LockoutDuration == "" {
			acc = append(acc, fieldErr("spec.passwordPolicy.lockout.lockoutDuration", "required", "lockoutDuration is required when lockout is enabled"))
		} else {
			d, derr := time.ParseDuration(p.Lockout.LockoutDuration)
			if derr != nil || d <= 0 {
				acc = append(acc, fieldErr("spec.passwordPolicy.lockout.lockoutDuration", "invalid_duration", "lockoutDuration must be a positive duration"))
			} else {
				out.LockoutDuration = d
			}
		}
	}
	if err := joinConfig(acc); err != nil {
		return NormalizedPolicy{}, err
	}
	return out, nil
}
