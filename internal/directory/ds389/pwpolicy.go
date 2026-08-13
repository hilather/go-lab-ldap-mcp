package ds389

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

func (e Engine) ReconcilePolicy(ctx context.Context, req bootstrap.PolicyRequest) (bootstrap.PolicyResult, error) {
	if err := unsupportedPolicy(req.Policy); err != nil {
		return bootstrap.PolicyResult{}, err
	}
	if req.Write {
		args, applied := policySetArgs(req.Policy)
		if _, err := e.Runner.JSON(ctx, req.PasswordFile, req.Instance, args); err != nil {
			return bootstrap.PolicyResult{}, bootstrap.PhaseError("pwpolicy", "readback_mismatch", "password policy apply failed").Wrap(err)
		}
		if err := e.readbackPolicy(ctx, req); err != nil {
			return bootstrap.PolicyResult{}, err
		}
		return bootstrap.PolicyResult{Applied: applied}, nil
	}
	if err := e.readbackPolicy(ctx, req); err != nil {
		return bootstrap.PolicyResult{}, err
	}
	_, applied := policySetArgs(req.Policy)
	return bootstrap.PolicyResult{Applied: applied}, nil
}

func unsupportedPolicy(p config.NormalizedPolicy) error {
	if p.MinLength < 0 || p.MinLength == 1 || p.MinLength > 512 {
		return bootstrap.PhaseError("pwpolicy", "unsupported_field",
			fmt.Sprintf("minLength %d cannot be represented on 389 DS (allowed: 0 or 2–512)", p.MinLength))
	}
	switch p.StorageScheme {
	case "", "PBKDF2-SHA256", "SSHA512", "PBKDF2_SHA256":
	default:
		if !known389Scheme(p.StorageScheme) {
			return bootstrap.PhaseError("pwpolicy", "unsupported_field", "storageScheme is not available on this engine")
		}
	}
	return nil
}

func known389Scheme(s string) bool {
	switch strings.ToUpper(strings.ReplaceAll(s, "_", "-")) {
	case "PBKDF2-SHA256", "SSHA512", "PBKDF2-SHA512", "PBKDF2-SHA1", "PBKDF2":
		return true
	default:
		return false
	}
}

func policySetArgs(p config.NormalizedPolicy) (args, applied []string) {
	args = []string{"pwpolicy", "set", "--pwdscheme", scheme389(p.StorageScheme)}
	applied = []string{"storageScheme"}
	if p.MinLength >= 2 {
		// Syntax must be on for minLength. Neutralize 389's other syntax
		// defaults so only the compiled minimum is enforced.
		args = append(args, "--pwdminlen", strconv.Itoa(p.MinLength), "--pwdchecksyntax", "on",
			"--pwdmincatagories", "1", "--pwdmintokenlen", "64",
			"--pwddictcheck", "off", "--pwdpalindrome", "off")
		applied = append(applied, "minLength")
	}
	if p.HistoryCount > 0 {
		args = append(args, "--pwdhistory", "on", "--pwdhistorycount", strconv.Itoa(p.HistoryCount))
		applied = append(applied, "historyCount")
	} else {
		args = append(args, "--pwdhistory", "off")
		applied = append(applied, "historyCount")
	}
	if p.MaxAge > 0 {
		args = append(args, "--pwdexpire", "on", "--pwdmaxage", seconds(p.MaxAge))
		applied = append(applied, "maxAge")
	} else {
		args = append(args, "--pwdexpire", "off")
		applied = append(applied, "maxAge")
	}
	args = append(args, "--pwdwarning", seconds(p.WarningAge))
	applied = append(applied, "warningAge")
	if p.LockoutEnabled {
		args = append(args, "--pwdlockout", "on", "--pwdunlock", "on",
			"--pwdmaxfailures", strconv.Itoa(p.MaxFailures),
			"--pwdlockoutduration", seconds(p.LockoutDuration))
		applied = append(applied, "lockout")
	} else {
		args = append(args, "--pwdlockout", "off")
		applied = append(applied, "lockout")
	}
	return args, applied
}

func scheme389(s string) string {
	if s == "PBKDF2_SHA256" || s == "" {
		return "PBKDF2-SHA256"
	}
	return s
}

func seconds(d time.Duration) string {
	n := int(d.Seconds())
	if n < 0 {
		n = 0
	}
	return strconv.Itoa(n)
}

func (e Engine) readbackPolicy(ctx context.Context, req bootstrap.PolicyRequest) error {
	raw, err := e.Runner.JSON(ctx, req.PasswordFile, req.Instance, []string{"pwpolicy", "get"})
	if err != nil {
		return bootstrap.PhaseError("pwpolicy", "readback_mismatch", "could not read password policy").Wrap(err)
	}
	attrs, err := parsePolicyAttrs(raw)
	if err != nil {
		return bootstrap.PhaseError("pwpolicy", "readback_mismatch", "password policy read-back is not JSON").Wrap(err)
	}
	p := req.Policy
	if got := first(attrs, "passwordstoragescheme"); !strings.EqualFold(got, scheme389(p.StorageScheme)) {
		return mismatch("storageScheme", scheme389(p.StorageScheme), got)
	}
	if p.MinLength >= 2 {
		if got := first(attrs, "passwordminlength"); got != strconv.Itoa(p.MinLength) {
			return mismatch("minLength", strconv.Itoa(p.MinLength), got)
		}
	}
	if p.HistoryCount > 0 {
		if first(attrs, "passwordhistory") != "on" || first(attrs, "passwordinhistory") != strconv.Itoa(p.HistoryCount) {
			return mismatch("historyCount", strconv.Itoa(p.HistoryCount), first(attrs, "passwordinhistory"))
		}
	} else if first(attrs, "passwordhistory") != "off" {
		return mismatch("historyCount", "off", first(attrs, "passwordhistory"))
	}
	if p.MaxAge > 0 {
		if first(attrs, "passwordexp") != "on" || first(attrs, "passwordmaxage") != seconds(p.MaxAge) {
			return mismatch("maxAge", seconds(p.MaxAge), first(attrs, "passwordmaxage"))
		}
	} else if first(attrs, "passwordexp") != "off" {
		return mismatch("maxAge", "off", first(attrs, "passwordexp"))
	}
	if first(attrs, "passwordwarning") != seconds(p.WarningAge) {
		return mismatch("warningAge", seconds(p.WarningAge), first(attrs, "passwordwarning"))
	}
	if p.LockoutEnabled {
		if first(attrs, "passwordlockout") != "on" {
			return mismatch("lockout", "on", first(attrs, "passwordlockout"))
		}
		if first(attrs, "passwordmaxfailure") != strconv.Itoa(p.MaxFailures) {
			return mismatch("lockout.maxFailures", strconv.Itoa(p.MaxFailures), first(attrs, "passwordmaxfailure"))
		}
		if first(attrs, "passwordlockoutduration") != seconds(p.LockoutDuration) {
			return mismatch("lockout.lockoutDuration", seconds(p.LockoutDuration), first(attrs, "passwordlockoutduration"))
		}
	} else if first(attrs, "passwordlockout") != "off" {
		return mismatch("lockout", "off", first(attrs, "passwordlockout"))
	}
	return nil
}

func parsePolicyAttrs(raw []byte) (map[string][]string, error) {
	var doc struct {
		Attrs map[string][]string `json:"attrs"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	out := make(map[string][]string, len(doc.Attrs))
	for k, v := range doc.Attrs {
		out[strings.ToLower(k)] = v
	}
	return out, nil
}

func first(attrs map[string][]string, key string) string {
	vs := attrs[strings.ToLower(key)]
	if len(vs) == 0 {
		return ""
	}
	return vs[0]
}

func mismatch(field, want, got string) error {
	return bootstrap.PhaseError("pwpolicy", "readback_mismatch",
		fmt.Sprintf("password policy %s read-back does not match the plan: want %s, got %s", field, want, got))
}
