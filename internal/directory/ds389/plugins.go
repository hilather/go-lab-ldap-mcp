package ds389

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

const (
	pluginMemberOf = "memberof"
	pluginReferint = "referint"
	pluginDisable  = "account-disable"

	cnMemberOf = "MemberOf Plugin"
	cnReferint = "referential integrity postoperation"
)

func (e Engine) ReconcilePlugins(ctx context.Context, req bootstrap.PluginRequest) (bootstrap.PluginResult, error) {
	wanted := req.Plugins
	if len(wanted) == 0 {
		wanted = []string{pluginMemberOf, pluginReferint, pluginDisable}
	}
	for _, name := range wanted {
		if err := knownPlugin(name); err != nil {
			return bootstrap.PluginResult{}, err
		}
	}
	if req.Write {
		if _, err := e.Runner.JSON(ctx, req.PasswordFile, req.Instance, []string{
			"config", "replace", "nsslapd-dynamic-plugins=on",
		}); err != nil {
			return bootstrap.PluginResult{}, bootstrap.PhaseError("plugins", "plugin_missing", "could not enable dynamic plugins").Wrap(err)
		}
		for _, name := range wanted {
			if err := e.applyPlugin(ctx, req, name); err != nil {
				return bootstrap.PluginResult{}, err
			}
		}
	}
	if err := e.readbackPlugins(ctx, req, wanted); err != nil {
		return bootstrap.PluginResult{}, err
	}
	return bootstrap.PluginResult{Applied: append([]string(nil), wanted...)}, nil
}

func (e Engine) pluginSet(ctx context.Context, req bootstrap.PluginRequest, args []string) error {
	_, err := e.Runner.JSON(ctx, req.PasswordFile, req.Instance, args)
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "nothing to set") {
		return nil
	}
	return err
}

func knownPlugin(name string) error {
	switch name {
	case pluginMemberOf, pluginReferint, pluginDisable:
		return nil
	default:
		return bootstrap.PhaseError("plugins", "plugin_missing", "required plugin is not available on this engine")
	}
}

func (e Engine) applyPlugin(ctx context.Context, req bootstrap.PluginRequest, name string) error {
	switch name {
	case pluginMemberOf:
		if _, err := e.Runner.JSON(ctx, req.PasswordFile, req.Instance, []string{
			"plugin", "memberof", "enable",
		}); err != nil {
			return bootstrap.PhaseError("plugins", "plugin_missing", "could not enable MemberOf").Wrap(err)
		}
		if err := e.pluginSet(ctx, req, []string{
			"plugin", "memberof", "set",
			"--attr", "memberOf",
			"--groupattr", "member",
			"--scope", req.Suffix,
			"--autoaddoc", "nsmemberof",
		}); err != nil {
			return bootstrap.PhaseError("plugins", "plugin_missing", "could not configure MemberOf").Wrap(err)
		}
		if _, err := e.Runner.JSON(ctx, req.PasswordFile, req.Instance, []string{
			"plugin", "memberof", "fixup", "--wait", "--timeout", "60", req.Suffix,
		}); err != nil {
			return bootstrap.PhaseError("plugins", "fixup_failed", "MemberOf fix-up failed").Wrap(err)
		}
	case pluginReferint:
		if _, err := e.Runner.JSON(ctx, req.PasswordFile, req.Instance, []string{
			"plugin", "referential-integrity", "enable",
		}); err != nil {
			return bootstrap.PhaseError("plugins", "plugin_missing", "could not enable referential integrity").Wrap(err)
		}
		if err := e.pluginSet(ctx, req, []string{
			"plugin", "referential-integrity", "set",
			"--update-delay", "0",
			"--membership-attr", "member",
			"--entry-scope", req.Suffix,
			"--container-scope", req.Suffix,
		}); err != nil {
			return bootstrap.PhaseError("plugins", "plugin_missing", "could not configure referential integrity").Wrap(err)
		}
	case pluginDisable:
		if err := e.readbackDisable(ctx, req); err != nil {
			return err
		}
	}
	return nil
}

func (e Engine) readbackPlugins(ctx context.Context, req bootstrap.PluginRequest, wanted []string) error {
	for _, name := range wanted {
		switch name {
		case pluginMemberOf:
			if err := e.readbackMemberOf(ctx, req); err != nil {
				return err
			}
		case pluginReferint:
			if err := e.readbackReferint(ctx, req); err != nil {
				return err
			}
		case pluginDisable:
			if err := e.readbackDisable(ctx, req); err != nil {
				return err
			}
		}
	}
	return nil
}

func (e Engine) readbackMemberOf(ctx context.Context, req bootstrap.PluginRequest) error {
	raw, err := e.Runner.JSON(ctx, req.PasswordFile, req.Instance, []string{"plugin", "show", cnMemberOf})
	if err != nil {
		return bootstrap.PhaseError("plugins", "plugin_missing", "could not read MemberOf plugin").Wrap(err)
	}
	attrs, err := parsePolicyAttrs(raw)
	if err != nil {
		return bootstrap.PhaseError("plugins", "plugin_missing", "MemberOf read-back is not JSON").Wrap(err)
	}
	if !strings.EqualFold(first(attrs, "nsslapd-pluginenabled"), "on") {
		return bootstrap.PhaseError("plugins", "plugin_missing", "MemberOf plugin is not enabled")
	}
	if !strings.EqualFold(first(attrs, "memberofattr"), "memberof") {
		return bootstrap.PhaseError("plugins", "plugin_missing", "MemberOf attribute is not memberOf")
	}
	if !attrHas(attrs, "memberofgroupattr", "member") {
		return bootstrap.PhaseError("plugins", "plugin_missing", "MemberOf group attribute does not include member")
	}
	if req.Suffix != "" && !sameDN(first(attrs, "memberofentryscope"), req.Suffix) {
		return bootstrap.PhaseError("plugins", "plugin_missing", "MemberOf scope does not match the planned suffix")
	}
	return nil
}

func (e Engine) readbackReferint(ctx context.Context, req bootstrap.PluginRequest) error {
	raw, err := e.Runner.JSON(ctx, req.PasswordFile, req.Instance, []string{"plugin", "show", cnReferint})
	if err != nil {
		return bootstrap.PhaseError("plugins", "plugin_missing", "could not read referential integrity plugin").Wrap(err)
	}
	attrs, err := parsePolicyAttrs(raw)
	if err != nil {
		return bootstrap.PhaseError("plugins", "plugin_missing", "referential integrity read-back is not JSON").Wrap(err)
	}
	if !strings.EqualFold(first(attrs, "nsslapd-pluginenabled"), "on") {
		return bootstrap.PhaseError("plugins", "plugin_missing", "referential integrity plugin is not enabled")
	}
	if !attrHas(attrs, "referint-membership-attr", "member") {
		return bootstrap.PhaseError("plugins", "plugin_missing", "referential integrity does not watch member")
	}
	return nil
}

func (e Engine) readbackDisable(ctx context.Context, req bootstrap.PluginRequest) error {
	raw, err := e.Runner.JSON(ctx, req.PasswordFile, req.Instance, []string{
		"schema", "attributetypes", "query", "nsAccountLock",
	})
	if err != nil {
		return bootstrap.PhaseError("plugins", "plugin_missing", "nsAccountLock is not available on this engine").Wrap(err)
	}
	var doc struct {
		AT struct {
			Names []string `json:"names"`
		} `json:"at"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return bootstrap.PhaseError("plugins", "plugin_missing", "nsAccountLock schema read-back is not JSON").Wrap(err)
	}
	for _, n := range doc.AT.Names {
		if strings.EqualFold(n, "nsAccountLock") {
			return nil
		}
	}
	return bootstrap.PhaseError("plugins", "plugin_missing", "nsAccountLock is not available on this engine")
}

func attrHas(attrs map[string][]string, key, want string) bool {
	for _, v := range attrs[strings.ToLower(key)] {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

func sameDN(a, b string) bool {
	da, err := config.ParseDN(a)
	if err != nil {
		return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
	}
	db, err := config.ParseDN(b)
	if err != nil {
		return false
	}
	return da.EqualFold(db)
}
