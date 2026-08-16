package native

import (
	"context"

	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
)

// knownPlugins mirrors the compiled engine plan's canonical plugin list
// (config buildEnginePlan): memberof and referint are ldapserver plugin
// hooks, account-disable is the nsAccountLock gate in the bind path.
var knownPlugins = []string{"memberof", "referint", "account-disable"}

// ReconcilePlugins verifies every compiled plugin is present in the
// daemon's applied plan. Nothing is enabled from here — labldapd wires
// the plugin hooks at start — so Write is a no-op and a missing plugin
// fails closed.
func (e Engine) ReconcilePlugins(ctx context.Context, req bootstrap.PluginRequest) (bootstrap.PluginResult, error) {
	wanted := req.Plugins
	if len(wanted) == 0 {
		wanted = knownPlugins
	}
	for _, name := range wanted {
		if !knownPlugin(name) {
			return bootstrap.PluginResult{}, bootstrap.PhaseError("plugins", "plugin_missing",
				"compiled engine plan names a plugin this engine does not have: "+name)
		}
	}
	pr, err := e.dmProbe(ctx, "plugins", req.PasswordFile)
	if err != nil {
		return bootstrap.PluginResult{}, err
	}
	defer func() { _ = pr.Close() }()

	for _, name := range wanted {
		if err := compareState(ctx, pr, "plugins", "plugin_missing", attrPlugins, name); err != nil {
			return bootstrap.PluginResult{}, err
		}
	}
	return bootstrap.PluginResult{Applied: append([]string(nil), wanted...)}, nil
}

func knownPlugin(name string) bool {
	for _, k := range knownPlugins {
		if k == name {
			return true
		}
	}
	return false
}
