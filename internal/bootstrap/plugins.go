package bootstrap

import "context"

// PluginRequest is the engine-plugin reconcile input.
type PluginRequest struct {
	PasswordFile       string
	Instance           string
	Suffix             string
	AdditionalSuffixes []string
	Plugins            []string
	Write              bool
}

// PluginResult is secret-free.
type PluginResult struct {
	Applied []string
}

// PluginReconciler enables or verifies compiled engine plugins.
type PluginReconciler interface {
	ReconcilePlugins(ctx context.Context, req PluginRequest) (PluginResult, error)
}
