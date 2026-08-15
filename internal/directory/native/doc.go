// Package native implements the bootstrap side of engine=native (ADR-0008).
//
// Where ds389 drives dsconf, the native reconcilers wait and read back over
// LDAP: labldapd self-applies the engine plan at start (suffix, TLS
// materials, password policy, plugin hooks), and the BackendReconciler,
// TLSReconciler, PolicyReconciler, and PluginReconciler implementations here
// fail closed when the daemon's applied plan does not match the compiled
// scenario (ADR-0009 decisions 11-12). The data plane (tree, ACIs, seed,
// verify, drift, marker) stays the existing LDAP-as-Directory-Manager
// implementations wired by cmd/labldap-bootstrap, and runtime repositories
// stay ds389.Runtime over LDAP (ADR-0009 rule 17).
//
// This package must not import internal/directory/ds389. The reconcilers
// land in T-144; T-122 pins only the package contract.
package native
