package auth

import "github.com/hilather/go-lab-ldap-mcp/internal/config/v1alpha1"

const (
	ScopeDirectoryRead     = v1alpha1.ScopeDirectoryRead
	ScopeDirectoryWrite    = v1alpha1.ScopeDirectoryWrite
	ScopeDirectoryPassword = v1alpha1.ScopeDirectoryPassword
	ScopeLabReset          = v1alpha1.ScopeLabReset
	ScopeLabExport         = v1alpha1.ScopeLabExport
	ScopeSchemaRead        = v1alpha1.ScopeSchemaRead
	ScopeAuditRead         = v1alpha1.ScopeAuditRead
)

// Scopes is the T-057 registry. write does not imply password, reset, or export.
func Scopes() []string { return v1alpha1.Scopes() }

func IndependentOfWrite() []string {
	return []string{ScopeDirectoryPassword, ScopeLabReset, ScopeLabExport}
}
