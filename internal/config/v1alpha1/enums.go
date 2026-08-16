package v1alpha1

const (
	APIVersion = "labldap.dev/v1alpha1"
	Kind       = "LabScenario"
)

const (
	StorageEphemeral  = "ephemeral"
	StoragePersistent = "persistent"
)

// Directory engines (ADR-0008). Both are wired into serve/bootstrap as of
// T-146; RequireAvailableEngine stays fail-closed behind this enum.
const (
	Engine389DS  = "389ds"
	EngineNative = "native"
)

const (
	StartupValidate = "validate"
	StartupMerge    = "merge"
	StartupReset    = "reset"
)

const (
	TLSGenerated = "generated"
	TLSFiles     = "files"
	TLSDisabled  = "disabled"
)

const (
	ScopeDirectoryRead     = "directory:read"
	ScopeDirectoryWrite    = "directory:write"
	ScopeDirectoryPassword = "directory:password"
	ScopeLabReset          = "lab:reset"
	ScopeLabExport         = "lab:export"
	ScopeSchemaRead        = "schema:read"
	ScopeAuditRead         = "audit:read"
)

const (
	PrincipalUser  = "user"
	PrincipalGroup = "group"
	PrincipalToken = "token"
)

const (
	TargetSuffix    = "suffix"
	TargetPeople    = "people"
	TargetGroups    = "groups"
	TargetEntry     = "entry"
	TargetAttribute = "attribute"
)

const (
	PermRead    = "read"
	PermSearch  = "search"
	PermCompare = "compare"
	PermAdd     = "add"
	PermDelete  = "delete"
	PermWrite   = "write"
)

const (
	SchemePBKDF2SHA256 = "PBKDF2-SHA256"
	SchemePBKDF2Alias  = "PBKDF2_SHA256"
	SchemeSSHA512      = "SSHA512"
)

const (
	SearchBase        = "base"
	SearchOneLevel    = "one"
	SearchSubtree     = "sub"
	SearchSubordinate = "children"
)

func StorageModes() []string { return []string{StorageEphemeral, StoragePersistent} }
func Engines() []string      { return []string{Engine389DS, EngineNative} }
func StartupModes() []string { return []string{StartupValidate, StartupMerge, StartupReset} }
func TLSModes() []string     { return []string{TLSGenerated, TLSFiles, TLSDisabled} }
func Scopes() []string {
	return []string{ScopeDirectoryRead, ScopeDirectoryWrite, ScopeDirectoryPassword, ScopeLabReset, ScopeLabExport, ScopeSchemaRead, ScopeAuditRead}
}
func PrincipalKinds() []string { return []string{PrincipalUser, PrincipalGroup, PrincipalToken} }
func TargetKinds() []string {
	return []string{TargetSuffix, TargetPeople, TargetGroups, TargetEntry, TargetAttribute}
}
func Permissions() []string {
	return []string{PermRead, PermSearch, PermCompare, PermAdd, PermDelete, PermWrite}
}
func StorageSchemes() []string { return []string{SchemePBKDF2SHA256, SchemePBKDF2Alias, SchemeSSHA512} }
func SearchScopes() []string {
	return []string{SearchBase, SearchOneLevel, SearchSubtree, SearchSubordinate}
}
func APIVersions() []string { return []string{APIVersion} }
func Kinds() []string       { return []string{Kind} }
