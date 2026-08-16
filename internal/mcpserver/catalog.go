package mcpserver

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

// T-087 lock note (docs/05-mcp-api.md absent). Names are binding or proposed.
// If docs/05 arrives, diff and ADR — do not silently rename.
//
// Tools:
//
//	ldap_search_entries     binding   T-088  yes                 directory:read
//	ldap_get_capabilities   proposed  T-088  yes                 directory:read
//	ldap_get_baseline       proposed  T-088  yes                 directory:read
//	ldap_get_entry          proposed  T-088  yes                 directory:read
//	ldap_create_user        proposed  T-089  registerMutations   directory:write
//	ldap_update_user        proposed  T-089  registerMutations   directory:write
//	ldap_delete_user        proposed  T-089  registerMutations   directory:write
//	ldap_set_password              proposed  T-089  registerPassword    directory:password
//	ldap_get_account_state         proposed  T-089  yes                 directory:read
//	ldap_expire_password           proposed  T-089  registerPassword    directory:password
//	ldap_clear_password_expiry     proposed  T-089  registerPassword    directory:password
//	ldap_lock_user                 proposed  T-089  registerMutations   directory:write
//	ldap_unlock_user               proposed  T-089  registerMutations   directory:write
//	ldap_enable_user               proposed  T-089  registerMutations   directory:write
//	ldap_disable_user              proposed  T-089  registerMutations   directory:write
//	ldap_create_group       proposed  T-090  registerMutations   directory:write
//	ldap_delete_group       proposed  T-090  registerMutations   directory:write
//	ldap_add_members        proposed  T-090  registerMutations   directory:write
//	ldap_remove_members     proposed  T-090  registerMutations   directory:write
//	ldap_replace_members    proposed  T-090  registerMutations   directory:write
//	ldap_update_group       omitted   v1     no GroupPatch / no PATCH /groups/{id} (membership tools are the update path)
//	ldap_bind_test          proposed  T-091  registerPassword    directory:password
//	ldap_reset_suffix       proposed  T-092  registerReset       lab:reset
//	ldap_export_ldif        proposed  T-092  registerExport      lab:export
//
// Resources (proposed; registered with the matching read tools):
//
//	labldap://capabilities                 directory:read  ldap_get_capabilities
//	labldap://baseline                     directory:read  ldap_get_baseline
//	labldap://rootdse                      schema:read     (T-070)
//	labldap://schema                       schema:read     (T-070)
//	labldap://schema/objectclass/{name}    schema:read     (T-070)
//	labldap://schema/attribute/{name}      schema:read     (T-070)
//	labldap://entry{?dn}                   directory:read  ldap_get_entry
const (
	ContractBinding  = "binding"
	ContractProposed = "proposed"

	ToolSearch              = "ldap_search_entries"
	ToolCapabilities        = "ldap_get_capabilities"
	ToolBaseline            = "ldap_get_baseline"
	ToolGetEntry            = "ldap_get_entry"
	ToolCreateUser          = "ldap_create_user"
	ToolUpdateUser          = "ldap_update_user"
	ToolDeleteUser          = "ldap_delete_user"
	ToolSetPassword         = "ldap_set_password"
	ToolAccountState        = "ldap_get_account_state"
	ToolExpirePassword      = "ldap_expire_password"
	ToolClearPasswordExpiry = "ldap_clear_password_expiry"
	ToolLockUser            = "ldap_lock_user"
	ToolUnlockUser          = "ldap_unlock_user"
	ToolEnableUser          = "ldap_enable_user"
	ToolDisableUser         = "ldap_disable_user"
	ToolCreateGroup         = "ldap_create_group"
	ToolDeleteGroup         = "ldap_delete_group"
	ToolAddMembers          = "ldap_add_members"
	ToolRemoveMembers       = "ldap_remove_members"
	ToolReplaceMembers      = "ldap_replace_members"
	ToolBindTest            = "ldap_bind_test"
	ToolResetSuffix         = "ldap_reset_suffix"
	ToolExportLDIF          = "ldap_export_ldif"

	flagMutations = "mutations"
	flagPassword  = "password"
	flagReset     = "reset"
	flagExport    = "export"

	resourceCapabilities = "labldap://capabilities"
	resourceBaseline     = "labldap://baseline"
	resourceRootDSE      = "labldap://rootdse"
	resourceSchema       = "labldap://schema"
	templateObjectClass  = "labldap://schema/objectclass/{name}"
	templateAttribute    = "labldap://schema/attribute/{name}"
	templateEntry        = "labldap://entry{?dn}"

	mimeJSON = "application/json"
)

// GetEntryInput is the proposed ldap_get_entry body. Sibling of a base-scope SearchQuery.
type GetEntryInput struct {
	DN         string   `json:"dn"`
	Attributes []string `json:"attributes,omitempty"`
}

// CreateUserInput matches POST /api/v1/users. Password is never returned.
type CreateUserInput struct {
	ID         string            `json:"id"`
	UID        string            `json:"uid,omitempty"`
	Enabled    *bool             `json:"enabled,omitempty"`
	Password   string            `json:"password"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// UpdateUserInput is PATCH /api/v1/users/{id} plus revision (no If-Match header).
type UpdateUserInput struct {
	ID         string            `json:"id"`
	Enabled    *bool             `json:"enabled,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Revision   string            `json:"revision"`
}

// DeleteInput is a destructive user/group delete. confirm must be true.
type DeleteInput struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
	Confirm  bool   `json:"confirm"`
}

// SetPasswordInput matches POST /api/v1/users/{id}/password.
type SetPasswordInput struct {
	ID         string `json:"id"`
	Password   string `json:"password"`
	Revision   string `json:"revision"`
	MustChange bool   `json:"mustChange,omitempty"`
}

// IDResult is the structured result for delete and set-password.
type IDResult struct {
	ID string `json:"id"`
}

// MembersInput is add/remove/replace members. Arrays cannot be a tool input root.
type MembersInput struct {
	ID       string                `json:"id"`
	Members  []directory.MemberRef `json:"members"`
	Revision string                `json:"revision"`
}

// IDOnlyInput is a user id with no revision.
type IDOnlyInput struct {
	ID string `json:"id"`
}

// RevisionIDInput is a mutating account-state tool body.
type RevisionIDInput struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
}

// BindTestInput matches POST /api/v1/auth-tests.
type BindTestInput struct {
	Identity  string `json:"identity"`
	Password  string `json:"password"`
	Transport string `json:"transport,omitempty"`
}

// ResetSuffixInput is the destructive soft-reset tool (T-092).
type ResetSuffixInput struct {
	Name             string `json:"name"`
	ExpectedRevision string `json:"expectedRevision"`
	Confirm          bool   `json:"confirm"`
}

// ExportLDIFInput is the small inline export (T-092).
type ExportLDIFInput struct {
	OmitSecrets *bool `json:"omitSecrets,omitempty"`
}

// ExportLDIFOutput is either inline LDIF or a REST handoff when over the ceiling.
type ExportLDIFOutput struct {
	LDIF    string `json:"ldif,omitempty"`
	Handoff string `json:"handoff,omitempty"`
	Bytes   int    `json:"bytes,omitempty"`
}

// emptyInput is the OpenAPI-empty object for tools with no fields.
type emptyInput struct{}

// RegisterFlags are spec.management.mcp registration switches (OD-016).
type RegisterFlags struct {
	Mutations bool
	Password  bool
	Reset     bool
	Export    bool
}

// ToolDef is one catalog row. Input/output types match §3.8 / OpenAPI siblings.
type ToolDef struct {
	Name            string
	Contract        string
	Task            string
	Description     string
	Scope           string
	ReadOnly        bool
	Destructive     bool
	Idempotent      bool
	OpenWorld       bool
	Flag            string
	SensitiveInputs []string
	Input           any
	Output          any
}

// ResourceDef is one proposed resource or template (T-087 lock note).
type ResourceDef struct {
	Name        string
	URI         string
	URITemplate string
	Contract    string
	Scope       string
	Sibling     string
	Description string
	MIMEType    string
}

func Catalog() []ToolDef {
	return []ToolDef{
		{
			Name: ToolSearch, Contract: ContractBinding, Task: "T-088",
			Description: "Search the managed suffix. Input and output match POST /api/v1/search (SearchQuery / SearchPage).",
			Scope:       auth.ScopeDirectoryRead, ReadOnly: true, Idempotent: true, OpenWorld: false,
			Input: directory.SearchQuery{}, Output: directory.SearchPage{},
		},
		{
			Name: ToolCapabilities, Contract: ContractProposed, Task: "T-088",
			Description: "Measured engine capabilities. Output matches GET /api/v1/capabilities.",
			Scope:       auth.ScopeDirectoryRead, ReadOnly: true, Idempotent: true, OpenWorld: false,
			Input: emptyInput{}, Output: directory.Capabilities{},
		},
		{
			Name: ToolBaseline, Contract: ContractProposed, Task: "T-088",
			Description: "Compiled versus applied baseline revisions. Output matches GET /api/v1/baseline.",
			Scope:       auth.ScopeDirectoryRead, ReadOnly: true, Idempotent: true, OpenWorld: false,
			Input: emptyInput{}, Output: app.Baseline{},
		},
		{
			Name: ToolGetEntry, Contract: ContractProposed, Task: "T-088",
			Description: "Read one entry by DN (base-scope search). Passwords and forbidden attributes are stripped.",
			Scope:       auth.ScopeDirectoryRead, ReadOnly: true, Idempotent: true, OpenWorld: false,
			Input: GetEntryInput{}, Output: directory.SearchEntry{},
		},
		{
			Name: ToolCreateUser, Contract: ContractProposed, Task: "T-089",
			Description: "Create a user. Input matches POST /api/v1/users (UserSpec).",
			Scope:       auth.ScopeDirectoryWrite, Flag: flagMutations,
			SensitiveInputs: []string{"password"},
			Input:           CreateUserInput{}, Output: directory.User{},
		},
		{
			Name: ToolUpdateUser, Contract: ContractProposed, Task: "T-089",
			Description: "Update a user. Input matches PATCH /api/v1/users/{id} plus revision.",
			Scope:       auth.ScopeDirectoryWrite, Flag: flagMutations, Idempotent: true,
			Input: UpdateUserInput{}, Output: directory.User{},
		},
		{
			Name: ToolDeleteUser, Contract: ContractProposed, Task: "T-089",
			Description: "Delete a user. Requires confirm:true and revision.",
			Scope:       auth.ScopeDirectoryWrite, Destructive: true, Flag: flagMutations,
			Input: DeleteInput{}, Output: IDResult{},
		},
		{
			Name: ToolSetPassword, Contract: ContractProposed, Task: "T-089",
			Description: "Set a user password. Input matches POST /api/v1/users/{id}/password. Clears must-change unless mustChange is true.",
			Scope:       auth.ScopeDirectoryPassword, Flag: flagPassword,
			SensitiveInputs: []string{"password"},
			Input:           SetPasswordInput{}, Output: IDResult{},
		},
		{
			Name: ToolAccountState, Contract: ContractProposed, Task: "T-089",
			Description: "Read enable/lock/must-change state. Sibling of GET /api/v1/users/{id}/account-state.",
			Scope:       auth.ScopeDirectoryRead, ReadOnly: true, Idempotent: true, OpenWorld: false,
			Input: IDOnlyInput{}, Output: directory.AccountState{},
		},
		{
			Name: ToolExpirePassword, Contract: ContractProposed, Task: "T-089",
			Description: "Force must-change on next successful bind-test. Does not change the password.",
			Scope:       auth.ScopeDirectoryPassword, Flag: flagPassword, Idempotent: true,
			Input: RevisionIDInput{}, Output: directory.AccountState{},
		},
		{
			Name: ToolClearPasswordExpiry, Contract: ContractProposed, Task: "T-089",
			Description: "Clear the must-change flag without setting a new password.",
			Scope:       auth.ScopeDirectoryPassword, Flag: flagPassword, Idempotent: true,
			Input: RevisionIDInput{}, Output: directory.AccountState{},
		},
		{
			Name: ToolLockUser, Contract: ContractProposed, Task: "T-089",
			Description: "Administratively lock a user (lockout stamp). Bind-test reports locked.",
			Scope:       auth.ScopeDirectoryWrite, Flag: flagMutations, Idempotent: true,
			Input: RevisionIDInput{}, Output: directory.AccountState{},
		},
		{
			Name: ToolUnlockUser, Contract: ContractProposed, Task: "T-089",
			Description: "Clear lockout stamps so a correct password can bind again.",
			Scope:       auth.ScopeDirectoryWrite, Flag: flagMutations, Idempotent: true,
			Input: RevisionIDInput{}, Output: directory.AccountState{},
		},
		{
			Name: ToolEnableUser, Contract: ContractProposed, Task: "T-089",
			Description: "Enable a user (clear nsAccountLock). Sibling of POST /api/v1/users/{id}/enable.",
			Scope:       auth.ScopeDirectoryWrite, Flag: flagMutations, Idempotent: true,
			Input: RevisionIDInput{}, Output: directory.User{},
		},
		{
			Name: ToolDisableUser, Contract: ContractProposed, Task: "T-089",
			Description: "Disable a user (set nsAccountLock). Sibling of POST /api/v1/users/{id}/disable. Distinct from lock.",
			Scope:       auth.ScopeDirectoryWrite, Flag: flagMutations, Idempotent: true,
			Input: RevisionIDInput{}, Output: directory.User{},
		},
		{
			Name: ToolCreateGroup, Contract: ContractProposed, Task: "T-090",
			Description: "Create a group. Empty members is empty_group.",
			Scope:       auth.ScopeDirectoryWrite, Flag: flagMutations,
			Input: directory.GroupSpec{}, Output: directory.Group{},
		},
		{
			Name: ToolDeleteGroup, Contract: ContractProposed, Task: "T-090",
			Description: "Delete a group. Requires confirm:true and revision.",
			Scope:       auth.ScopeDirectoryWrite, Destructive: true, Flag: flagMutations,
			Input: DeleteInput{}, Output: IDResult{},
		},
		{
			Name: ToolAddMembers, Contract: ContractProposed, Task: "T-090",
			Description: "Add group members. Idempotent for already-present members.",
			Scope:       auth.ScopeDirectoryWrite, Flag: flagMutations, Idempotent: true,
			Input: MembersInput{}, Output: directory.MembershipSummary{},
		},
		{
			Name: ToolRemoveMembers, Contract: ContractProposed, Task: "T-090",
			Description: "Remove group members.",
			Scope:       auth.ScopeDirectoryWrite, Flag: flagMutations, Idempotent: true,
			Input: MembersInput{}, Output: directory.MembershipSummary{},
		},
		{
			Name: ToolReplaceMembers, Contract: ContractProposed, Task: "T-090",
			Description: "Replace group members. Empty replacement is empty_group.",
			Scope:       auth.ScopeDirectoryWrite, Flag: flagMutations, Idempotent: true,
			Input: MembersInput{}, Output: directory.MembershipSummary{},
		},
		{
			Name: ToolBindTest, Contract: ContractProposed, Task: "T-091",
			Description: "Bind-test diagnostic. Unknown user and wrong password are indistinguishable.",
			Scope:       auth.ScopeDirectoryPassword, Flag: flagPassword, OpenWorld: false,
			SensitiveInputs: []string{"password"},
			Input:           BindTestInput{}, Output: directory.BindTestResult{},
		},
		{
			Name: ToolResetSuffix, Contract: ContractProposed, Task: "T-092",
			Description: "Soft-reset the managed suffix. Requires lab:reset, revision, and exact confirmation.",
			Scope:       auth.ScopeLabReset, Destructive: true, Flag: flagReset,
			Input: ResetSuffixInput{}, Output: app.ResetStatus{},
		},
		{
			Name: ToolExportLDIF, Contract: ContractProposed, Task: "T-092",
			Description: "Export a small LDIF snapshot. Large exports should use authenticated REST.",
			Scope:       auth.ScopeLabExport, ReadOnly: true, Flag: flagExport,
			Input: ExportLDIFInput{}, Output: ExportLDIFOutput{},
		},
	}
}

func ResourceCatalog() []ResourceDef {
	return []ResourceDef{
		{Name: "capabilities", URI: resourceCapabilities, Contract: ContractProposed, Scope: auth.ScopeDirectoryRead, Sibling: ToolCapabilities, Description: "Measured engine capabilities.", MIMEType: mimeJSON},
		{Name: "baseline", URI: resourceBaseline, Contract: ContractProposed, Scope: auth.ScopeDirectoryRead, Sibling: ToolBaseline, Description: "Compiled versus applied baseline revisions.", MIMEType: mimeJSON},
		{Name: "rootdse", URI: resourceRootDSE, Contract: ContractProposed, Scope: auth.ScopeSchemaRead, Sibling: "", Description: "Root DSE (T-070).", MIMEType: mimeJSON},
		{Name: "schema", URI: resourceSchema, Contract: ContractProposed, Scope: auth.ScopeSchemaRead, Sibling: "", Description: "Directory schema (T-070).", MIMEType: mimeJSON},
		{Name: "objectclass", URITemplate: templateObjectClass, Contract: ContractProposed, Scope: auth.ScopeSchemaRead, Sibling: "", Description: "One object class by name (T-070).", MIMEType: mimeJSON},
		{Name: "attribute", URITemplate: templateAttribute, Contract: ContractProposed, Scope: auth.ScopeSchemaRead, Sibling: "", Description: "One attribute type by name (T-070).", MIMEType: mimeJSON},
		{Name: "entry", URITemplate: templateEntry, Contract: ContractProposed, Scope: auth.ScopeDirectoryRead, Sibling: ToolGetEntry, Description: "One directory entry by DN.", MIMEType: mimeJSON},
	}
}

func LookupTool(name string) (ToolDef, bool) {
	for _, d := range Catalog() {
		if d.Name == name {
			return d, true
		}
	}
	return ToolDef{}, false
}

func (d ToolDef) ShouldRegister(flags RegisterFlags) bool {
	switch d.Flag {
	case "":
		return true
	case flagMutations:
		return flags.Mutations
	case flagPassword:
		return flags.Password
	case flagReset:
		return flags.Reset
	case flagExport:
		return flags.Export
	default:
		return false
	}
}

func ValidateCatalog() error {
	seen := map[string]struct{}{}
	scopes := map[string]struct{}{}
	for _, s := range auth.Scopes() {
		scopes[s] = struct{}{}
	}
	for _, d := range Catalog() {
		if d.Name == "" {
			return fmt.Errorf("catalog tool missing name")
		}
		if _, ok := seen[d.Name]; ok {
			return fmt.Errorf("duplicate tool name %q", d.Name)
		}
		seen[d.Name] = struct{}{}
		if d.Contract != ContractBinding && d.Contract != ContractProposed {
			return fmt.Errorf("tool %q: unknown contract %q", d.Name, d.Contract)
		}
		if d.Description == "" || d.Task == "" {
			return fmt.Errorf("tool %q: description and task are required", d.Name)
		}
		if _, ok := scopes[d.Scope]; !ok {
			return fmt.Errorf("tool %q: unknown scope %q", d.Name, d.Scope)
		}
		if d.ReadOnly && d.Destructive {
			return fmt.Errorf("tool %q: read-only and destructive are exclusive", d.Name)
		}
	}
	if _, ok := seen[ToolSearch]; !ok {
		return fmt.Errorf("binding tool %q is required", ToolSearch)
	}
	seenURI := map[string]struct{}{}
	for _, r := range ResourceCatalog() {
		key := r.URI + r.URITemplate
		if key == "" {
			return fmt.Errorf("resource %q missing URI", r.Name)
		}
		if _, ok := seenURI[key]; ok {
			return fmt.Errorf("duplicate resource URI %q", key)
		}
		seenURI[key] = struct{}{}
		if _, ok := scopes[r.Scope]; !ok {
			return fmt.Errorf("resource %q: unknown scope %q", r.Name, r.Scope)
		}
	}
	return nil
}

// CatalogMarkdown is the T-087 docs generator. It emits the lock-note tables.
func CatalogMarkdown() string {
	var b strings.Builder
	b.WriteString("# MCP catalog (T-087 lock note)\n\n")
	b.WriteString("docs/05-mcp-api.md is absent. Names are `binding` or `proposed`.\n\n")
	b.WriteString("## Tools\n\n")
	b.WriteString("| Tool | Contract | Task | Default registered | Scope | Read-only | Destructive | Sensitive inputs |\n")
	b.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, d := range Catalog() {
		reg := "yes"
		if d.Flag != "" {
			reg = "if register" + strings.ToUpper(d.Flag[:1]) + d.Flag[1:]
		}
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | `%s` | %t | %t | %s |\n",
			d.Name, d.Contract, d.Task, reg, d.Scope, d.ReadOnly, d.Destructive, strings.Join(d.SensitiveInputs, ", "))
	}
	b.WriteString("\n## Omitted v1 names\n\n")
	b.WriteString("| Name | Reason |\n| --- | --- |\n")
	b.WriteString("| `ldap_update_group` | omitted: v1 has no GroupPatch and no PATCH /api/v1/groups/{id}; membership tools are the group update path |\n")
	b.WriteString("\n## Resources\n\n")
	b.WriteString("| URI | Scope | Sibling |\n| --- | --- | --- |\n")
	for _, r := range ResourceCatalog() {
		uri := r.URI
		if uri == "" {
			uri = r.URITemplate
		}
		fmt.Fprintf(&b, "| `%s` | `%s` | %s |\n", uri, r.Scope, r.Sibling)
	}
	return b.String()
}

func RedactArgs(tool string, args map[string]any) map[string]any {
	if args == nil {
		return nil
	}
	out := make(map[string]any, len(args))
	for k, v := range args {
		out[k] = v
	}
	d, ok := LookupTool(tool)
	if !ok {
		return out
	}
	sensitive := map[string]struct{}{}
	for _, name := range d.SensitiveInputs {
		sensitive[strings.ToLower(name)] = struct{}{}
	}
	for k := range out {
		if _, ok := sensitive[strings.ToLower(k)]; ok {
			out[k] = "[redacted]"
		}
	}
	return out
}

func registeredReadTools() []string {
	return registeredTools(RegisterFlags{})
}

func registeredTools(flags RegisterFlags) []string {
	var names []string
	for _, d := range Catalog() {
		if d.ShouldRegister(flags) {
			names = append(names, d.Name)
		}
	}
	sort.Strings(names)
	return names
}
