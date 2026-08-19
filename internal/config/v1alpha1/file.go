package v1alpha1

// File is the public YAML document. Sensitive values are path references only.
type File struct {
	APIVersion string   `json:"apiVersion" yaml:"apiVersion"`
	Kind       string   `json:"kind" yaml:"kind"`
	Metadata   Metadata `json:"metadata" yaml:"metadata"`
	Spec       Spec     `json:"spec" yaml:"spec"`
}

type Metadata struct {
	Name string `json:"name" yaml:"name"`
}

type Spec struct {
	Directory      Directory      `json:"directory" yaml:"directory"`
	Lifecycle      Lifecycle      `json:"lifecycle" yaml:"lifecycle"`
	Transport      Transport      `json:"transport" yaml:"transport"`
	Management     Management     `json:"management" yaml:"management"`
	Limits         Limits         `json:"limits" yaml:"limits"`
	RuntimeAccount RuntimeAccount `json:"runtimeAccount" yaml:"runtimeAccount"`
	Users          []User         `json:"users" yaml:"users"`
	Groups         []Group        `json:"groups" yaml:"groups"`
	PasswordPolicy PasswordPolicy `json:"passwordPolicy" yaml:"passwordPolicy"`
	ACLs           []ACL          `json:"acls" yaml:"acls"`
	Tokens         []Token        `json:"tokens" yaml:"tokens"`
}

type Directory struct {
	// Engine selects the directory engine (389ds | native). Empty defaults
	// to EngineNative (v0.3.0; ADR-0008 amendment 2026-08-17).
	Engine string `json:"engine" yaml:"engine"`
	Suffix string `json:"suffix" yaml:"suffix"`
	// AdditionalSuffixes are extra managed naming contexts (ADR-0011).
	// Sibling / unrelated DNs only; never nested inside the primary or
	// each other. Empty keeps a single-suffix lab.
	AdditionalSuffixes []string `json:"additionalSuffixes" yaml:"additionalSuffixes"`
	PeopleRDN          string   `json:"peopleRDN" yaml:"peopleRDN"`
	GroupsRDN          string   `json:"groupsRDN" yaml:"groupsRDN"`
	NestedGroups       bool     `json:"nestedGroups" yaml:"nestedGroups"`
	AllowRawACI        bool     `json:"allowRawACI" yaml:"allowRawACI"`
}

type Lifecycle struct {
	StorageMode string `json:"storageMode" yaml:"storageMode"`
	StartupMode string `json:"startupMode" yaml:"startupMode"`
	SoftReset   *bool  `json:"softReset" yaml:"softReset"`
}

type Transport struct {
	InsecureLabMode    bool     `json:"insecureLabMode" yaml:"insecureLabMode"`
	LDAP               PortSpec `json:"ldap" yaml:"ldap"`
	LDAPS              PortSpec `json:"ldaps" yaml:"ldaps"`
	StartTLS           bool     `json:"startTLS" yaml:"startTLS"`
	AllowCleartextBind bool     `json:"allowCleartextBind" yaml:"allowCleartextBind"`
	AllowAnonymousBind bool     `json:"allowAnonymousBind" yaml:"allowAnonymousBind"`
}

type PortSpec struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
	Port    int  `json:"port" yaml:"port"`
}

type Management struct {
	Listen string `json:"listen" yaml:"listen"`
	// AllowedHosts is a union on top of LoopbackHosts (ADR-0010). Empty
	// keeps the compiled loopback/bind-all default. Never "*".
	AllowedHosts []string `json:"allowedHosts" yaml:"allowedHosts"`
	TLS          TLSpec   `json:"tls" yaml:"tls"`
	CORS         CORS     `json:"cors" yaml:"cors"`
	Session      Session  `json:"session" yaml:"session"`
	MCP          MCP      `json:"mcp" yaml:"mcp"`
	Metrics      Metrics  `json:"metrics" yaml:"metrics"`
}

type TLSpec struct {
	Mode     string `json:"mode" yaml:"mode"`
	CertFile string `json:"certFile" yaml:"certFile"`
	KeyFile  string `json:"keyFile" yaml:"keyFile"`
}

type CORS struct {
	AllowedOrigins []string `json:"allowedOrigins" yaml:"allowedOrigins"`
}

type Session struct {
	IdleTimeout     string `json:"idleTimeout" yaml:"idleTimeout"`
	AbsoluteTimeout string `json:"absoluteTimeout" yaml:"absoluteTimeout"`
	MaxSessions     int    `json:"maxSessions" yaml:"maxSessions"`
}

type MCP struct {
	// Enabled defaults to true when omitted (applyDefaults). Pointer so
	// enabled: false is distinct from an absent key (OD-016).
	Enabled           *bool `json:"enabled" yaml:"enabled"`
	RegisterMutations bool  `json:"registerMutations" yaml:"registerMutations"`
	RegisterPassword  bool  `json:"registerPassword" yaml:"registerPassword"`
	RegisterReset     bool  `json:"registerReset" yaml:"registerReset"`
	RegisterExport    bool  `json:"registerExport" yaml:"registerExport"`
}

type Metrics struct {
	// Enabled defaults to true when omitted (applyDefaults). Pointer so
	// enabled: false is distinct from an absent key.
	Enabled     *bool `json:"enabled" yaml:"enabled"`
	RequireAuth bool  `json:"requireAuth" yaml:"requireAuth"`
}

type Limits struct {
	RequestTimeout      string    `json:"requestTimeout" yaml:"requestTimeout"`
	ShutdownTimeout     string    `json:"shutdownTimeout" yaml:"shutdownTimeout"`
	MaxRequestBodyBytes int64     `json:"maxRequestBodyBytes" yaml:"maxRequestBodyBytes"`
	PageSizeDefault     int       `json:"pageSizeDefault" yaml:"pageSizeDefault"`
	PageSizeMax         int       `json:"pageSizeMax" yaml:"pageSizeMax"`
	SearchTimeLimit     string    `json:"searchTimeLimit" yaml:"searchTimeLimit"`
	SearchSizeLimit     int       `json:"searchSizeLimit" yaml:"searchSizeLimit"`
	MaxFilterDepth      int       `json:"maxFilterDepth" yaml:"maxFilterDepth"`
	MaxFilterLength     int       `json:"maxFilterLength" yaml:"maxFilterLength"`
	ExportMaxEntries    int       `json:"exportMaxEntries" yaml:"exportMaxEntries"`
	ExportMaxBytes      int64     `json:"exportMaxBytes" yaml:"exportMaxBytes"`
	LDAPPoolSize        int       `json:"ldapPoolSize" yaml:"ldapPoolSize"`
	LDAPMaxIdle         string    `json:"ldapMaxIdle" yaml:"ldapMaxIdle"`
	LDAPMaxLifetime     string    `json:"ldapMaxLifetime" yaml:"ldapMaxLifetime"`
	LDAPDialTimeout     string    `json:"ldapDialTimeout" yaml:"ldapDialTimeout"`
	ConcurrentMutations int       `json:"concurrentMutations" yaml:"concurrentMutations"`
	RateLimit           RateLimit `json:"rateLimit" yaml:"rateLimit"`
}

type RateLimit struct {
	RequestsPerMinute int `json:"requestsPerMinute" yaml:"requestsPerMinute"`
	PasswordPerMinute int `json:"passwordPerMinute" yaml:"passwordPerMinute"`
	BindTestPerMinute int `json:"bindTestPerMinute" yaml:"bindTestPerMinute"`
	ResetPerHour      int `json:"resetPerHour" yaml:"resetPerHour"`
}

// SecretRef is a filesystem path. File content becomes observability.Secret later (T-014).
type SecretRef struct {
	File string `json:"file" yaml:"file"`
}

type RuntimeAccount struct {
	ID           string `json:"id" yaml:"id"`
	PasswordFile string `json:"passwordFile" yaml:"passwordFile"`
}

type User struct {
	ID           string            `json:"id" yaml:"id"`
	UID          string            `json:"uid" yaml:"uid"`
	RDN          string            `json:"rdn" yaml:"rdn"`
	DN           string            `json:"dn" yaml:"dn"`
	PasswordFile string            `json:"passwordFile" yaml:"passwordFile"`
	Enabled      *bool             `json:"enabled" yaml:"enabled"`
	Attributes   map[string]string `json:"attributes" yaml:"attributes"`
}

type Group struct {
	ID      string   `json:"id" yaml:"id"`
	Members []Member `json:"members" yaml:"members"`
}

type Member struct {
	User  string `json:"user" yaml:"user"`
	Group string `json:"group" yaml:"group"`
}

type PasswordPolicy struct {
	MinLength     int     `json:"minLength" yaml:"minLength"`
	HistoryCount  int     `json:"historyCount" yaml:"historyCount"`
	MaxAge        string  `json:"maxAge" yaml:"maxAge"`
	WarningAge    string  `json:"warningAge" yaml:"warningAge"`
	Lockout       Lockout `json:"lockout" yaml:"lockout"`
	StorageScheme string  `json:"storageScheme" yaml:"storageScheme"`
}

type Lockout struct {
	Enabled         bool   `json:"enabled" yaml:"enabled"`
	MaxFailures     int    `json:"maxFailures" yaml:"maxFailures"`
	LockoutDuration string `json:"lockoutDuration" yaml:"lockoutDuration"`
}

type ACL struct {
	ID          string     `json:"id" yaml:"id"`
	Principal   Principal  `json:"principal" yaml:"principal"`
	Target      Target     `json:"target" yaml:"target"`
	Permissions []string   `json:"permissions" yaml:"permissions"`
	Attributes  AttrFilter `json:"attributes" yaml:"attributes"`
	RawACI      string     `json:"rawACI" yaml:"rawACI"`
}

type Principal struct {
	Kind string `json:"kind" yaml:"kind"`
	Ref  string `json:"ref" yaml:"ref"`
}

type Target struct {
	Kind string `json:"kind" yaml:"kind"`
	DN   string `json:"dn" yaml:"dn"`
}

type AttrFilter struct {
	Allow []string `json:"allow" yaml:"allow"`
	Deny  []string `json:"deny" yaml:"deny"`
}

type Token struct {
	ID         string   `json:"id" yaml:"id"`
	SecretFile string   `json:"secretFile" yaml:"secretFile"`
	Scopes     []string `json:"scopes" yaml:"scopes"`
}
