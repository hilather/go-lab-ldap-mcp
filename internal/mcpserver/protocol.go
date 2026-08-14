package mcpserver

// OD-015 protocol record. Streamable HTTP accepts 2026-07-28 only when
// StreamableHTTPOptions.Stateless is true (SDK v1.7.0).
const (
	SDKModule       = "github.com/modelcontextprotocol/go-sdk"
	SDKVersion      = "v1.7.0"
	ProtocolVersion = "2026-07-28"
	Stateless       = true
	MountPath       = "/mcp"

	// RPC names used with spec 2026-07-28 (stateless; server/discover, not initialize).
	RPCDiscover               = "server/discover"
	RPCToolsList              = "tools/list"
	RPCToolsCall              = "tools/call"
	RPCResourcesList          = "resources/list"
	RPCResourcesRead          = "resources/read"
	RPCResourceTemplatesList  = "resources/templates/list"
	RPCNotificationsCancelled = "notifications/cancelled"
)

const (
	headerRequestID     = "X-Request-ID"
	problemTypePrefix   = "https://labldap.dev/problems/"
	defaultMaxBodyBytes = 1 << 20
	maxRequestIDLen     = 128
)
