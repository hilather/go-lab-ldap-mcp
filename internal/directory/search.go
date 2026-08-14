package directory

// SearchQuery is the shared REST/MCP search input (design §3.3).
// Filter syntax is validated with config.ParseFilter; empty is field code empty.
type SearchQuery struct {
	Base       string   `json:"base"`
	Scope      string   `json:"scope"`
	Filter     string   `json:"filter"`
	Attributes []string `json:"attributes"`
	PageSize   int      `json:"pageSize"`
	Cursor     string   `json:"cursor"`
}

const (
	SearchScopeBase     = "base"
	SearchScopeOne      = "one"
	SearchScopeSub      = "sub"
	SearchScopeChildren = "children"
)
