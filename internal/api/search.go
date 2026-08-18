package api

import (
	"net"
	"net/http"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

type searchQueryBody struct {
	Base       string   `json:"base"`
	Scope      string   `json:"scope"`
	Filter     string   `json:"filter"`
	Attributes []string `json:"attributes"`
	PageSize   int      `json:"pageSize"`
	Cursor     string   `json:"cursor"`
}

type bindTestBody struct {
	Identity  string               `json:"identity"`
	Password  observability.Secret `json:"password"`
	Transport string               `json:"transport,omitempty"`
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireScope(w, r, auth.ScopeDirectoryRead)
	if !ok || !s.requireQuery(w, r) || !requireJSONBody(w, r) {
		return
	}
	// Search bodies are never logged: filters and requested attributes stay off slog.
	var body searchQueryBody
	if err := DecodeJSON(r.Body, &body); err != nil {
		writeProblem(w, r, err)
		return
	}
	q, err := s.searchQuery(body)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	out, err := s.query.Search(r.Context(), p, q)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeSearchPage(w, r, out)
}

func (s *Server) handleBindTest(w http.ResponseWriter, r *http.Request) {
	// directory:write does not imply directory:password (§3.6).
	p, ok := s.requireScope(w, r, auth.ScopeDirectoryPassword)
	if !ok || !s.requireQuery(w, r) || !requireJSONBody(w, r) {
		return
	}
	if err := s.allowBindTest(r, p); err != nil {
		writeProblem(w, r, err)
		return
	}
	// Sensitive decode: password is observability.Secret and must not be logged.
	var body bindTestBody
	if err := DecodeJSON(r.Body, &body); err != nil {
		writeProblem(w, r, err)
		return
	}
	identity := strings.TrimSpace(body.Identity)
	pw := body.Password
	transport, err := parseBindTransport(body.Transport)
	body.Password = ""
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	if identity == "" {
		writeProblem(w, r, apperr.New(apperr.CodeConfiguration, "identity is required").WithField(apperr.Field{
			Path: "identity", Code: "empty", Message: "identity is required",
		}))
		return
	}
	res, err := s.query.BindTest(r.Context(), p, identity, pw, transport)
	if diagnosticOutcome(res.Outcome) {
		writeBindTest(w, r, res)
		return
	}
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeBindTest(w, r, res)
}

func (s *Server) searchQuery(body searchQueryBody) (directory.SearchQuery, error) {
	if !validSearchScope(body.Scope) {
		return directory.SearchQuery{}, apperr.New(apperr.CodeConfiguration, "unknown search scope").WithField(apperr.Field{
			Path: "scope", Code: "invalid", Message: "unknown search scope",
		})
	}
	if strings.TrimSpace(body.Filter) == "" {
		return directory.SearchQuery{}, apperr.New(apperr.CodeConfiguration, "filter is empty").WithField(apperr.Field{
			Path: "filter", Code: "empty", Message: "filter is empty",
		})
	}
	page, err := s.searchPageSize(body.PageSize)
	if err != nil {
		return directory.SearchQuery{}, err
	}
	return directory.SearchQuery{
		Base:       strings.TrimSpace(body.Base),
		Scope:      body.Scope,
		Filter:     body.Filter,
		Attributes: body.Attributes,
		PageSize:   page,
		Cursor:     body.Cursor,
	}, nil
}

func (s *Server) searchPageSize(n int) (int, error) {
	def, max := defaultPageSize, defaultPageMax
	if s != nil {
		if s.pageSizeDefault > 0 {
			def = s.pageSizeDefault
		}
		if s.pageSizeMax > 0 {
			max = s.pageSizeMax
		}
	}
	if n == 0 {
		return def, nil
	}
	if n < 1 {
		return 0, apperr.New(apperr.CodeConfiguration, "pageSize is invalid").WithField(apperr.Field{
			Path: "pageSize", Code: "invalid", Message: "pageSize must be a positive integer",
		})
	}
	if n > max {
		return 0, apperr.New(apperr.CodeConfiguration, "pageSize exceeds the configured maximum").WithField(apperr.Field{
			Path: "pageSize", Code: "too_large", Message: "pageSize exceeds the configured maximum",
		})
	}
	return n, nil
}

func validSearchScope(scope string) bool {
	switch scope {
	case "", directory.SearchScopeBase, directory.SearchScopeOne, directory.SearchScopeSub, directory.SearchScopeChildren:
		return true
	default:
		return false
	}
}

func parseBindTransport(raw string) (directory.Transport, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", nil
	case string(directory.TransportLDAP):
		return directory.TransportLDAP, nil
	case string(directory.TransportLDAPS):
		return directory.TransportLDAPS, nil
	case string(directory.TransportStartTLS):
		return directory.TransportStartTLS, nil
	default:
		return "", apperr.New(apperr.CodeConfiguration, "unknown bind transport").WithField(apperr.Field{
			Path: "transport", Code: "invalid", Message: "unknown bind transport",
		})
	}
}

func diagnosticOutcome(outcome string) bool {
	switch outcome {
	case directory.BindOutcomeInvalidCredentials, directory.BindOutcomeLocked, directory.BindOutcomeDisabled, directory.BindOutcomeMustChange:
		return true
	default:
		return false
	}
}

func (s *Server) allowBindTest(r *http.Request, p app.Principal) error {
	if s == nil || s.limiter == nil {
		return nil
	}
	if !s.limiter.Allow("bind:ip:" + requestIP(r)) {
		return rateLimited()
	}
	if p.ID != "" && !s.limiter.Allow("bind:actor:"+p.ID) {
		return rateLimited()
	}
	return nil
}

func rateLimited() error {
	return apperr.New(apperr.CodeAuth, "rate limit exceeded").WithField(apperr.Field{
		Path: "rateLimit", Code: "rate_limited", Message: "rate limit exceeded",
	}).Retry()
}

func requestIP(r *http.Request) string {
	if r == nil || r.RemoteAddr == "" {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeSearchPage(w http.ResponseWriter, r *http.Request, page directory.SearchPage) {
	if page.Entries == nil {
		page.Entries = []directory.SearchEntry{}
	}
	for i := range page.Entries {
		if page.Entries[i].Attributes == nil {
			page.Entries[i].Attributes = []directory.AttrKV{}
		}
	}
	setNoStore(w)
	writeJSON(w, r, http.StatusOK, "application/json", page)
}

func writeBindTest(w http.ResponseWriter, r *http.Request, res directory.BindTestResult) {
	setNoStore(w)
	writeJSON(w, r, http.StatusOK, "application/json", res)
}
