package observability

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Registry is a bounded-cardinality Prometheus surface (T-074, OD-021).
// Labels are never DNs, user IDs, request IDs, token IDs, session IDs,
// filters, or passwords.
type Registry struct {
	mu sync.Mutex

	http map[httpKey]*latAcc
	mcp  map[mcpKey]*uint64
	auth map[authKey]*uint64
	rst  map[string]*uint64
	exp  map[string]*uint64

	ldapActive  atomic.Int64
	ldapIdle    atomic.Int64
	ldapMax     atomic.Int64
	ldapWaiters atomic.Int64
	ldapDialOK  atomic.Uint64
	ldapDialErr atomic.Uint64
	ldapWaitTO  atomic.Uint64
	ldapEvict   sync.Map // reason -> *uint64

	resetInProgress atomic.Int64

	snapLDAP  func() (active, idle, max, waiters int)
	snapReset func() bool

	build BuildInfo
}

type httpKey struct{ method, route, class string }
type mcpKey struct{ tool, outcome string }
type authKey struct{ result, reason string }

type latAcc struct {
	count uint64
	sumNS uint64
}

func NewRegistry(build BuildInfo) *Registry {
	return &Registry{
		http:  map[httpKey]*latAcc{},
		mcp:   map[mcpKey]*uint64{},
		auth:  map[authKey]*uint64{},
		rst:   map[string]*uint64{},
		exp:   map[string]*uint64{},
		build: build,
	}
}

func (r *Registry) ObserveHTTP(method, route, statusClass string, d time.Duration) {
	if r == nil {
		return
	}
	k := httpKey{method: boundMethod(method), route: boundRoute(route), class: boundStatusClass(statusClass)}
	r.mu.Lock()
	acc := r.http[k]
	if acc == nil {
		acc = &latAcc{}
		r.http[k] = acc
	}
	acc.count++
	if d > 0 {
		acc.sumNS += uint64(d.Nanoseconds())
	}
	r.mu.Unlock()
}

func (r *Registry) ObserveMCP(tool, outcome string) {
	if r == nil {
		return
	}
	k := mcpKey{tool: boundTool(tool), outcome: boundOutcome(outcome)}
	r.mu.Lock()
	incLocked(r.mcp, k)
	r.mu.Unlock()
}

func (r *Registry) ObserveAuth(result, reason string) {
	if r == nil {
		return
	}
	k := authKey{result: boundAuthResult(result), reason: boundAuthReason(reason)}
	r.mu.Lock()
	incLocked(r.auth, k)
	r.mu.Unlock()
}

func (r *Registry) ObserveReset(outcome string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	incStrLocked(r.rst, boundOutcome(outcome))
	r.mu.Unlock()
}

func (r *Registry) ObserveExport(outcome string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	incStrLocked(r.exp, boundOutcome(outcome))
	r.mu.Unlock()
}

func (r *Registry) SetResetInProgress(v bool) {
	if r == nil {
		return
	}
	if v {
		r.resetInProgress.Store(1)
		return
	}
	r.resetInProgress.Store(0)
}

func (r *Registry) SetLDAPPool(active, idle, max, waiters int) {
	if r == nil {
		return
	}
	r.ldapActive.Store(int64(active))
	r.ldapIdle.Store(int64(idle))
	r.ldapMax.Store(int64(max))
	r.ldapWaiters.Store(int64(waiters))
}

func (r *Registry) ObserveLDAPDial(ok bool) {
	if r == nil {
		return
	}
	if ok {
		r.ldapDialOK.Add(1)
		return
	}
	r.ldapDialErr.Add(1)
}

func (r *Registry) ObserveLDAPWaitTimeout() {
	if r == nil {
		return
	}
	r.ldapWaitTO.Add(1)
}

func (r *Registry) ObserveLDAPEvict(reason string) {
	if r == nil {
		return
	}
	reason = boundEvict(reason)
	v, _ := r.ldapEvict.LoadOrStore(reason, new(uint64))
	ptr := v.(*uint64)
	atomic.AddUint64(ptr, 1)
}

func (r *Registry) ObserveLDAPAcquire(time.Duration) {}
func (r *Registry) ObserveLDAPRelease()              {}

// SetSnapshots installs live LDAP pool and reset-state readers. WritePrometheus
// calls them so /metrics does not depend on a prior /health/ready scrape.
func (r *Registry) SetSnapshots(ldap func() (active, idle, max, waiters int), reset func() bool) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.snapLDAP = ldap
	r.snapReset = reset
	r.mu.Unlock()
}

func (r *Registry) applySnapshots() {
	r.mu.Lock()
	ldap := r.snapLDAP
	rst := r.snapReset
	r.mu.Unlock()
	if ldap != nil {
		a, idle, max, waiters := ldap()
		r.SetLDAPPool(a, idle, max, waiters)
	}
	if rst != nil {
		r.SetResetInProgress(rst())
	}
}

// WritePrometheus emits Prometheus 0.0.4 text. Identity labels are forbidden.
func (r *Registry) WritePrometheus(w io.Writer) {
	if r == nil || w == nil {
		return
	}
	r.applySnapshots()
	r.mu.Lock()
	httpKeys := make([]httpKey, 0, len(r.http))
	for k := range r.http {
		httpKeys = append(httpKeys, k)
	}
	sort.Slice(httpKeys, func(i, j int) bool {
		a, b := httpKeys[i], httpKeys[j]
		if a.method != b.method {
			return a.method < b.method
		}
		if a.route != b.route {
			return a.route < b.route
		}
		return a.class < b.class
	})
	fmt.Fprintln(w, "# HELP labldap_http_requests_total HTTP requests by route template and status class")
	fmt.Fprintln(w, "# TYPE labldap_http_requests_total counter")
	for _, k := range httpKeys {
		acc := r.http[k]
		fmt.Fprintf(w, "labldap_http_requests_total{method=%q,route=%q,status_class=%q} %d\n", k.method, k.route, k.class, acc.count)
	}
	fmt.Fprintln(w, "# HELP labldap_http_request_duration_seconds_sum HTTP request duration sum")
	fmt.Fprintln(w, "# TYPE labldap_http_request_duration_seconds_sum counter")
	for _, k := range httpKeys {
		acc := r.http[k]
		fmt.Fprintf(w, "labldap_http_request_duration_seconds_sum{method=%q,route=%q,status_class=%q} %.6f\n", k.method, k.route, k.class, float64(acc.sumNS)/1e9)
	}

	fmt.Fprintln(w, "# HELP labldap_mcp_requests_total MCP calls by tool and outcome")
	fmt.Fprintln(w, "# TYPE labldap_mcp_requests_total counter")
	mcpKeys := make([]mcpKey, 0, len(r.mcp))
	for k := range r.mcp {
		mcpKeys = append(mcpKeys, k)
	}
	sort.Slice(mcpKeys, func(i, j int) bool {
		if mcpKeys[i].tool != mcpKeys[j].tool {
			return mcpKeys[i].tool < mcpKeys[j].tool
		}
		return mcpKeys[i].outcome < mcpKeys[j].outcome
	})
	for _, k := range mcpKeys {
		fmt.Fprintf(w, "labldap_mcp_requests_total{tool=%q,outcome=%q} %d\n", k.tool, k.outcome, *r.mcp[k])
	}

	fmt.Fprintln(w, "# HELP labldap_auth_total Authentication attempts by result and reason class")
	fmt.Fprintln(w, "# TYPE labldap_auth_total counter")
	authKeys := make([]authKey, 0, len(r.auth))
	for k := range r.auth {
		authKeys = append(authKeys, k)
	}
	sort.Slice(authKeys, func(i, j int) bool {
		if authKeys[i].result != authKeys[j].result {
			return authKeys[i].result < authKeys[j].result
		}
		return authKeys[i].reason < authKeys[j].reason
	})
	for _, k := range authKeys {
		fmt.Fprintf(w, "labldap_auth_total{result=%q,reason=%q} %d\n", k.result, k.reason, *r.auth[k])
	}

	fmt.Fprintln(w, "# HELP labldap_reset_total Soft-reset outcomes")
	fmt.Fprintln(w, "# TYPE labldap_reset_total counter")
	writeStrMap(w, "labldap_reset_total", "outcome", r.rst)
	fmt.Fprintln(w, "# HELP labldap_export_total LDIF export outcomes")
	fmt.Fprintln(w, "# TYPE labldap_export_total counter")
	writeStrMap(w, "labldap_export_total", "outcome", r.exp)
	r.mu.Unlock()

	fmt.Fprintln(w, "# HELP labldap_reset_in_progress 1 when a soft reset is running")
	fmt.Fprintln(w, "# TYPE labldap_reset_in_progress gauge")
	fmt.Fprintf(w, "labldap_reset_in_progress %d\n", r.resetInProgress.Load())

	fmt.Fprintln(w, "# HELP labldap_ldap_pool_active In-use LDAP connections")
	fmt.Fprintln(w, "# TYPE labldap_ldap_pool_active gauge")
	fmt.Fprintf(w, "labldap_ldap_pool_active %d\n", r.ldapActive.Load())
	fmt.Fprintln(w, "# HELP labldap_ldap_pool_idle Idle LDAP connections")
	fmt.Fprintln(w, "# TYPE labldap_ldap_pool_idle gauge")
	fmt.Fprintf(w, "labldap_ldap_pool_idle %d\n", r.ldapIdle.Load())
	fmt.Fprintln(w, "# HELP labldap_ldap_pool_max Configured pool size")
	fmt.Fprintln(w, "# TYPE labldap_ldap_pool_max gauge")
	fmt.Fprintf(w, "labldap_ldap_pool_max %d\n", r.ldapMax.Load())
	fmt.Fprintln(w, "# HELP labldap_ldap_pool_waiters Waiters blocked on the pool")
	fmt.Fprintln(w, "# TYPE labldap_ldap_pool_waiters gauge")
	fmt.Fprintf(w, "labldap_ldap_pool_waiters %d\n", r.ldapWaiters.Load())
	fmt.Fprintln(w, "# HELP labldap_ldap_dials_total LDAP dial attempts")
	fmt.Fprintln(w, "# TYPE labldap_ldap_dials_total counter")
	fmt.Fprintf(w, "labldap_ldap_dials_total{result=%q} %d\n", "ok", r.ldapDialOK.Load())
	fmt.Fprintf(w, "labldap_ldap_dials_total{result=%q} %d\n", "error", r.ldapDialErr.Load())
	fmt.Fprintln(w, "# HELP labldap_ldap_wait_timeouts_total Pool wait timeouts")
	fmt.Fprintln(w, "# TYPE labldap_ldap_wait_timeouts_total counter")
	fmt.Fprintf(w, "labldap_ldap_wait_timeouts_total %d\n", r.ldapWaitTO.Load())
	fmt.Fprintln(w, "# HELP labldap_ldap_evictions_total Connection evictions by reason class")
	fmt.Fprintln(w, "# TYPE labldap_ldap_evictions_total counter")
	var reasons []string
	r.ldapEvict.Range(func(key, _ any) bool {
		reasons = append(reasons, key.(string))
		return true
	})
	sort.Strings(reasons)
	for _, reason := range reasons {
		v, _ := r.ldapEvict.Load(reason)
		fmt.Fprintf(w, "labldap_ldap_evictions_total{reason=%q} %d\n", reason, atomic.LoadUint64(v.(*uint64)))
	}

	ver := sanitizeLabel(r.build.Version)
	rev := sanitizeLabel(r.build.Revision)
	fmt.Fprintln(w, "# HELP labldap_build_info Build version and source revision")
	fmt.Fprintln(w, "# TYPE labldap_build_info gauge")
	fmt.Fprintf(w, "labldap_build_info{version=%q,revision=%q} 1\n", ver, rev)
}

func incLocked[K comparable](m map[K]*uint64, k K) {
	p := m[k]
	if p == nil {
		var z uint64
		p = &z
		m[k] = p
	}
	*p++
}

func incStrLocked(m map[string]*uint64, k string) { incLocked(m, k) }

func writeStrMap(w io.Writer, metric, label string, m map[string]*uint64) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "%s{%s=%q} %d\n", metric, label, k, *m[k])
	}
}

func boundMethod(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD":
		return strings.ToUpper(strings.TrimSpace(s))
	default:
		return "OTHER"
	}
}

func boundStatusClass(s string) string {
	switch s {
	case "1xx", "2xx", "3xx", "4xx", "5xx":
		return s
	default:
		return "5xx"
	}
}

func boundOutcome(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "ok", "success":
		return "success"
	case "denied", "forbidden":
		return "denied"
	case "error", "failure":
		return "failure"
	default:
		return "other"
	}
}

func boundAuthResult(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "success", "ok":
		return "success"
	default:
		return "failure"
	}
}

func boundAuthReason(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "ok", "missing", "malformed", "invalid", "forbidden":
		return strings.ToLower(strings.TrimSpace(s))
	default:
		return "other"
	}
}

func boundEvict(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "idle", "lifetime", "broken", "shutdown":
		return strings.ToLower(strings.TrimSpace(s))
	default:
		return "other"
	}
}

func boundTool(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "other"
	}
	// Tool names are catalog identifiers, never request/user IDs.
	if len(s) > 64 || strings.ContainsAny(s, " \t\r\n\"{}") {
		return "other"
	}
	return s
}

func boundRoute(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "other"
	}
	if _, ok := knownRoutes[s]; ok {
		return s
	}
	return "other"
}

func sanitizeLabel(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown"
	}
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

func StatusClass(code int) string {
	switch {
	case code >= 100 && code < 200:
		return "1xx"
	case code >= 200 && code < 300:
		return "2xx"
	case code >= 300 && code < 400:
		return "3xx"
	case code >= 400 && code < 500:
		return "4xx"
	default:
		return "5xx"
	}
}

// RouteTemplate maps a request path to a bounded route template.
func RouteTemplate(method, path string) string {
	_ = method
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		path = "/"
	}
	if _, ok := knownRoutes[path]; ok {
		return path
	}
	if t, ok := matchTemplated(path); ok {
		return t
	}
	return "other"
}

var knownRoutes = map[string]struct{}{
	"/health": {}, "/health/ready": {}, "/metrics": {}, "/mcp": {},
	"/api/v1/version": {}, "/api/v1/capabilities": {}, "/api/v1/baseline": {},
	"/api/v1/session": {}, "/api/v1/users": {}, "/api/v1/groups": {},
	"/api/v1/search": {}, "/api/v1/auth-tests": {}, "/api/v1/rootdse": {},
	"/api/v1/schema": {}, "/api/v1/audit": {}, "/api/v1/reset": {},
	"/api/v1/export": {}, "/api/v1/diagnostics": {},
	"/api/v1/users/{id}": {}, "/api/v1/users/{id}/password": {},
	"/api/v1/users/{id}/enable": {}, "/api/v1/users/{id}/disable": {},
	"/api/v1/users/{id}/account-state":         {},
	"/api/v1/users/{id}/expire-password":       {},
	"/api/v1/users/{id}/clear-password-expiry": {},
	"/api/v1/users/{id}/lock":                  {}, "/api/v1/users/{id}/unlock": {},
	"/api/v1/users/{id}/groups": {},
	"/api/v1/groups/{id}":       {}, "/api/v1/groups/{id}/members": {},
	"/api/v1/schema/objectclasses/{name}": {},
	"/api/v1/schema/attributes/{name}":    {},
}

func matchTemplated(path string) (string, bool) {
	switch {
	case strings.HasPrefix(path, "/api/v1/users/") && strings.HasSuffix(path, "/password"):
		return "/api/v1/users/{id}/password", true
	case strings.HasPrefix(path, "/api/v1/users/") && strings.HasSuffix(path, "/enable"):
		return "/api/v1/users/{id}/enable", true
	case strings.HasPrefix(path, "/api/v1/users/") && strings.HasSuffix(path, "/disable"):
		return "/api/v1/users/{id}/disable", true
	case strings.HasPrefix(path, "/api/v1/users/") && strings.HasSuffix(path, "/account-state"):
		return "/api/v1/users/{id}/account-state", true
	case strings.HasPrefix(path, "/api/v1/users/") && strings.HasSuffix(path, "/expire-password"):
		return "/api/v1/users/{id}/expire-password", true
	case strings.HasPrefix(path, "/api/v1/users/") && strings.HasSuffix(path, "/clear-password-expiry"):
		return "/api/v1/users/{id}/clear-password-expiry", true
	case strings.HasPrefix(path, "/api/v1/users/") && strings.HasSuffix(path, "/unlock"):
		return "/api/v1/users/{id}/unlock", true
	case strings.HasPrefix(path, "/api/v1/users/") && strings.HasSuffix(path, "/lock"):
		return "/api/v1/users/{id}/lock", true
	case strings.HasPrefix(path, "/api/v1/users/") && strings.HasSuffix(path, "/groups"):
		return "/api/v1/users/{id}/groups", true
	case strings.HasPrefix(path, "/api/v1/users/"):
		return "/api/v1/users/{id}", true
	case strings.HasPrefix(path, "/api/v1/groups/") && strings.HasSuffix(path, "/members"):
		return "/api/v1/groups/{id}/members", true
	case strings.HasPrefix(path, "/api/v1/groups/"):
		return "/api/v1/groups/{id}", true
	case strings.HasPrefix(path, "/api/v1/schema/objectclasses/"):
		return "/api/v1/schema/objectclasses/{name}", true
	case strings.HasPrefix(path, "/api/v1/schema/attributes/"):
		return "/api/v1/schema/attributes/{name}", true
	default:
		return "", false
	}
}
