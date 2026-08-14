package ds389

import (
	"context"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ldapclient"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

var (
	_ directory.SearchRepository    = (*Runtime)(nil)
	_ directory.BindTester          = (*Runtime)(nil)
	_ directory.SchemaRepository    = (*Runtime)(nil)
	_ directory.CapabilityInspector = (*Runtime)(nil)
)

// Runtime is the restricted-account repository surface (T-048–T-052).
type Runtime struct {
	pool *ldapclient.Pool
	cfg  RuntimeConfig
	now  func() time.Time

	cache schemaCache
}

// RuntimeConfig is compiled directory geometry plus search/schema limits.
type RuntimeConfig struct {
	Suffix       string
	PeopleDN     string
	GroupsDN     string
	RuntimeDN    string
	NestedGroups bool
	// NestedMemberHook, if set, is the nested-group validation hook (T-049).
	NestedMemberHook func(member directory.MemberRef) error

	PageSizeDefault int
	PageSizeMax     int
	SearchSizeLimit int
	SearchTimeLimit time.Duration
	MaxFilterDepth  int
	MaxFilterLength int
	SchemaTTL       time.Duration
	AllowedAttrs    []string

	// CursorKey is the process-local HMAC key. Empty → generated in NewRuntime.
	CursorKey config.CursorKey
	CursorTTL time.Duration
	// Assertion, if set, overrides Root DSE supportedControl for OID 1.3.6.1.1.12.
	Assertion *bool

	// Client is the unbound-capable LDAP config for disposable bind-test.
	Client ldapclient.Config
	// Connect, if set, replaces ldapclient.Connect (tests).
	Connect func(ctx context.Context, cfg ldapclient.Config) (*ldapclient.Conn, error)
}

var defaultAllowedAttrs = []string{
	"objectclass", "uid", "cn", "sn", "givenname", "mail", "displayname",
	"description", "member", "uniquemember", "memberof", "ou", "dc",
	"nsaccountlock", "ismemberof",
}

func NewRuntime(pool *ldapclient.Pool, cfg RuntimeConfig) (*Runtime, error) {
	if pool == nil {
		return nil, directory.Error("connection", directory.FieldUnavailable, "ldap pool is required")
	}
	cfg.applyDefaults()
	if cfg.Suffix == "" || cfg.PeopleDN == "" || cfg.GroupsDN == "" {
		return nil, directory.Error("directory", directory.FieldConstraint, "managed suffix is required")
	}
	return &Runtime{pool: pool, cfg: cfg, now: time.Now}, nil
}

func (c *RuntimeConfig) applyDefaults() {
	if c.PageSizeDefault <= 0 {
		c.PageSizeDefault = 50
	}
	if c.PageSizeMax <= 0 {
		c.PageSizeMax = 500
	}
	if c.SearchSizeLimit <= 0 {
		c.SearchSizeLimit = 1000
	}
	if c.SearchTimeLimit <= 0 {
		c.SearchTimeLimit = 10 * time.Second
	}
	if c.MaxFilterDepth <= 0 {
		c.MaxFilterDepth = 16
	}
	if c.MaxFilterLength <= 0 {
		c.MaxFilterLength = 4096
	}
	if c.SchemaTTL <= 0 {
		c.SchemaTTL = 60 * time.Second
	}
	if len(c.AllowedAttrs) == 0 {
		c.AllowedAttrs = append([]string(nil), defaultAllowedAttrs...)
	}
	if len(c.CursorKey) == 0 {
		c.CursorKey = config.NewCursorKey()
	}
	if c.CursorTTL <= 0 {
		c.CursorTTL = config.DefaultCursorTTL
	}
}

func (r *Runtime) InvalidateSchema() {
	r.cache.invalidate()
}

func cfgErr(path, code, msg string) *apperr.Error {
	return apperr.New(apperr.CodeConfiguration, msg).WithField(apperr.Field{
		Path: path, Code: code, Message: msg,
	})
}

func parseSafeID(id, path string) error {
	if strings.TrimSpace(id) == "" {
		return cfgErr(path, "required", "id is required")
	}
	if strings.ContainsRune(id, 0) {
		return cfgErr(path, "invalid", "id contains NUL")
	}
	if strings.ContainsAny(id, ",=") {
		return cfgErr(path, "invalid", "id must not be a DN")
	}
	if _, err := config.BuildRDN("uid", id); err != nil {
		return cfgErr(path, "invalid_rdn", "id is not a safe identifier")
	}
	return nil
}

func (r *Runtime) userDN(uid string) (string, error) {
	if err := parseSafeID(uid, "id"); err != nil {
		return "", err
	}
	rdn, err := config.BuildRDN("uid", uid)
	if err != nil {
		return "", cfgErr("id", "invalid_rdn", "cannot build user DN")
	}
	return rdn + "," + r.cfg.PeopleDN, nil
}

func (r *Runtime) groupDN(id string) (string, error) {
	if err := parseSafeID(id, "id"); err != nil {
		return "", err
	}
	rdn, err := config.BuildRDN("cn", id)
	if err != nil {
		return "", cfgErr("id", "invalid_rdn", "cannot build group DN")
	}
	return rdn + "," + r.cfg.GroupsDN, nil
}

func (r *Runtime) searchLimits() (size, seconds int) {
	size = r.cfg.SearchSizeLimit
	if size <= 0 {
		size = 1000
	}
	seconds = int(r.cfg.SearchTimeLimit.Round(time.Second) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	return size, seconds
}

func (r *Runtime) pageSize(n int) int {
	if n <= 0 {
		n = r.cfg.PageSizeDefault
	}
	if n > r.cfg.PageSizeMax {
		n = r.cfg.PageSizeMax
	}
	if n > r.cfg.SearchSizeLimit && r.cfg.SearchSizeLimit > 0 {
		n = r.cfg.SearchSizeLimit
	}
	if n < 1 {
		n = 1
	}
	return n
}

func (r *Runtime) underManaged(dn string) bool {
	got, err := config.ParseDN(dn)
	if err != nil {
		return false
	}
	suf, err := config.ParseDN(r.cfg.Suffix)
	if err != nil {
		return false
	}
	return got.Equal(suf) || got.IsDescendantOf(suf)
}

func (r *Runtime) underPeople(dn string) bool {
	return underContainer(dn, r.cfg.PeopleDN)
}

func (r *Runtime) underGroups(dn string) bool {
	return underContainer(dn, r.cfg.GroupsDN)
}

func underContainer(dn, container string) bool {
	got, err := config.ParseDN(dn)
	if err != nil {
		return false
	}
	par, err := config.ParseDN(container)
	if err != nil {
		return false
	}
	return got.IsDescendantOf(par)
}

func checkRev(got, want directory.Revision) error {
	if want == "" || got == want {
		return nil
	}
	return directory.Error("revision", directory.FieldConflict, "directory entry revision does not match")
}

func leafValue(dn string) string {
	parsed, err := config.ParseDN(dn)
	if err != nil {
		return ""
	}
	_, v, ok := parsed.Leaf()
	if !ok {
		return ""
	}
	return v
}

func attrMapValue(m map[string]string, name string) string {
	want := config.CanonicalAttr(name)
	for k, v := range m {
		if config.CanonicalAttr(k) == want {
			return v
		}
	}
	return ""
}

func forbiddenWriteAttr(name string) bool {
	return config.ForbiddenUserAttr(name)
}

func skipReturnedAttr(name string) bool {
	switch config.CanonicalAttr(name) {
	case "userpassword", "aci", "nsslapd-rootpw", "nsslapd-rootpwstoragescheme",
		"nsmultiplexorbindcred", "nsmultiplexorcredentials",
		"entrycsn", "modifytimestamp", "entryuuid", "nsuniqueid",
		"createtimestamp", "creatorsname", "modifiersname",
		"entrydn", "numsubordinates":
		return true
	default:
		return false
	}
}

func operationalReadAttrs() []string {
	return []string{"entryCSN", "modifyTimestamp", "entryUUID"}
}

func runtimeUserReadAttrs() []string {
	return append([]string{
		"objectClass", "uid", "cn", "sn", "givenName", "mail", "displayName",
		"description", "nsAccountLock", "memberOf",
	}, operationalReadAttrs()...)
}

func groupReadAttrs() []string {
	return append([]string{"objectClass", "cn", "member", "uniqueMember"}, operationalReadAttrs()...)
}

func searchBaseConn(ctx context.Context, c *ldapclient.Conn, dn string, attrs []string, size, seconds int) (*ldap.Entry, error) {
	res, err := c.Search(ctx, &ldap.SearchRequest{
		BaseDN:       dn,
		Scope:        ldap.ScopeBaseObject,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    size,
		TimeLimit:    seconds,
		Filter:       "(objectClass=*)",
		Attributes:   attrs,
	})
	if err != nil {
		return nil, err
	}
	if len(res.Entries) == 0 {
		return nil, directory.Error("entry", directory.FieldNotFound, "directory entry not found")
	}
	return res.Entries[0], nil
}

func existsConn(ctx context.Context, c *ldapclient.Conn, dn string, size, seconds int) (bool, error) {
	_, err := searchBaseConn(ctx, c, dn, []string{"objectClass"}, size, seconds)
	if err == nil {
		return true, nil
	}
	if fieldOf(err) == directory.FieldNotFound {
		return false, nil
	}
	return false, err
}

func fieldOf(err error) string {
	var e *apperr.Error
	if err == nil || !errors.As(err, &e) {
		return ""
	}
	for _, f := range e.Fields() {
		if f.Code != "" {
			return f.Code
		}
	}
	return ""
}

func hasField(err error, path, code string) bool {
	var e *apperr.Error
	if !errors.As(err, &e) {
		return false
	}
	for _, f := range e.Fields() {
		if (path == "" || f.Path == path) && f.Code == code {
			return true
		}
	}
	return false
}

func sortAttrKV(in []directory.AttrKV) []directory.AttrKV {
	out := append([]directory.AttrKV(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Value < out[j].Value
	})
	return out
}

func sortCI(in []string) []string {
	out := append([]string(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i]) < strings.ToLower(out[j])
	})
	return out
}

func (r *Runtime) encodePageCursor(query string, cookie []byte) (string, error) {
	if len(cookie) == 0 {
		return "", nil
	}
	return config.ProtectCursor(r.cfg.CursorKey, config.Cursor{
		Query: query,
		Page:  hex.EncodeToString(cookie),
	}, r.now().Add(r.cfg.CursorTTL))
}

func (r *Runtime) decodePageCursor(raw, query string) ([]byte, error) {
	if raw == "" {
		return nil, nil
	}
	c, err := config.UnprotectCursor(r.cfg.CursorKey, raw, r.now())
	if err != nil {
		return nil, err
	}
	if c.Query != query {
		return nil, cfgErr("cursor", "invalid", "cursor does not match this query")
	}
	if c.Page == "" {
		return nil, nil
	}
	b, err := hex.DecodeString(c.Page)
	if err != nil {
		return nil, cfgErr("cursor", "invalid", "cursor is malformed")
	}
	return b, nil
}

// assertionEnabled is true when T-044 Controls listed 1.3.6.1.1.12, or a test override.
func (r *Runtime) assertionEnabled(ctx context.Context) bool {
	if r.cfg.Assertion != nil {
		return *r.cfg.Assertion
	}
	dse, err := r.RootDSE(ctx)
	if err != nil {
		return false
	}
	return directory.Capabilities{Controls: dse.SupportedControls}.HasAssertionControl()
}

func assertionFilter(e *ldap.Entry) string {
	if e == nil {
		return ""
	}
	if v := e.GetAttributeValue("entryCSN"); v != "" {
		return "(entryCSN=" + ldapclient.EscapeFilter(v) + ")"
	}
	if v := e.GetAttributeValue("modifyTimestamp"); v != "" {
		return "(modifyTimestamp=" + ldapclient.EscapeFilter(v) + ")"
	}
	if v := e.GetAttributeValue("entryUUID"); v != "" {
		return "(entryUUID=" + ldapclient.EscapeFilter(v) + ")"
	}
	return ""
}

func (r *Runtime) assertionControl(ctx context.Context, live *ldap.Entry) ldap.Control {
	if live == nil || !r.assertionEnabled(ctx) {
		return nil
	}
	filter := assertionFilter(live)
	if filter == "" {
		return nil
	}
	ctl, err := ldapclient.NewControlAssertion(filter)
	if err != nil {
		return nil
	}
	return ctl
}

func newModify(ctx context.Context, r *Runtime, dn string, live *ldap.Entry) *ldap.ModifyRequest {
	var controls []ldap.Control
	if ctl := r.assertionControl(ctx, live); ctl != nil {
		controls = append(controls, ctl)
	}
	return ldap.NewModifyRequest(dn, controls)
}

func newDelete(ctx context.Context, r *Runtime, dn string, live *ldap.Entry) *ldap.DelRequest {
	var controls []ldap.Control
	if ctl := r.assertionControl(ctx, live); ctl != nil {
		controls = append(controls, ctl)
	}
	return ldap.NewDelRequest(dn, controls)
}

func filterEntryAttrs(e *ldap.Entry, allow map[string]struct{}) []directory.AttrKV {
	if e == nil {
		return nil
	}
	var out []directory.AttrKV
	for _, a := range e.Attributes {
		name := config.CanonicalAttr(a.Name)
		if skipReturnedAttr(name) {
			continue
		}
		if len(allow) > 0 {
			if _, ok := allow[name]; !ok {
				continue
			}
		}
		for _, v := range a.Values {
			out = append(out, directory.AttrKV{Name: name, Value: v})
		}
	}
	return sortAttrKV(out)
}

func (r *Runtime) allowSet(requested []string) (map[string]struct{}, []string) {
	allow := map[string]struct{}{}
	for _, a := range r.cfg.AllowedAttrs {
		allow[config.CanonicalAttr(a)] = struct{}{}
	}
	if len(requested) == 0 {
		names := make([]string, 0, len(allow))
		for n := range allow {
			if !skipReturnedAttr(n) {
				names = append(names, n)
			}
		}
		sort.Strings(names)
		return allow, names
	}
	var names []string
	want := map[string]struct{}{}
	for _, a := range requested {
		n := config.CanonicalAttr(a)
		if n == "" || skipReturnedAttr(n) || n == "*" {
			continue
		}
		if _, ok := allow[n]; !ok {
			continue
		}
		if _, dup := want[n]; dup {
			continue
		}
		want[n] = struct{}{}
		names = append(names, n)
	}
	if len(names) == 0 {
		return allow, []string{"objectclass"}
	}
	return want, names
}

func redactSecrets(err error, secrets ...observability.Secret) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	for _, s := range secrets {
		if v := s.Reveal(); v != "" && strings.Contains(msg, v) {
			return directory.Error("bind", directory.FieldInvalidCredentials, "invalid credentials")
		}
	}
	return err
}
