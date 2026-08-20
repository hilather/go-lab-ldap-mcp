package ds389

import (
	"context"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ldapclient"
)

func (r *Runtime) Search(ctx context.Context, q directory.SearchQuery) (directory.SearchPage, error) {
	req, queryKey, cookie, dropBase, err := r.buildSearch(q)
	if err != nil {
		return directory.SearchPage{}, err
	}
	page := r.pageSize(q.PageSize)
	var out directory.SearchPage
	err = r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		res, next, e := c.SearchPage(ctx, req, uint32(page), cookie)
		if e != nil {
			return e
		}
		allow, _ := r.allowSet(q.Attributes)
		for _, e := range res.Entries {
			if dropBase && sameDN(e.DN, req.BaseDN) {
				continue
			}
			out.Entries = append(out.Entries, directory.SearchEntry{
				DN:         e.DN,
				Attributes: filterEntryAttrs(e, allow),
			})
		}
		cur, e := r.encodePageCursor(queryKey, next)
		if e != nil {
			return e
		}
		out.NextCursor = cur
		return nil
	})
	return out, err
}

func (r *Runtime) buildSearch(q directory.SearchQuery) (*ldap.SearchRequest, string, []byte, bool, error) {
	base := strings.TrimSpace(q.Base)
	if base == "" {
		base = r.cfg.Suffix
	}
	parsed, err := config.ParseDN(base)
	if err != nil {
		return nil, "", nil, false, apperr.New(apperr.CodeConfiguration, "search base is not a valid DN").
			WithField(apperr.Field{Path: "base", Code: "invalid_dn", Message: "search base is not a valid DN"})
	}
	managed := r.managedSuffixDNs()
	if len(managed) == 0 {
		return nil, "", nil, false, directory.Error("base", directory.FieldConstraint, "managed suffix is not a valid DN")
	}
	if !config.UnderAny(parsed, managed) {
		return nil, "", nil, false, directory.Error("base", directory.FieldForbidden, "search base is outside configured roots")
	}
	base = parsed.String()

	scopeName := q.Scope
	if scopeName == "" {
		scopeName = directory.SearchScopeSub
	}
	scope, dropBase, err := ldapScope(scopeName)
	if err != nil {
		return nil, "", nil, false, err
	}

	if strings.TrimSpace(q.Filter) == "" {
		return nil, "", nil, false, cfgErr("filter", "empty", "filter is empty")
	}
	if _, err := config.ParseFilterLimits(q.Filter, r.cfg.MaxFilterDepth, r.cfg.MaxFilterLength); err != nil {
		return nil, "", nil, false, err
	}
	// children is emulated as subtree minus the base, so suffix+children+
	// match-all is the same dump as suffix+sub and is rejected with it.
	atRoot := false
	for _, suf := range managed {
		if parsed.Equal(suf) {
			atRoot = true
			break
		}
	}
	if config.IsOverBroad(q.Filter) && atRoot &&
		(scopeName == directory.SearchScopeSub || scopeName == directory.SearchScopeChildren) {
		return nil, "", nil, false, apperr.New(apperr.CodeConfiguration, "search too broad").
			WithField(apperr.Field{Path: "filter", Code: "over_broad", Message: "filter is over-broad"})
	}

	_, attrs := r.allowSet(q.Attributes)
	page := r.pageSize(q.PageSize)
	queryKey := searchCursorKey(base, scopeName, q.Filter, attrs, page)
	cookie, err := r.decodePageCursor(q.Cursor, queryKey)
	if err != nil {
		return nil, "", nil, false, err
	}
	size, seconds := r.searchLimits()
	req := &ldap.SearchRequest{
		BaseDN:       base,
		Scope:        scope,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    size,
		TimeLimit:    seconds,
		Filter:       q.Filter,
		Attributes:   attrs,
	}
	return req, queryKey, cookie, dropBase, nil
}

func ldapScope(scope string) (int, bool, error) {
	switch scope {
	case directory.SearchScopeBase:
		return ldap.ScopeBaseObject, false, nil
	case directory.SearchScopeOne:
		return ldap.ScopeSingleLevel, false, nil
	case directory.SearchScopeSub:
		return ldap.ScopeWholeSubtree, false, nil
	case directory.SearchScopeChildren:
		// 389 DS does not implement LDAP scope 3; emulate with subtree minus base.
		return ldap.ScopeWholeSubtree, true, nil
	default:
		return 0, false, cfgErr("scope", "invalid", "unknown search scope")
	}
}

func searchCursorKey(base, scope, filter string, attrs []string, page int) string {
	return strings.Join([]string{base, scope, filter, strings.Join(attrs, ","), strconv.Itoa(page)}, "|")
}
