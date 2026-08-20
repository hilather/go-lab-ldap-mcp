package ds389

import (
	"context"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ldapclient"
)

func (r *Runtime) Inventory(ctx context.Context) (directory.ManagedInventory, error) {
	if r == nil {
		return directory.ManagedInventory{}, directory.Error("reset", directory.FieldUnavailable, "runtime is not configured")
	}
	preserve := r.preserveDNs()
	page := r.cfg.InventoryPageSize
	if page <= 0 {
		page = r.pageSize(0)
	}
	_, seconds := r.searchLimits()
	var out directory.ManagedInventory
	err := r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		people, e := pageSubtree(ctx, c, r.cfg.PeopleDN, uint32(page), seconds)
		if e != nil {
			return e
		}
		groups, e := pageSubtree(ctx, c, r.cfg.GroupsDN, uint32(page), seconds)
		if e != nil {
			return e
		}
		seen := map[string]struct{}{}
		add := func(dn string, users *[]string, groupsOut *[]string, extra *[]string, userLike, groupLike bool) {
			if _, keep := preserve[dnKey(dn)]; keep {
				return
			}
			if sameDN(dn, r.cfg.PeopleDN) || sameDN(dn, r.cfg.GroupsDN) {
				return
			}
			key := dnKey(dn)
			if _, ok := seen[key]; ok {
				return
			}
			seen[key] = struct{}{}
			switch {
			case userLike:
				*users = append(*users, dn)
			case groupLike:
				*groupsOut = append(*groupsOut, dn)
			default:
				*extra = append(*extra, dn)
			}
		}
		for _, e := range people {
			if e == nil {
				continue
			}
			add(e.DN, &out.Users, &out.Groups, &out.Extra, isPersonEntry(e), false)
		}
		for _, e := range groups {
			if e == nil {
				continue
			}
			add(e.DN, &out.Users, &out.Groups, &out.Extra, false, isGroupEntry(e))
		}
		for _, extraBase := range r.cfg.AdditionalSuffixes {
			ents, e := pageSubtree(ctx, c, extraBase, uint32(page), seconds)
			if e != nil {
				if fieldOf(e) == directory.FieldNotFound {
					continue
				}
				return e
			}
			for _, ent := range ents {
				if ent == nil || sameDN(ent.DN, extraBase) {
					continue
				}
				add(ent.DN, &out.Users, &out.Groups, &out.Extra, isPersonEntry(ent), isGroupEntry(ent))
			}
		}
		return nil
	})
	if err != nil {
		return directory.ManagedInventory{}, err
	}
	out.Preserve = make([]string, 0, len(preserve))
	for _, dn := range preserve {
		out.Preserve = append(out.Preserve, dn)
	}
	sort.Strings(out.Users)
	sort.Strings(out.Groups)
	sort.Strings(out.Extra)
	sort.Strings(out.Preserve)
	return out, nil
}

func (r *Runtime) DeleteManaged(ctx context.Context, dn string) error {
	if r == nil {
		return directory.Error("reset", directory.FieldUnavailable, "runtime is not configured")
	}
	parsed, err := config.ParseDN(dn)
	if err != nil {
		return directory.Error("dn", directory.FieldConstraint, "delete DN is not valid")
	}
	dn = parsed.String()
	if r.isProtectedDN(dn) {
		return directory.Error("dn", directory.FieldForbidden, "protected directory entry cannot be deleted")
	}
	if !r.resetDeleteAllowed(dn) {
		return directory.Error("dn", directory.FieldForbidden, "delete is outside managed suffixes")
	}
	size, seconds := r.searchLimits()
	return r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		if _, e := searchBaseConn(ctx, c, dn, []string{"objectClass"}, size, seconds); e != nil {
			if fieldOf(e) == directory.FieldNotFound {
				return nil
			}
			return e
		}
		if e := c.Del(ctx, ldap.NewDelRequest(dn, nil)); e != nil {
			if fieldOf(e) == directory.FieldNotFound {
				return nil
			}
			return e
		}
		return nil
	})
}

func (r *Runtime) preserveDNs() map[string]string {
	out := map[string]string{}
	add := func(dn string) {
		dn = strings.TrimSpace(dn)
		if dn == "" {
			return
		}
		out[dnKey(dn)] = canonicalOrRaw(dn)
	}
	add(r.cfg.RuntimeDN)
	add(r.cfg.PeopleDN)
	add(r.cfg.GroupsDN)
	add(r.cfg.MarkerDN)
	if r.cfg.MarkerDN == "" && r.cfg.Suffix != "" {
		add("cn=" + markerCN + "," + r.cfg.Suffix)
	}
	add(r.cfg.Suffix)
	for _, extra := range r.cfg.AdditionalSuffixes {
		add(extra)
	}
	return out
}

func (r *Runtime) isProtectedDN(dn string) bool {
	if _, ok := r.preserveDNs()[dnKey(dn)]; ok {
		return true
	}
	return r.cfg.RuntimeDN != "" && sameDN(dn, r.cfg.RuntimeDN)
}

// resetDeleteAllowed is the DeleteManaged write gate. Soft reset may
// remove entries under people/groups, or operator extras under an
// additional suffix (ADR-0011). Entries under the primary suffix that
// are not under people/groups — such as cn=outside,<suffix> — stay
// forbidden even though they sit inside a managed naming context.
func (r *Runtime) resetDeleteAllowed(dn string) bool {
	if r.underPeople(dn) || r.underGroups(dn) {
		return true
	}
	return r.underAdditionalSuffix(dn)
}

func (r *Runtime) underAdditionalSuffix(dn string) bool {
	got, err := config.ParseDN(dn)
	if err != nil {
		return false
	}
	for _, raw := range r.cfg.AdditionalSuffixes {
		par, err := config.ParseDN(raw)
		if err != nil {
			continue
		}
		if got.IsDescendantOf(par) {
			return true
		}
	}
	return false
}

func pageSubtree(ctx context.Context, c *ldapclient.Conn, base string, page uint32, seconds int) ([]*ldap.Entry, error) {
	if strings.TrimSpace(base) == "" {
		return nil, nil
	}
	req := &ldap.SearchRequest{
		BaseDN:       base,
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    0,
		TimeLimit:    seconds,
		Filter:       "(objectClass=*)",
		Attributes:   []string{"objectClass"},
	}
	var all []*ldap.Entry
	var cookie []byte
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		res, next, err := c.SearchPage(ctx, req, page, cookie)
		if err != nil {
			if fieldOf(err) == directory.FieldNotFound {
				return nil, nil
			}
			return nil, err
		}
		all = append(all, res.Entries...)
		if len(next) == 0 {
			break
		}
		cookie = next
	}
	return all, nil
}

func isPersonEntry(e *ldap.Entry) bool {
	return hasObjectClass(e, "inetOrgPerson") || hasObjectClass(e, "person") || e.GetAttributeValue("uid") != ""
}

func isGroupEntry(e *ldap.Entry) bool {
	return hasObjectClass(e, "groupOfNames") || hasObjectClass(e, "groupOfUniqueNames")
}

func canonicalOrRaw(dn string) string {
	d, err := config.ParseDN(dn)
	if err != nil {
		return strings.TrimSpace(dn)
	}
	return d.String()
}
