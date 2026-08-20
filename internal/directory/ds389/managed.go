package ds389

import (
	"context"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ldapclient"
)

func (r *Runtime) managedSuffixDNs() []config.DN {
	var out []config.DN
	if s, err := config.ParseDN(r.cfg.Suffix); err == nil {
		out = append(out, s)
	}
	for _, raw := range r.cfg.AdditionalSuffixes {
		d, err := config.ParseDN(raw)
		if err != nil {
			continue
		}
		out = append(out, d)
	}
	return out
}

func (r *Runtime) managedSuffixStrings() []string {
	dns := r.managedSuffixDNs()
	out := make([]string, 0, len(dns))
	for _, d := range dns {
		out = append(out, d.String())
	}
	return out
}

func (r *Runtime) suffixList() directory.SuffixList {
	all := r.managedSuffixStrings()
	primary := ""
	if len(all) > 0 {
		primary = all[0]
	}
	var extra []string
	if len(all) > 1 {
		extra = append([]string(nil), all[1:]...)
	}
	return directory.SuffixList{Primary: primary, Additional: extra, All: all}
}

func (r *Runtime) ManagedSuffixes() directory.SuffixList { return r.suffixList() }

func (r *Runtime) parseManagedDN(raw, path string) (config.DN, error) {
	d, err := config.ParseDN(strings.TrimSpace(raw))
	if err != nil {
		return config.DN{}, cfgErr(path, "invalid_dn", "DN is not valid")
	}
	if !config.UnderAny(d, r.managedSuffixDNs()) {
		return config.DN{}, directory.Error(path, directory.FieldForbidden, "DN is outside configured managed suffixes")
	}
	return d, nil
}

func (r *Runtime) requireParent(ctx context.Context, c *ldapclient.Conn, child config.DN) error {
	parent, ok := child.Parent()
	if !ok {
		return cfgErr("dn", "parent_missing", "entry parent is missing")
	}
	size, seconds := r.searchLimits()
	ok, err := existsConn(ctx, c, parent.String(), size, seconds)
	if err != nil {
		return err
	}
	if !ok {
		return directory.Error("dn", "parent_missing", "entry parent does not exist")
	}
	return nil
}

func (r *Runtime) protectedDN(dn string) bool {
	for _, p := range []string{r.cfg.Suffix, r.cfg.PeopleDN, r.cfg.GroupsDN, r.cfg.RuntimeDN, r.cfg.MarkerDN} {
		if p != "" && sameDN(dn, p) {
			return true
		}
	}
	for _, extra := range r.cfg.AdditionalSuffixes {
		if sameDN(dn, extra) {
			return true
		}
	}
	return false
}

func (r *Runtime) placeUserDN(spec directory.UserSpec) (string, error) {
	uid := spec.UID
	if uid == "" {
		uid = spec.ID
	}
	if strings.TrimSpace(spec.DN) != "" {
		d, err := r.parseManagedDN(spec.DN, "dn")
		if err != nil {
			return "", err
		}
		return d.String(), nil
	}
	if strings.TrimSpace(spec.ParentDN) != "" {
		parent, err := r.parseManagedDN(spec.ParentDN, "parentDN")
		if err != nil {
			return "", err
		}
		rdn, err := config.BuildRDN("uid", uid)
		if err != nil {
			return "", cfgErr("uid", "invalid_rdn", "cannot build user RDN")
		}
		return rdn + "," + parent.String(), nil
	}
	return r.userDN(uid)
}

func (r *Runtime) placeGroupDN(spec directory.GroupSpec) (string, error) {
	if strings.TrimSpace(spec.DN) != "" {
		d, err := r.parseManagedDN(spec.DN, "dn")
		if err != nil {
			return "", err
		}
		return d.String(), nil
	}
	if strings.TrimSpace(spec.ParentDN) != "" {
		parent, err := r.parseManagedDN(spec.ParentDN, "parentDN")
		if err != nil {
			return "", err
		}
		rdn, err := config.BuildRDN("cn", spec.ID)
		if err != nil {
			return "", cfgErr("id", "invalid_rdn", "cannot build group RDN")
		}
		return rdn + "," + parent.String(), nil
	}
	return r.groupDN(spec.ID)
}

func (r *Runtime) lookupUserDN(ctx context.Context, c *ldapclient.Conn, id string) (string, error) {
	if def, err := r.userDN(id); err == nil {
		size, seconds := r.searchLimits()
		if ok, e := existsConn(ctx, c, def, size, seconds); e != nil {
			return "", e
		} else if ok {
			return def, nil
		}
	}
	return r.searchAttrDN(ctx, c, "uid", id, "(&(objectClass=inetOrgPerson)(uid="+ldapclient.EscapeFilter(id)+"))")
}

func (r *Runtime) lookupGroupDN(ctx context.Context, c *ldapclient.Conn, id string) (string, error) {
	if def, err := r.groupDN(id); err == nil {
		size, seconds := r.searchLimits()
		if ok, e := existsConn(ctx, c, def, size, seconds); e != nil {
			return "", e
		} else if ok {
			return def, nil
		}
	}
	return r.searchAttrDN(ctx, c, "cn", id, "(&(objectClass=groupOfNames)(cn="+ldapclient.EscapeFilter(id)+"))")
}

func (r *Runtime) searchAttrDN(ctx context.Context, c *ldapclient.Conn, path, id, filter string) (string, error) {
	size, seconds := r.searchLimits()
	for _, base := range r.managedSuffixStrings() {
		res, err := c.Search(ctx, &ldap.SearchRequest{
			BaseDN:       base,
			Scope:        ldap.ScopeWholeSubtree,
			DerefAliases: ldap.NeverDerefAliases,
			SizeLimit:    2,
			TimeLimit:    seconds,
			Filter:       filter,
			Attributes:   []string{"1.1"},
		})
		if err != nil {
			if fieldOf(err) == directory.FieldNotFound {
				continue
			}
			return "", err
		}
		if len(res.Entries) == 1 {
			return res.Entries[0].DN, nil
		}
		if len(res.Entries) > 1 {
			return "", cfgErr(path, "conflict", "multiple entries match this id")
		}
		_ = size
	}
	return "", directory.Error(path, directory.FieldNotFound, "directory entry not found")
}
