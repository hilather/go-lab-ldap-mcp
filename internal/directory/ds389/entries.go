package ds389

import (
	"context"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ldapclient"
)

var _ directory.EntryRepository = (*Runtime)(nil)

func (r *Runtime) CreateEntry(ctx context.Context, spec directory.EntrySpec) (directory.DirectoryEntry, error) {
	class, err := directory.PrimaryStructuralClass(spec.ObjectClasses)
	if err != nil {
		return directory.DirectoryEntry{}, err
	}
	dn, err := r.parseManagedDN(spec.DN, "dn")
	if err != nil {
		return directory.DirectoryEntry{}, err
	}
	if r.protectedDN(dn.String()) {
		return directory.DirectoryEntry{}, directory.Error("dn", directory.FieldForbidden, "protected directory entry cannot be created")
	}
	if err := checkRDNForClass(dn, class); err != nil {
		return directory.DirectoryEntry{}, err
	}
	attrs, err := entryAddAttrs(dn, class, spec.Attributes)
	if err != nil {
		return directory.DirectoryEntry{}, err
	}
	add := ldap.NewAddRequest(dn.String(), nil)
	for _, a := range attrs {
		add.Attribute(a.Type, a.Vals)
	}
	size, seconds := r.searchLimits()
	var out directory.DirectoryEntry
	err = r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		if e := r.requireParent(ctx, c, dn); e != nil {
			return e
		}
		if e := c.Add(ctx, add); e != nil {
			return e
		}
		ent, e := searchBaseConn(ctx, c, dn.String(), entryReadAttrs(), size, seconds)
		if e != nil {
			return e
		}
		out = directoryEntryFromLDAP(ent)
		return nil
	})
	return out, err
}

func (r *Runtime) UpdateEntry(ctx context.Context, patch directory.EntryPatch) (directory.DirectoryEntry, error) {
	dn, err := r.parseManagedDN(patch.DN, "dn")
	if err != nil {
		return directory.DirectoryEntry{}, err
	}
	if r.protectedDN(dn.String()) {
		return directory.DirectoryEntry{}, directory.Error("dn", directory.FieldForbidden, "protected directory entry cannot be modified")
	}
	if err := requireRevision(patch.Revision); err != nil {
		return directory.DirectoryEntry{}, err
	}
	if len(patch.Changes) == 0 {
		return directory.DirectoryEntry{}, cfgErr("changes", "required", "at least one change is required")
	}
	size, seconds := r.searchLimits()
	var out directory.DirectoryEntry
	err = r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		live, e := searchBaseConn(ctx, c, dn.String(), entryReadAttrs(), size, seconds)
		if e != nil {
			return e
		}
		cur := directoryEntryFromLDAP(live)
		if e := checkRev(cur.Revision, patch.Revision); e != nil {
			return e
		}
		mod := newModify(ctx, r, c, dn.String(), live)
		r.afterSearch(ctx, dn.String())
		for _, ch := range patch.Changes {
			if e := applyEntryChange(mod, ch); e != nil {
				return e
			}
		}
		if e := c.Modify(ctx, mod); e != nil {
			return e
		}
		ent, e := searchBaseConn(ctx, c, dn.String(), entryReadAttrs(), size, seconds)
		if e != nil {
			return e
		}
		out = directoryEntryFromLDAP(ent)
		return nil
	})
	return out, err
}

func (r *Runtime) DeleteEntry(ctx context.Context, del directory.EntryDelete) error {
	if !del.Confirm {
		return cfgErr("confirm", "required", "destructive delete requires confirm")
	}
	dn, err := r.parseManagedDN(del.DN, "dn")
	if err != nil {
		return err
	}
	if r.protectedDN(dn.String()) {
		return directory.Error("dn", directory.FieldForbidden, "protected directory entry cannot be deleted")
	}
	if err := requireRevision(del.Revision); err != nil {
		return err
	}
	size, seconds := r.searchLimits()
	return r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		live, e := searchBaseConn(ctx, c, dn.String(), entryReadAttrs(), size, seconds)
		if e != nil {
			return e
		}
		cur := directoryEntryFromLDAP(live)
		if e := checkRev(cur.Revision, del.Revision); e != nil {
			return e
		}
		children, e := r.listChildren(ctx, c, dn.String())
		if e != nil {
			return e
		}
		if len(children) > 0 && !del.Recursive {
			return directory.Error("dn", directory.FieldConstraint, "container is not empty")
		}
		if del.Recursive {
			if e := r.deleteDescendants(ctx, c, dn.String()); e != nil {
				return e
			}
		}
		r.afterSearch(ctx, dn.String())
		return c.Del(ctx, newDelete(ctx, r, c, dn.String(), live))
	})
}

func (r *Runtime) MoveEntry(ctx context.Context, move directory.EntryMove) (directory.DirectoryEntry, error) {
	from, err := r.parseManagedDN(move.DN, "dn")
	if err != nil {
		return directory.DirectoryEntry{}, err
	}
	to, err := r.parseManagedDN(move.NewDN, "newDN")
	if err != nil {
		return directory.DirectoryEntry{}, err
	}
	if r.protectedDN(from.String()) || r.protectedDN(to.String()) {
		return directory.DirectoryEntry{}, directory.Error("dn", directory.FieldForbidden, "protected directory entry cannot be moved")
	}
	if err := requireRevision(move.Revision); err != nil {
		return directory.DirectoryEntry{}, err
	}
	newParent, ok := to.Parent()
	if !ok {
		return directory.DirectoryEntry{}, cfgErr("newDN", "parent_missing", "new DN parent is missing")
	}
	leafAttr, leafVal, ok := to.Leaf()
	if !ok {
		return directory.DirectoryEntry{}, cfgErr("newDN", "invalid_dn", "new DN has no RDN")
	}
	newRDN := leafAttr + "=" + config.EscapeAttributeValue(leafVal)
	size, seconds := r.searchLimits()
	var out directory.DirectoryEntry
	err = r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		live, e := searchBaseConn(ctx, c, from.String(), entryReadAttrs(), size, seconds)
		if e != nil {
			return e
		}
		cur := directoryEntryFromLDAP(live)
		if e := checkRev(cur.Revision, move.Revision); e != nil {
			return e
		}
		if e := r.requireParent(ctx, c, to); e != nil {
			return e
		}
		req := ldap.NewModifyDNRequest(from.String(), newRDN, move.DeleteOld, newParent.String())
		if e := c.ModifyDN(ctx, req); e != nil {
			return e
		}
		ent, e := searchBaseConn(ctx, c, to.String(), entryReadAttrs(), size, seconds)
		if e != nil {
			return e
		}
		out = directoryEntryFromLDAP(ent)
		return nil
	})
	return out, err
}

func (r *Runtime) ListTree(ctx context.Context, q directory.TreeQuery) (directory.TreePage, error) {
	base := strings.TrimSpace(q.Base)
	if base == "" {
		base = r.cfg.Suffix
	}
	dn, err := r.parseManagedDN(base, "base")
	if err != nil {
		return directory.TreePage{}, err
	}
	page := r.pageSize(q.PageSize)
	queryKey := "tree|" + dn.String() + "|" + strconv.Itoa(page)
	cookie, err := r.decodePageCursor(q.Cursor, queryKey)
	if err != nil {
		return directory.TreePage{}, err
	}
	size, seconds := r.searchLimits()
	var out directory.TreePage
	out.Base = dn.String()
	err = r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		res, next, e := c.SearchPage(ctx, &ldap.SearchRequest{
			BaseDN:       dn.String(),
			Scope:        ldap.ScopeSingleLevel,
			DerefAliases: ldap.NeverDerefAliases,
			SizeLimit:    size,
			TimeLimit:    seconds,
			Filter:       "(objectClass=*)",
			Attributes:   []string{"objectClass", "hasSubordinates", "numSubordinates"},
		}, uint32(page), cookie)
		if e != nil {
			return e
		}
		for _, ent := range res.Entries {
			if ent == nil {
				continue
			}
			node := directory.TreeNode{
				DN:            ent.DN,
				ObjectClasses: sortCI(ent.GetAttributeValues("objectClass")),
				HasChildren:   hasChildren(ent),
			}
			if parsed, perr := config.ParseDN(ent.DN); perr == nil {
				attr, val, ok := parsed.Leaf()
				if ok {
					node.RDN = attr + "=" + config.EscapeAttributeValue(val)
				}
			}
			out.Nodes = append(out.Nodes, node)
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

func (r *Runtime) GetEntryMeta(ctx context.Context, raw string) (directory.DirectoryEntry, error) {
	dn, err := r.parseManagedDN(raw, "dn")
	if err != nil {
		return directory.DirectoryEntry{}, err
	}
	size, seconds := r.searchLimits()
	var out directory.DirectoryEntry
	err = r.pool.Do(ctx, func(c *ldapclient.Conn) error {
		ent, e := searchBaseConn(ctx, c, dn.String(), entryReadAttrs(), size, seconds)
		if e != nil {
			return e
		}
		out = directoryEntryFromLDAP(ent)
		return nil
	})
	return out, err
}

func (r *Runtime) listChildren(ctx context.Context, c *ldapclient.Conn, base string) ([]string, error) {
	_, seconds := r.searchLimits()
	res, err := c.Search(ctx, &ldap.SearchRequest{
		BaseDN:       base,
		Scope:        ldap.ScopeSingleLevel,
		DerefAliases: ldap.NeverDerefAliases,
		SizeLimit:    r.cfg.SearchSizeLimit,
		TimeLimit:    seconds,
		Filter:       "(objectClass=*)",
		Attributes:   []string{"1.1"},
	})
	if err != nil {
		if fieldOf(err) == directory.FieldNotFound {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range res.Entries {
		if e != nil && e.DN != "" {
			out = append(out, e.DN)
		}
	}
	return out, nil
}

func (r *Runtime) deleteDescendants(ctx context.Context, c *ldapclient.Conn, base string) error {
	children, err := r.listChildren(ctx, c, base)
	if err != nil {
		return err
	}
	for i := len(children) - 1; i >= 0; i-- {
		if r.protectedDN(children[i]) {
			return directory.Error("dn", directory.FieldForbidden, "protected directory entry cannot be deleted")
		}
		if err := r.deleteDescendants(ctx, c, children[i]); err != nil {
			return err
		}
		if err := c.Del(ctx, ldap.NewDelRequest(children[i], nil)); err != nil && fieldOf(err) != directory.FieldNotFound {
			return err
		}
	}
	return nil
}

func requireRevision(rev directory.Revision) error {
	if strings.TrimSpace(string(rev)) == "" {
		return cfgErr("revision", "required", "revision is required")
	}
	return nil
}

func applyEntryChange(mod *ldap.ModifyRequest, ch directory.EntryChange) error {
	name := strings.TrimSpace(ch.Name)
	if name == "" {
		return cfgErr("changes.name", "required", "attribute name is required")
	}
	if directory.ForbiddenEntryAttr(name) || config.CanonicalAttr(name) == "objectclass" {
		return cfgErr("changes.name", "forbidden_attribute", "attribute is not allowed")
	}
	switch strings.ToLower(strings.TrimSpace(ch.Op)) {
	case directory.EntryModReplace:
		mod.Replace(name, ch.Values)
	case directory.EntryModAdd:
		if len(ch.Values) == 0 {
			return cfgErr("changes.values", "required", "add requires values")
		}
		mod.Add(name, ch.Values)
	case directory.EntryModDelete:
		mod.Delete(name, ch.Values)
	default:
		return cfgErr("changes.op", "invalid", "change op must be replace, add, or delete")
	}
	return nil
}

func checkRDNForClass(dn config.DN, class string) error {
	attr, _, ok := dn.Leaf()
	if !ok {
		return cfgErr("dn", "invalid_dn", "DN has no RDN")
	}
	want := directory.LeafAttrForClass(class)
	switch class {
	case directory.ClassInetOrgPerson:
		if attr != "uid" && attr != "cn" {
			return cfgErr("dn", "invalid_rdn", "user DN RDN must be uid or cn")
		}
	case directory.ClassGroupOfNames:
		if attr != "cn" {
			return cfgErr("dn", "invalid_rdn", "group DN RDN must be cn")
		}
	default:
		if want != "" && attr != want {
			return cfgErr("dn", "invalid_rdn", "DN RDN does not match object class")
		}
	}
	return nil
}

func entryAddAttrs(dn config.DN, class string, extra map[string]string) ([]ldap.Attribute, error) {
	attr, value, ok := dn.Leaf()
	if !ok {
		return nil, cfgErr("dn", "invalid_dn", "DN has no RDN")
	}
	out := []ldap.Attribute{}
	switch class {
	case directory.ClassDomain:
		out = append(out,
			ldap.Attribute{Type: "objectClass", Vals: []string{"top", "domain"}},
			ldap.Attribute{Type: "dc", Vals: []string{value}},
		)
	case directory.ClassOrganizationalUnit:
		out = append(out,
			ldap.Attribute{Type: "objectClass", Vals: []string{"top", "organizationalUnit"}},
			ldap.Attribute{Type: "ou", Vals: []string{value}},
		)
	case directory.ClassInetOrgPerson:
		cn := attrMapValue(extra, "cn")
		if cn == "" {
			cn = value
		}
		sn := attrMapValue(extra, "sn")
		if sn == "" {
			sn = value
		}
		uid := attrMapValue(extra, "uid")
		if uid == "" {
			if attr == "uid" {
				uid = value
			} else {
				uid = value
			}
		}
		out = append(out,
			ldap.Attribute{Type: "objectClass", Vals: config.RequiredUserObjectClasses()},
			ldap.Attribute{Type: "uid", Vals: []string{uid}},
			ldap.Attribute{Type: "cn", Vals: []string{cn}},
			ldap.Attribute{Type: "sn", Vals: []string{sn}},
		)
	case directory.ClassGroupOfNames:
		return nil, cfgErr("objectClasses", "empty_group", "create groups through the group API so OD-018 is enforced")
	default:
		return nil, directory.Error("objectClasses", directory.FieldForbidden, "object class is not allowlisted")
	}
	seen := map[string]struct{}{"objectclass": {}, attr: {}, "uid": {}, "cn": {}, "sn": {}, "dc": {}, "ou": {}}
	for name, val := range extra {
		key := config.CanonicalAttr(name)
		if _, ok := seen[key]; ok {
			continue
		}
		if directory.ForbiddenEntryAttr(name) {
			return nil, cfgErr("attributes."+name, "forbidden_attribute", "attribute is not allowed")
		}
		if strings.TrimSpace(val) == "" {
			continue
		}
		out = append(out, ldap.Attribute{Type: name, Vals: []string{val}})
		seen[key] = struct{}{}
	}
	return out, nil
}

func entryReadAttrs() []string {
	return []string{"*", "objectClass"}
}

func directoryEntryFromLDAP(e *ldap.Entry) directory.DirectoryEntry {
	if e == nil {
		return directory.DirectoryEntry{}
	}
	var attrs []directory.AttrKV
	for _, a := range e.Attributes {
		name := config.CanonicalAttr(a.Name)
		if skipReturnedAttr(name) || name == "objectclass" {
			continue
		}
		for _, v := range a.Values {
			attrs = append(attrs, directory.AttrKV{Name: name, Value: v})
		}
	}
	out := directory.DirectoryEntry{
		DN:            e.DN,
		ObjectClasses: sortCI(e.GetAttributeValues("objectClass")),
		Attributes:    sortAttrKV(attrs),
	}
	out.Revision = directory.RevisionOfEntry(out)
	return out
}

func hasChildren(e *ldap.Entry) bool {
	if e == nil {
		return false
	}
	if v := strings.ToLower(e.GetAttributeValue("hasSubordinates")); v == "true" {
		return true
	}
	if n := e.GetAttributeValue("numSubordinates"); n != "" && n != "0" {
		return true
	}
	return false
}
