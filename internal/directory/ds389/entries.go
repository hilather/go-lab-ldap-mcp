package ds389

import (
	"context"
	"slices"
	"sort"
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
			if e := applyEntryChange(mod, ch, live); e != nil {
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
	if r.managedSuffixIndex(from) != r.managedSuffixIndex(to) {
		// 389 answers affectsMultipleDSAs for a move between backends and
		// native matches it (oracle probe 34; resolved CAND-39); refuse it
		// up front with a stable field error on both engines.
		return directory.DirectoryEntry{}, directory.Error("newDN", directory.FieldForbidden, "moves across managed suffixes are not supported")
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
		// The stored DN is the source so a rename keeps the stored parent
		// spelling (both engines take a rename's parent spelling from the
		// request DN; resolved CAND-30).
		req := ldap.NewModifyDNRequest(live.DN, newRDN, move.DeleteOld, newParent.String())
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

func applyEntryChange(mod *ldap.ModifyRequest, ch directory.EntryChange, live *ldap.Entry) error {
	name := strings.TrimSpace(ch.Name)
	if name == "" {
		return cfgErr("changes.name", "required", "attribute name is required")
	}
	if directory.ForbiddenEntryAttr(name) || config.CanonicalAttrType(name) == "objectclass" {
		return cfgErr("changes.name", "forbidden_attribute", "attribute is not allowed")
	}
	// Replace and add send the primary descriptor (gn as givenName). Delete
	// of a second descriptor goes through aliasDeleteName (parity delta
	// D35).
	switch strings.ToLower(strings.TrimSpace(ch.Op)) {
	case directory.EntryModReplace:
		mod.Replace(config.PrimaryAttrDescription(name), ch.Values)
	case directory.EntryModAdd:
		if len(ch.Values) == 0 {
			return cfgErr("changes.values", "required", "add requires values")
		}
		mod.Add(config.PrimaryAttrDescription(name), ch.Values)
	case directory.EntryModDelete:
		mod.Delete(aliasDeleteName(name, ch.Values, live), ch.Values)
	default:
		return cfgErr("changes.op", "invalid", "change op must be replace, add, or delete")
	}
	return nil
}

// aliasDeleteName picks the attribute description an entry-update delete
// sends (parity delta D35). Names that are not second descriptors are sent
// as written. For an alias spelling:
//  1. a stored row under the same alias and option set (a native legacy
//     attribute written by direct LDAP, D17) is deleted under its stored
//     name, so the primary attribute is never touched; a value delete
//     takes this branch only when that row holds every named value. 389
//     returns primary names and never takes this branch;
//  2. an optioned spelling (rfc822Mailbox;lang-en) otherwise deletes the
//     optioned primary description that add and replace wrote for it
//     (mail;lang-en), using the stored name when the entry holds one with
//     the same option set (native matches names literally, options
//     included); bare mail is not addressed;
//  3. a bare alias keeps the client's spelling: native answers
//     noSuchAttribute and never touches the primary value, 389 resolves the
//     alias itself.
func aliasDeleteName(name string, values []string, live *ldap.Entry) string {
	if _, ok := config.AttrAliasType(name); !ok {
		return name
	}
	want := literalAttrKey(name)
	if stored, ok := storedAttrName(live, func(n string) bool { return literalAttrKey(n) == want }); ok &&
		(len(values) == 0 || holdsValues(live, stored, values)) {
		return stored
	}
	if !strings.Contains(name, ";") {
		return name
	}
	key := config.AttrDuplicateKey(name)
	if stored, ok := storedAttrName(live, func(n string) bool {
		_, alias := config.AttrAliasType(n)
		return !alias && config.AttrDuplicateKey(n) == key
	}); ok {
		return stored
	}
	return config.PrimaryAttrDescription(name)
}

// literalAttrKey is the lowercase attribute description with options
// sorted, without resolving descriptor aliases (rfc822Mailbox stays
// rfc822mailbox).
func literalAttrKey(name string) string {
	parts := strings.Split(config.CanonicalAttr(name), ";")
	opts := parts[1:]
	sort.Strings(opts)
	return strings.Join(append([]string{parts[0]}, opts...), ";")
}

// holdsValues reports whether live's attribute stored under name holds
// every value in values (case-insensitive, as mail and givenName match).
func holdsValues(live *ldap.Entry, name string, values []string) bool {
	for _, a := range live.Attributes {
		if a.Name != name {
			continue
		}
		for _, v := range values {
			if !slices.ContainsFunc(a.Values, func(s string) bool { return strings.EqualFold(s, v) }) {
				return false
			}
		}
		return true
	}
	return false
}

// storedAttrName returns the first attribute name in live that holds
// values and satisfies match.
func storedAttrName(live *ldap.Entry, match func(string) bool) (string, bool) {
	if live == nil {
		return "", false
	}
	for _, a := range live.Attributes {
		if len(a.Values) > 0 && match(a.Name) {
			return a.Name, true
		}
	}
	return "", false
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
	// Planned names are dropped in every spelling (option, OID, descriptor
	// alias); the forbidden check runs first so a protected alias is still an
	// error. Extras de-duplicate on AttrDuplicateKey, keeping the first name
	// in case-insensitive order (entry create drops duplicates; the user API
	// rejects them with duplicate_attribute), and are sent under the primary
	// descriptor (rfc822Mailbox as mail).
	planned := map[string]struct{}{"objectclass": {}, strings.ToLower(attr): {}, "uid": {}, "cn": {}, "sn": {}, "dc": {}, "ou": {}}
	seen := map[string]struct{}{}
	for _, name := range duplicateOrderNames(extra) {
		val := extra[name]
		if directory.ForbiddenEntryAttr(name) {
			return nil, cfgErr("attributes."+name, "forbidden_attribute", "attribute is not allowed")
		}
		if _, ok := planned[config.CanonicalAttrType(name)]; ok {
			continue
		}
		key := config.AttrDuplicateKey(name)
		if _, ok := seen[key]; ok {
			continue
		}
		if strings.TrimSpace(val) == "" {
			continue
		}
		out = append(out, ldap.Attribute{Type: config.PrimaryAttrDescription(name), Vals: []string{val}})
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

// duplicateOrderNames lists m's keys in duplicate-detection order
// (config.SortAttrNamesForDuplicates); sortedNames stays byte-ordered for
// its other callers.
func duplicateOrderNames(m map[string]string) []string {
	out := sortedNames(m)
	config.SortAttrNamesForDuplicates(out)
	return out
}

func sortedNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
