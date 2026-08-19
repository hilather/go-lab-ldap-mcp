package ldapserver

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// memberof.go is the T-135 MemberOf write-path plugin: the native
// equivalent of the 389 MemberOf plugin (parity contract C7). Forward
// membership stays on the group (groupOfNames member / groupOfUniqueNames
// uniqueMember); this plugin maintains the derived, operational memberOf
// attribute on member entries inside the same store commit as the write
// that changed membership, and auto-adds the nsmemberof object class to
// entries that gain memberOf (ADR-0009 decision 20).
//
// Nested-group propagation follows the constructor flag, which cmd/labldapd
// threads from spec.directory.nestedGroups: with nesting off, a group listed
// as a member still earns its own memberOf (the direct membership is real),
// but propagation stops there; with nesting on, memberOf extends
// transitively up the group graph. 389's plugin always recurses; gating
// recursion on the scenario flag is recorded as a Delta candidate because
// the control plane rejects nested membership outright when the flag is off.
//
// Consistency model: instead of incrementally adding/removing single
// values, the plugin recomputes the affected members' memberOf sets from
// the post-write group graph. Multi-path nesting (a user reachable through
// two groups) and group rename/delete therefore stay correct without
// special cases. Only entries whose computed set differs from the stored
// one are rewritten, so unrelated entries are never touched.
//
// The plugin never panics on adversarial content: unparseable member values
// are skipped, members that do not resolve to an in-suffix entry are
// ignored, and nothing outside the managed suffix is read or written.

// MemberOfPlugin maintains memberOf for members of changed groups.
type MemberOfPlugin struct {
	suffix config.DN
	extra  []config.DN
	nested bool
}

var _ Plugin = (*MemberOfPlugin)(nil)

// NewMemberOfPlugin returns the plugin scoped to suffix. nestedGroups must
// match compiled spec.directory.nestedGroups.
func NewMemberOfPlugin(suffix string, nestedGroups bool, additional ...string) (*MemberOfPlugin, error) {
	d, err := config.ParseDN(suffix)
	if err != nil {
		return nil, fmt.Errorf("ldapserver: memberof: invalid suffix: %w", err)
	}
	p := &MemberOfPlugin{suffix: d, nested: nestedGroups, extra: nil}
	for _, raw := range additional {
		got, err := config.ParseDN(raw)
		if err != nil {
			return nil, fmt.Errorf("ldapserver: memberof: invalid additional suffix: %w", err)
		}
		p.extra = append(p.extra, got)
	}
	return p, nil
}

// Name implements Plugin.
func (p *MemberOfPlugin) Name() string { return "memberof" }

// inScope reports whether d is the managed suffix or beneath it.
func (p *MemberOfPlugin) inScope(d config.DN) bool {
	if d.Equal(p.suffix) || d.IsDescendantOf(p.suffix) {
		return true
	}
	return config.UnderAny(d, p.extra)
}

// AfterWrite implements Plugin. It runs inside the write's Update
// transaction, so memberOf commits (or rolls back) with its cause (C7).
func (p *MemberOfPlugin) AfterWrite(ctx context.Context, tx UpdateTx, ev WriteEvent) error {
	// Seeds are the direct members of the group side of the event, before
	// and after: every entry whose derived memberOf could have changed.
	seeds := map[string]config.DN{}
	seed := func(e *Entry) {
		if e == nil || !isGroupEntry(e) {
			return
		}
		for _, m := range memberDNs(e) {
			if p.inScope(m) {
				seeds[m.FoldedKey()] = m
			}
		}
	}
	switch ev.Op {
	case WriteAdd:
		seed(ev.After)
	case WriteModify, WriteRename:
		// A group rename changes the DN stored in memberOf values; the
		// recompute below rewrites them from the post-rename graph.
		seed(ev.Before)
		seed(ev.After)
	case WriteDelete:
		// A deleted group's members lose its memberOf; a deleted user needs
		// nothing (its memberOf dies with the entry; referint repairs the
		// forward references).
		seed(ev.Before)
	}
	if len(seeds) == 0 {
		return nil
	}
	idx, err := p.indexGroups(ctx, tx)
	if err != nil {
		return err
	}
	if p.nested {
		// A seed that is itself a group pulls its whole membership into the
		// affected set: outer membership changed, so transitive memberOf of
		// the inner group's members changed with it.
		queue := make([]string, 0, len(seeds))
		for k := range seeds {
			queue = append(queue, k)
		}
		for len(queue) > 0 {
			key := queue[0]
			queue = queue[1:]
			g, ok := idx.groups[key]
			if !ok {
				continue
			}
			for _, m := range memberDNs(g) {
				mk := m.FoldedKey()
				if _, seen := seeds[mk]; !seen && p.inScope(m) {
					seeds[mk] = m
					queue = append(queue, mk)
				}
			}
		}
	}
	for _, d := range seeds {
		if err := p.recompute(ctx, tx, idx, d); err != nil {
			return err
		}
	}
	return nil
}

// Fixup recomputes memberOf for every entry in the managed suffix: the
// native equivalent of the 389 memberOf fixup task, used by bootstrap and
// soft reset after data was applied through paths that bypass the write
// plugins (C7). It is suffix-scoped and converges entries exactly: stale
// memberOf values and nsmemberof classes are removed, missing ones added.
func (p *MemberOfPlugin) Fixup(ctx context.Context, store Store) error {
	return store.Update(ctx, func(tx UpdateTx) error {
		idx, err := p.indexGroups(ctx, tx)
		if err != nil {
			return err
		}
		entries, err := tx.Subtree(ctx, p.suffix)
		if errors.Is(err, ErrNoSuchObject) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("ldapserver: memberof: fixup scan: %w", err)
		}
		for _, e := range entries {
			d, err := config.ParseDN(e.DN)
			if err != nil {
				continue // store invariant violation; skip rather than abort the sweep
			}
			if err := p.recompute(ctx, tx, idx, d); err != nil {
				return err
			}
		}
		return nil
	})
}

// groupIndex is a snapshot of the suffix's group graph: groups by folded
// DN, and the reverse edge map from a folded member DN to the groups that
// directly list it.
type groupIndex struct {
	groups   map[string]*Entry
	byMember map[string][]*Entry
}

// indexGroups scans the managed suffix once and builds the membership
// graph. A missing suffix yields an empty index (nothing to maintain).
func (p *MemberOfPlugin) indexGroups(ctx context.Context, tx ReadTx) (*groupIndex, error) {
	idx := &groupIndex{groups: map[string]*Entry{}, byMember: map[string][]*Entry{}}
	entries, err := tx.Subtree(ctx, p.suffix)
	if errors.Is(err, ErrNoSuchObject) {
		return idx, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ldapserver: memberof: list suffix: %w", err)
	}
	for _, e := range entries {
		if !isGroupEntry(e) {
			continue
		}
		d, err := config.ParseDN(e.DN)
		if err != nil {
			continue
		}
		idx.groups[d.FoldedKey()] = e
		for _, m := range memberDNs(e) {
			idx.byMember[m.FoldedKey()] = append(idx.byMember[m.FoldedKey()], e)
		}
	}
	return idx, nil
}

// recompute converges one entry's memberOf to the set of groups that list
// it (transitively when nested). Missing entries are skipped: a dangling
// forward reference is the referint plugin's concern, not an error here.
func (p *MemberOfPlugin) recompute(ctx context.Context, tx UpdateTx, idx *groupIndex, member config.DN) error {
	e, err := tx.Entry(ctx, member)
	if errors.Is(err, ErrNoSuchObject) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("ldapserver: memberof: load member: %w", err)
	}

	// Reverse reachability: walk from the member up through groups that
	// list it. With nesting, listing a reached group extends the walk;
	// without, only the member's direct groups count. The seen set bounds
	// the walk, so membership cycles terminate.
	expected := map[string]string{} // folded group key → canonical group DN
	seen := map[string]struct{}{member.FoldedKey(): {}}
	frontier := []string{member.FoldedKey()}
	for len(frontier) > 0 {
		key := frontier[0]
		frontier = frontier[1:]
		for _, g := range idx.byMember[key] {
			gd, err := config.ParseDN(g.DN)
			if err != nil {
				continue
			}
			gk := gd.FoldedKey()
			if _, dup := expected[gk]; dup {
				continue
			}
			expected[gk] = gd.String()
			if p.nested {
				if _, done := seen[gk]; !done {
					seen[gk] = struct{}{}
					frontier = append(frontier, gk)
				}
			}
		}
	}

	current := map[string]struct{}{}
	for _, v := range e.Values("memberOf") {
		if d, ok := dnFromValue(v, false); ok {
			current[d.FoldedKey()] = struct{}{}
		}
	}
	if sameDNSet(current, expected) && hasObjectClass(e, "nsmemberof") == (len(expected) > 0) {
		return nil // already converged: no write, no modifyTimestamp churn
	}
	keys := make([]string, 0, len(expected))
	for k := range expected {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	values := make([][]byte, 0, len(keys))
	for _, k := range keys {
		values = append(values, []byte(expected[k]))
	}
	setAttr(e, "memberOf", values...)
	if len(values) > 0 {
		ensureObjectClass(e, "nsmemberof")
	} else {
		removeObjectClass(e, "nsmemberof")
	}
	if err := tx.Replace(ctx, e); err != nil {
		return fmt.Errorf("ldapserver: memberof: update member: %w", err)
	}
	return nil
}

// sameDNSet reports whether the folded-key sets current and expected match.
func sameDNSet(current map[string]struct{}, expected map[string]string) bool {
	if len(current) != len(expected) {
		return false
	}
	for k := range current {
		if _, ok := expected[k]; !ok {
			return false
		}
	}
	return true
}

// isGroupEntry reports whether e carries a group object class the plugin
// manages (groupOfNames / groupOfUniqueNames, C5).
func isGroupEntry(e *Entry) bool {
	return hasObjectClass(e, "groupOfNames") || hasObjectClass(e, "groupOfUniqueNames")
}

// memberDNs parses the distinct member and uniqueMember values of a group
// entry. Malformed values are skipped (never a panic, never an error); the
// RFC 4519 '#' bit-string suffix on uniqueMember values is stripped.
func memberDNs(e *Entry) []config.DN {
	seen := map[string]struct{}{}
	var out []config.DN
	for _, attr := range []string{"member", "uniqueMember"} {
		for _, v := range e.Values(attr) {
			d, ok := dnFromValue(v, attr == "uniqueMember")
			if !ok {
				continue
			}
			k := d.FoldedKey()
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			out = append(out, d)
		}
	}
	return out
}

// setAttr replaces the named attribute's values, creating the attribute or
// removing it when values is empty. Shared by the write-path plugins and
// the operational-attribute maintenance (T-137).
func setAttr(e *Entry, name string, values ...[]byte) {
	idx := attrIndex(e, name)
	if len(values) == 0 {
		if idx >= 0 {
			e.Attributes = append(e.Attributes[:idx], e.Attributes[idx+1:]...)
		}
		return
	}
	if idx < 0 {
		e.Attributes = append(e.Attributes, Attribute{Name: name, Values: values})
		return
	}
	e.Attributes[idx].Values = values
}

// hasObjectClass reports whether e carries the named object class.
func hasObjectClass(e *Entry, name string) bool {
	for _, v := range e.Values("objectClass") {
		if strings.EqualFold(string(v), name) {
			return true
		}
	}
	return false
}

// ensureObjectClass appends the named object class unless already present.
func ensureObjectClass(e *Entry, name string) {
	if hasObjectClass(e, name) {
		return
	}
	idx := attrIndex(e, "objectClass")
	if idx < 0 {
		e.Attributes = append(e.Attributes, Attribute{Name: "objectClass", Values: [][]byte{[]byte(name)}})
		return
	}
	e.Attributes[idx].Values = append(e.Attributes[idx].Values, []byte(name))
}

// removeObjectClass drops the named object class if present.
func removeObjectClass(e *Entry, name string) {
	idx := attrIndex(e, "objectClass")
	if idx < 0 {
		return
	}
	kept := e.Attributes[idx].Values[:0]
	for _, v := range e.Attributes[idx].Values {
		if !strings.EqualFold(string(v), name) {
			kept = append(kept, v)
		}
	}
	e.Attributes[idx].Values = kept
}
