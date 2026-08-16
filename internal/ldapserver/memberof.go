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
// entries that gain memberOf (ADR-0009 decision 20). Leftover nsmemberof
// after the last membership is retracted is retained to match 389 (D26);
// the class MAY memberOf, so an empty leftover stays schema-legal.
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
	nested bool
}

var _ Plugin = (*MemberOfPlugin)(nil)

// NewMemberOfPlugin returns the plugin scoped to suffix. nestedGroups must
// match compiled spec.directory.nestedGroups.
func NewMemberOfPlugin(suffix string, nestedGroups bool) (*MemberOfPlugin, error) {
	d, err := config.ParseDN(suffix)
	if err != nil {
		return nil, fmt.Errorf("ldapserver: memberof: invalid suffix: %w", err)
	}
	return &MemberOfPlugin{suffix: d, nested: nestedGroups}, nil
}

// Name implements Plugin.
func (p *MemberOfPlugin) Name() string { return "memberof" }

// inScope reports whether d is the managed suffix or beneath it.
func (p *MemberOfPlugin) inScope(d config.DN) bool {
	return d.Equal(p.suffix) || d.IsDescendantOf(p.suffix)
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
// memberOf values are removed and missing ones added. Leftover nsmemberof
// after the computed set becomes empty is retained (D26).
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

	// Reverse reachability via the shared group-graph walker: from the
	// member up through groups that list it. With nesting, listing a
	// reached group extends the walk; without, only the member's direct
	// groups count. The walker's seen set bounds cycles.
	expected := map[string]string{} // folded group key → canonical group DN
	if _, err := walkGroupFrontier(member.FoldedKey(), p.nested, 0,
		func(key string) ([]string, error) {
			var next []string
			for _, g := range idx.byMember[key] {
				gd, err := config.ParseDN(g.DN)
				if err != nil {
					continue
				}
				next = append(next, gd.FoldedKey())
			}
			return next, nil
		},
		func(key string) bool {
			g := idx.groups[key]
			if g == nil {
				return false
			}
			gd, err := config.ParseDN(g.DN)
			if err != nil {
				return false
			}
			expected[key] = gd.String()
			return false
		},
	); err != nil {
		return err
	}

	current := map[string]struct{}{}
	for _, v := range e.Values("memberOf") {
		if d, ok := dnFromValue(v, false); ok {
			current[d.FoldedKey()] = struct{}{}
		}
	}
	// D26: retain leftover nsmemberof when the computed set is empty.
	// Still add the class on grant. Skip the write when memberOf already
	// matches and no class needs to be added (avoids modifyTimestamp churn).
	needClass := len(expected) > 0 && !hasObjectClass(e, "nsmemberof")
	if sameDNSet(current, expected) && !needClass {
		return nil
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

// groupNestMaxDepth bounds ACI groupdn nesting (D22). MemberOf uses 0
// (unlimited, seen-set only): its walk is a suffix-scoped recompute, not
// an authorization check. Exceeding the ACI cap denies; the walk never
// continues unbounded.
const groupNestMaxDepth = 8

// walkGroupFrontier is the shared group-graph BFS used by MemberOf
// (reverse: who contains this member) and ACI groupdn (forward: does this
// group contain the user). start is the folded seed key. neighbors returns
// adjacent folded keys. visit is called once per newly seen neighbor (not
// start); returning true stops the walk.
//
// When nested is false, only start's immediate neighbors are visited.
// When nested is true, the walk continues through those neighbors. Cycles
// are skipped via a seen set of folded keys.
//
// maxDepth <= 0 means unlimited. Otherwise a hop that would exceed
// maxDepth stops the walk and returns exceeded=true (caller denies).
func walkGroupFrontier(
	start string,
	nested bool,
	maxDepth int,
	neighbors func(key string) ([]string, error),
	visit func(key string) (stop bool),
) (exceeded bool, err error) {
	seen := map[string]struct{}{start: {}}
	type item struct {
		key   string
		depth int
	}
	queue := []item{{key: start, depth: 0}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		adj, err := neighbors(cur.key)
		if err != nil {
			return false, err
		}
		for _, n := range adj {
			if _, dup := seen[n]; dup {
				continue
			}
			if visit(n) {
				return false, nil
			}
			seen[n] = struct{}{}
			if !nested {
				continue
			}
			nextDepth := cur.depth + 1
			if maxDepth > 0 && nextDepth > maxDepth {
				// Keep visiting siblings at this depth; deny only if
				// the walk ends without a match.
				exceeded = true
				continue
			}
			queue = append(queue, item{key: n, depth: nextDepth})
		}
	}
	return exceeded, nil
}
