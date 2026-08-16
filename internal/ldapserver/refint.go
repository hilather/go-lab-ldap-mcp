package ldapserver

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// refint.go is the T-136 referential integrity plugin: the native
// equivalent of 389's "referential integrity postoperation" with update
// delay 0 (parity contract C7). Deleting an entry removes its DN from the
// member/uniqueMember attributes of every group in the managed suffix, in
// the same store commit as the delete.
//
// Empty-group handling matches the 389-observed behavior recorded in
// test/integration/dirsrv/plugins_test.go: the reference is removed even
// when it is the group's last member, leaving a groupOfNames with no member
// attribute. The schema MUST gate (T-132) stops *clients* from emptying a
// group through Add/Modify, but plugin-internal repairs bypass it exactly
// like 389's internal postoperation — the group persists, member-less.
// Recorded as a Delta candidate for the T-147 oracle to confirm.
//
// Rename (modrdn) support mirrors 389's plugin: member/uniqueMember values
// naming the old DN are rewritten to the new DN in the same commit. When
// both plugins are registered, run referint before memberof in
// Options.Plugins so memberOf recompute sees the repaired forward
// references.
//
// Scope: repairs touch only group entries inside the managed suffix.
// Deletes and renames of entries outside the suffix are ignored entirely,
// and member values pointing outside the suffix are never rewritten —
// there are no foreign entries in v1, so out-of-suffix references cannot be
// verified and are left as data.

// RefIntPlugin repairs forward membership references on delete and rename.
type RefIntPlugin struct {
	suffix config.DN
}

var _ Plugin = (*RefIntPlugin)(nil)

// NewRefIntPlugin returns the plugin scoped to suffix.
func NewRefIntPlugin(suffix string) (*RefIntPlugin, error) {
	d, err := config.ParseDN(suffix)
	if err != nil {
		return nil, fmt.Errorf("ldapserver: referint: invalid suffix: %w", err)
	}
	return &RefIntPlugin{suffix: d}, nil
}

// Name implements Plugin.
func (p *RefIntPlugin) Name() string { return "referint" }

// inScope reports whether d is the managed suffix or beneath it.
func (p *RefIntPlugin) inScope(d config.DN) bool {
	return d.Equal(p.suffix) || d.IsDescendantOf(p.suffix)
}

// AfterWrite implements Plugin.
func (p *RefIntPlugin) AfterWrite(ctx context.Context, tx UpdateTx, ev WriteEvent) error {
	switch ev.Op {
	case WriteDelete:
		if ev.Before == nil {
			return nil
		}
		gone, err := config.ParseDN(ev.Before.DN)
		if err != nil || !p.inScope(gone) {
			return nil
		}
		return p.repair(ctx, tx, func(g *Entry) bool {
			return filterMemberValues(g, func(v []byte, uniqueMember bool) bool {
				d, ok := dnFromValue(v, uniqueMember)
				return !ok || !d.EqualFold(gone)
			})
		})
	case WriteRename:
		if ev.Before == nil || ev.After == nil {
			return nil
		}
		from, err1 := config.ParseDN(ev.Before.DN)
		to, err2 := config.ParseDN(ev.After.DN)
		if err1 != nil || err2 != nil || !p.inScope(from) || !p.inScope(to) {
			return nil
		}
		if from.EqualFold(to) {
			return nil
		}
		replacement := []byte(to.String())
		return p.repair(ctx, tx, func(g *Entry) bool {
			return mapMemberValues(g, func(v []byte, uniqueMember bool) []byte {
				d, ok := dnFromValue(v, uniqueMember)
				if !ok || !d.EqualFold(from) {
					return v
				}
				if !uniqueMember {
					return replacement
				}
				// Preserve the RFC 4519 '#' bit-string suffix.
				tail := v[len(stripUniqueMemberSuffix(v)):]
				out := make([]byte, 0, len(replacement)+len(tail))
				out = append(out, replacement...)
				return append(out, tail...)
			})
		})
	default:
		return nil
	}
}

// Fixup drops member/uniqueMember values that dangle because their target
// entry no longer exists — the native equivalent of 389's referential
// integrity fixup task, used by bootstrap and soft reset (C7). The sweep is
// suffix-scoped: only groups under the managed suffix are repaired, values
// pointing outside the suffix are left untouched (unverifiable in v1), and
// unparseable values are kept as data rather than silently deleted.
func (p *RefIntPlugin) Fixup(ctx context.Context, store Store) error {
	return store.Update(ctx, func(tx UpdateTx) error {
		var lookupErr error
		err := p.repair(ctx, tx, func(g *Entry) bool {
			if lookupErr != nil {
				return false
			}
			return filterMemberValues(g, func(v []byte, uniqueMember bool) bool {
				d, ok := dnFromValue(v, uniqueMember)
				if !ok || !p.inScope(d) {
					return true
				}
				_, err := tx.Entry(ctx, d)
				switch {
				case err == nil:
					return true
				case errors.Is(err, ErrNoSuchObject):
					return false
				default:
					lookupErr = err
					return true
				}
			})
		})
		if lookupErr != nil {
			return fmt.Errorf("ldapserver: referint: fixup lookup: %w", lookupErr)
		}
		return err
	})
}

// repair applies fix to every group entry in the managed suffix, writing
// back only entries the fix changed.
func (p *RefIntPlugin) repair(ctx context.Context, tx UpdateTx, fix func(g *Entry) (changed bool)) error {
	entries, err := tx.Subtree(ctx, p.suffix)
	if errors.Is(err, ErrNoSuchObject) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("ldapserver: referint: scan: %w", err)
	}
	for _, e := range entries {
		if !isGroupEntry(e) {
			continue
		}
		if !fix(e) {
			continue
		}
		if err := tx.Replace(ctx, e); err != nil {
			return fmt.Errorf("ldapserver: referint: repair group: %w", err)
		}
	}
	return nil
}

// filterMemberValues drops member/uniqueMember values for which keep
// returns false. An attribute whose last value is dropped is removed
// entirely. Reports whether the entry changed.
func filterMemberValues(e *Entry, keep func(v []byte, uniqueMember bool) bool) bool {
	changed := false
	attrs := e.Attributes[:0]
	for _, a := range e.Attributes {
		isMember := strings.EqualFold(a.Name, "member")
		isUnique := strings.EqualFold(a.Name, "uniqueMember")
		if !isMember && !isUnique {
			attrs = append(attrs, a)
			continue
		}
		var kept [][]byte
		for _, v := range a.Values {
			if keep(v, isUnique) {
				kept = append(kept, v)
			}
		}
		if len(kept) != len(a.Values) {
			changed = true
		}
		if len(kept) == 0 {
			continue
		}
		attrs = append(attrs, Attribute{Name: a.Name, Values: kept})
	}
	if changed {
		e.Attributes = attrs
	}
	return changed
}

// mapMemberValues replaces member/uniqueMember values with f(v), keeping
// values for which f returns the input. Reports whether the entry changed.
func mapMemberValues(e *Entry, f func(v []byte, uniqueMember bool) []byte) bool {
	changed := false
	for i, a := range e.Attributes {
		isMember := strings.EqualFold(a.Name, "member")
		isUnique := strings.EqualFold(a.Name, "uniqueMember")
		if !isMember && !isUnique {
			continue
		}
		for j, v := range a.Values {
			if nv := f(v, isUnique); string(nv) != string(v) {
				e.Attributes[i].Values[j] = nv
				changed = true
			}
		}
	}
	return changed
}
