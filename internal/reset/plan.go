package reset

import (
	"sort"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

// Kind classifies a planned delete.
type Kind string

const (
	KindGroup Kind = "group"
	KindUser  Kind = "user"
	KindExtra Kind = "extra"
)

// DeleteStep is one managed DN to remove. Order is children first.
type DeleteStep struct {
	DN    string
	Kind  Kind
	Depth int
}

// Plan is a dry-run delete plan. It never mutates the directory.
type Plan struct {
	Deletes  []DeleteStep
	Preserve []string
	Users    []string
	Groups   []string
	Extra    []string
	Counts   Counts
}

// PlanConfig is compiled geometry plus configured baseline DNs.
type PlanConfig struct {
	PeopleDN         string
	GroupsDN         string
	Suffix           string
	RuntimeDN        string
	MarkerDN         string
	ConfiguredUsers  []string
	ConfiguredGroups []string
}

// BuildPlan inventories extras and orders deletes. It never includes DNs
// outside people/groups, the runtime account, required containers, or the marker.
func BuildPlan(inv directory.ManagedInventory, cfg PlanConfig) Plan {
	preserve := preserveSet(inv, cfg)
	configured := dnSet(append(append([]string{}, cfg.ConfiguredUsers...), cfg.ConfiguredGroups...))

	var users, groups, extra []string
	seen := map[string]struct{}{}
	addLive := func(dn string, hint Kind) {
		key, ok := managedKey(dn)
		if !ok || !underManagedContainers(dn, cfg) {
			return
		}
		if _, dup := seen[key]; dup {
			return
		}
		if _, keep := preserve[key]; keep {
			return
		}
		seen[key] = struct{}{}
		switch {
		case hint == KindGroup || isGroupDN(dn, cfg):
			groups = append(groups, canonicalDN(dn))
		case hint == KindUser || isUserDN(dn, cfg):
			users = append(users, canonicalDN(dn))
		default:
			extra = append(extra, canonicalDN(dn))
		}
	}
	for _, dn := range inv.Users {
		addLive(dn, KindUser)
	}
	for _, dn := range inv.Groups {
		addLive(dn, KindGroup)
	}
	for _, dn := range inv.Extra {
		addLive(dn, KindExtra)
	}

	// Unconfigured live entries are extras even if they looked like users/groups.
	var extraUsers, extraGroups, keepUsers, keepGroups []string
	for _, dn := range users {
		if _, ok := configured[dnKey(dn)]; ok {
			keepUsers = append(keepUsers, dn)
		} else {
			extraUsers = append(extraUsers, dn)
		}
	}
	for _, dn := range groups {
		if _, ok := configured[dnKey(dn)]; ok {
			keepGroups = append(keepGroups, dn)
		} else {
			extraGroups = append(extraGroups, dn)
		}
	}
	extra = append(extra, extraUsers...)
	extra = append(extra, extraGroups...)
	sortCI(extra)
	extra = uniqueDN(extra)

	// Soft reset deletes extras and configured objects (then reapplies).
	var steps []DeleteStep
	push := func(dns []string, kind Kind) {
		for _, dn := range dns {
			if !underManagedContainers(dn, cfg) {
				continue
			}
			if _, keep := preserve[dnKey(dn)]; keep {
				continue
			}
			steps = append(steps, DeleteStep{DN: canonicalDN(dn), Kind: kind, Depth: dnDepth(dn)})
		}
	}
	push(extra, KindExtra)
	push(keepGroups, KindGroup)
	push(keepUsers, KindUser)

	sort.SliceStable(steps, func(i, j int) bool {
		if steps[i].Depth != steps[j].Depth {
			return steps[i].Depth > steps[j].Depth
		}
		pi, pj := kindPri(steps[i].Kind), kindPri(steps[j].Kind)
		if pi != pj {
			return pi < pj
		}
		return strings.ToLower(steps[i].DN) < strings.ToLower(steps[j].DN)
	})

	pres := make([]string, 0, len(preserve))
	for k := range preserve {
		pres = append(pres, k)
	}
	sort.Strings(pres)

	return Plan{
		Deletes:  steps,
		Preserve: pres,
		Users:    keepUsers,
		Groups:   keepGroups,
		Extra:    extra,
		Counts: Counts{
			Deleted: len(steps),
			Users:   len(keepUsers),
			Groups:  len(keepGroups),
			Extra:   len(extra),
		},
	}
}

func kindPri(k Kind) int {
	switch k {
	case KindGroup:
		return 0
	case KindExtra:
		return 1
	default:
		return 2
	}
}

func preserveSet(inv directory.ManagedInventory, cfg PlanConfig) map[string]struct{} {
	out := map[string]struct{}{}
	add := func(s string) {
		if k, ok := managedKey(s); ok {
			out[k] = struct{}{}
		}
	}
	add(cfg.RuntimeDN)
	add(cfg.PeopleDN)
	add(cfg.GroupsDN)
	add(cfg.MarkerDN)
	add(cfg.Suffix)
	for _, p := range inv.Preserve {
		add(p)
	}
	return out
}

func underManagedContainers(dn string, cfg PlanConfig) bool {
	return underContainer(dn, cfg.PeopleDN) || underContainer(dn, cfg.GroupsDN)
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

func isGroupDN(dn string, cfg PlanConfig) bool {
	return underContainer(dn, cfg.GroupsDN)
}

func isUserDN(dn string, cfg PlanConfig) bool {
	return underContainer(dn, cfg.PeopleDN)
}

func dnDepth(dn string) int {
	d, err := config.ParseDN(dn)
	if err != nil {
		return strings.Count(dn, ",") + 1
	}
	return d.Depth()
}

func canonicalDN(dn string) string {
	d, err := config.ParseDN(dn)
	if err != nil {
		return strings.TrimSpace(dn)
	}
	return d.String()
}

func dnKey(dn string) string {
	return strings.ToLower(canonicalDN(dn))
}

func managedKey(dn string) (string, bool) {
	s := strings.TrimSpace(dn)
	if s == "" {
		return "", false
	}
	return dnKey(s), true
}

func dnSet(in []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, s := range in {
		if k, ok := managedKey(s); ok {
			out[k] = struct{}{}
		}
	}
	return out
}

func uniqueDN(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		k := dnKey(s)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, canonicalDN(s))
	}
	return out
}

func sortCI(in []string) {
	sort.Slice(in, func(i, j int) bool {
		return strings.ToLower(in[i]) < strings.ToLower(in[j])
	})
}
