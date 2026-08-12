package config

import (
	"fmt"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
)

func normalizeGroups(in *Input, users []NormalizedUser, groupsDN DN, nested bool) ([]NormalizedGroup, error) {
	var acc []*apperr.Error
	userByID := map[string]NormalizedUser{}
	for _, u := range users {
		userByID[u.ID] = u
	}
	groupIDs := map[string]int{}
	for i, g := range in.Groups {
		if g.ID == "" {
			acc = append(acc, fieldErr(fmt.Sprintf("spec.groups[%d].id", i), "required", "group id is required"))
			continue
		}
		if prev, ok := groupIDs[g.ID]; ok {
			acc = append(acc, fieldErr(fmt.Sprintf("spec.groups[%d].id", i), "duplicate", fmt.Sprintf("duplicate group id (also spec.groups[%d])", prev)))
			continue
		}
		groupIDs[g.ID] = i
	}

	out := make([]NormalizedGroup, 0, len(in.Groups))
	adj := map[string][]string{}
	for i, g := range in.Groups {
		if g.ID == "" {
			continue
		}
		path := fmt.Sprintf("spec.groups[%d]", i)
		if len(g.Members) == 0 {
			acc = append(acc, fieldErr(path+".members", "empty_group", "groupOfNames cannot be empty"))
			continue
		}
		rdn, err := BuildRDN("cn", g.ID)
		if err != nil {
			acc = append(acc, fieldErr(path+".id", "invalid_rdn", "cannot build group RDN"))
			continue
		}
		seenMem := map[string]struct{}{}
		var members []MemberRef
		for j, m := range g.Members {
			mp := fmt.Sprintf("%s.members[%d]", path, j)
			switch {
			case m.User != "" && m.Group != "":
				acc = append(acc, fieldErr(mp, "invalid_member", "member must be user or group, not both"))
			case m.User != "":
				u, ok := userByID[m.User]
				if !ok {
					acc = append(acc, fieldErr(mp+".user", "missing_ref", "user "+m.User+" is not defined"))
					continue
				}
				key := "user:" + m.User
				if _, dup := seenMem[key]; dup {
					continue
				}
				seenMem[key] = struct{}{}
				members = append(members, MemberRef{Kind: "user", ID: m.User, DN: u.DN})
			case m.Group != "":
				if !nested {
					acc = append(acc, fieldErr(mp+".group", "nested_disabled", "nested groups are disabled"))
					continue
				}
				if _, ok := groupIDs[m.Group]; !ok {
					acc = append(acc, fieldErr(mp+".group", "missing_ref", "group "+m.Group+" is not defined"))
					continue
				}
				key := "group:" + m.Group
				if _, dup := seenMem[key]; dup {
					continue
				}
				seenMem[key] = struct{}{}
				adj[g.ID] = append(adj[g.ID], m.Group)
				members = append(members, MemberRef{Kind: "group", ID: m.Group})
			default:
				acc = append(acc, fieldErr(mp, "invalid_member", "member requires user or group"))
			}
		}
		out = append(out, NormalizedGroup{ID: g.ID, DN: rdn + "," + groupsDN.String(), Members: members})
	}
	if err := detectCycles(adj); err != nil {
		acc = append(acc, err)
	}
	// fill nested group DNs after all groups exist
	byID := map[string]string{}
	for _, g := range out {
		byID[g.ID] = g.DN
	}
	for i := range out {
		for j := range out[i].Members {
			if out[i].Members[j].Kind == "group" {
				out[i].Members[j].DN = byID[out[i].Members[j].ID]
			}
		}
	}
	if err := joinConfig(acc); err != nil {
		return nil, err
	}
	sortGroups(out)
	return out, nil
}

func detectCycles(adj map[string][]string) *apperr.Error {
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := map[string]int{}
	var walk func(string) bool
	walk = func(n string) bool {
		color[n] = gray
		for _, m := range adj[n] {
			switch color[m] {
			case gray:
				return true
			case white:
				if walk(m) {
					return true
				}
			}
		}
		color[n] = black
		return false
	}
	for n := range adj {
		if color[n] == white && walk(n) {
			return fieldErr("spec.groups", "cycle", "group membership contains a cycle")
		}
	}
	return nil
}
