package app

import (
	"context"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

// Groups is group CRUD plus membership. v1 has no group attribute Modify.
type Groups struct {
	repo     directory.GroupRepository
	hooks    hooks
	peopleDN string
	groupsDN string
}

func (s *Groups) List(ctx context.Context, p Principal, q directory.GroupListQuery) (directory.GroupPage, error) {
	if err := s.hooks.authorize(ctx, p, OpGroupList); err != nil {
		return directory.GroupPage{}, err
	}
	if err := s.hooks.allowRead(ctx); err != nil {
		return directory.GroupPage{}, err
	}
	return s.repo.List(ctx, q)
}

func (s *Groups) Get(ctx context.Context, p Principal, id directory.GroupID) (directory.Group, error) {
	if err := s.hooks.authorize(ctx, p, OpGroupGet); err != nil {
		return directory.Group{}, err
	}
	if err := s.hooks.allowRead(ctx); err != nil {
		return directory.Group{}, err
	}
	return s.repo.Get(ctx, id)
}

func (s *Groups) Create(ctx context.Context, p Principal, spec directory.GroupSpec) (directory.Group, error) {
	if err := s.hooks.authorize(ctx, p, OpGroupCreate); err != nil {
		return directory.Group{}, err
	}
	if err := s.hooks.allowWrite(ctx); err != nil {
		return directory.Group{}, err
	}
	unlock := s.hooks.lock(groupLockKey(spec.ID))
	defer unlock()
	if spec.ID == "" {
		s.hooks.record(ctx, p, OpGroupCreate.Name, spec.ID, AuditFailure, "", "")
		return directory.Group{}, apperr.New(apperr.CodeConfiguration, "id is required").WithField(apperr.Field{
			Path: "id", Code: "required", Message: "id is required",
		})
	}
	if len(spec.Members) == 0 {
		s.hooks.record(ctx, p, OpGroupCreate.Name, spec.ID, AuditFailure, "", "")
		return directory.Group{}, apperr.New(apperr.CodeConfiguration, "groupOfNames cannot be empty").WithField(apperr.Field{
			Path: "members", Code: "empty_group", Message: "groupOfNames cannot be empty",
		})
	}
	if err := s.rejectSelfMember(directory.GroupID(spec.ID), spec.Members); err != nil {
		s.hooks.record(ctx, p, OpGroupCreate.Name, spec.ID, AuditFailure, "", "")
		return directory.Group{}, err
	}
	g, err := s.repo.Add(ctx, spec)
	if err != nil {
		s.hooks.record(ctx, p, OpGroupCreate.Name, spec.ID, AuditFailure, "", "")
		return directory.Group{}, err
	}
	s.hooks.record(ctx, p, OpGroupCreate.Name, g.ID, AuditSuccess, "", string(g.Revision))
	return g, nil
}

func (s *Groups) Delete(ctx context.Context, p Principal, id directory.GroupID, rev directory.Revision) error {
	if err := s.hooks.authorize(ctx, p, OpGroupDelete); err != nil {
		return err
	}
	if err := s.hooks.allowWrite(ctx); err != nil {
		return err
	}
	unlock := s.hooks.lock(groupLockKey(string(id)))
	defer unlock()
	if err := requireRevision(rev); err != nil {
		s.hooks.record(ctx, p, OpGroupDelete.Name, string(id), AuditFailure, string(rev), "")
		return err
	}
	err := s.repo.Delete(ctx, id, rev)
	if err != nil {
		s.hooks.record(ctx, p, OpGroupDelete.Name, string(id), AuditFailure, string(rev), "")
		return err
	}
	s.hooks.record(ctx, p, OpGroupDelete.Name, string(id), AuditSuccess, string(rev), "")
	return nil
}

func (s *Groups) AddMembers(ctx context.Context, p Principal, id directory.GroupID, members []directory.MemberRef, rev directory.Revision) (directory.MembershipSummary, error) {
	return s.mutateMembers(ctx, p, id, members, rev, "group.add_members", s.repo.AddMembers)
}

func (s *Groups) RemoveMembers(ctx context.Context, p Principal, id directory.GroupID, members []directory.MemberRef, rev directory.Revision) (directory.MembershipSummary, error) {
	return s.mutateMembers(ctx, p, id, members, rev, "group.remove_members", s.repo.RemoveMembers)
}

func (s *Groups) ReplaceMembers(ctx context.Context, p Principal, id directory.GroupID, members []directory.MemberRef, rev directory.Revision) (directory.MembershipSummary, error) {
	if err := requireRevision(rev); err != nil {
		if authErr := s.hooks.authorize(ctx, p, OpGroupMembers); authErr != nil {
			return directory.MembershipSummary{}, authErr
		}
		s.hooks.record(ctx, p, "group.replace_members", string(id), AuditFailure, string(rev), "")
		return directory.MembershipSummary{}, err
	}
	if err := s.rejectSelfMember(id, members); err != nil {
		if authErr := s.hooks.authorize(ctx, p, OpGroupMembers); authErr != nil {
			return directory.MembershipSummary{}, authErr
		}
		s.hooks.record(ctx, p, "group.replace_members", string(id), AuditFailure, string(rev), "")
		return directory.MembershipSummary{}, err
	}
	return s.mutateMembers(ctx, p, id, members, rev, "group.replace_members", s.repo.ReplaceMembers)
}

type memberMutate func(context.Context, directory.GroupID, []directory.MemberRef, directory.Revision) (directory.MembershipSummary, error)

func (s *Groups) mutateMembers(ctx context.Context, p Principal, id directory.GroupID, members []directory.MemberRef, rev directory.Revision, action string, fn memberMutate) (directory.MembershipSummary, error) {
	if err := s.hooks.authorize(ctx, p, OpGroupMembers); err != nil {
		return directory.MembershipSummary{}, err
	}
	if err := s.hooks.allowWrite(ctx); err != nil {
		return directory.MembershipSummary{}, err
	}
	unlock := s.hooks.lock(groupLockKey(string(id)))
	defer unlock()
	if err := requireRevision(rev); err != nil {
		s.hooks.record(ctx, p, action, string(id), AuditFailure, string(rev), "")
		return directory.MembershipSummary{}, err
	}
	if err := s.rejectSelfMember(id, members); err != nil && action != "group.remove_members" {
		s.hooks.record(ctx, p, action, string(id), AuditFailure, string(rev), "")
		return directory.MembershipSummary{}, err
	}
	if err := s.detectCycle(ctx, id, members, action); err != nil {
		s.hooks.record(ctx, p, action, string(id), AuditFailure, string(rev), "")
		return directory.MembershipSummary{}, err
	}
	sum, err := fn(ctx, id, members, rev)
	if err != nil {
		s.hooks.record(ctx, p, action, string(id), AuditFailure, string(rev), "")
		return directory.MembershipSummary{}, err
	}
	s.hooks.record(ctx, p, action, string(id), AuditSuccess, string(rev), string(sum.Revision))
	return sum, nil
}

func (s *Groups) detectCycle(ctx context.Context, id directory.GroupID, incoming []directory.MemberRef, action string) error {
	if action == "group.remove_members" {
		return nil
	}
	for _, raw := range incoming {
		m := s.normalizeRef(raw)
		if !strings.EqualFold(m.Kind, "group") {
			continue
		}
		gid := directory.GroupID(m.ID)
		if gid == "" && m.DN != "" {
			gid = directory.GroupID(leafCN(m.DN))
		}
		if gid == "" {
			continue
		}
		hit, err := s.cycleFrom(ctx, id, gid, map[string]struct{}{})
		if err != nil {
			return err
		}
		if hit {
			return apperr.New(apperr.CodeConfiguration, "group membership cycle").WithField(apperr.Field{
				Path: "members", Code: "cycle", Message: "group membership cycle",
			})
		}
	}
	return nil
}

func (s *Groups) cycleFrom(ctx context.Context, origin, cur directory.GroupID, seen map[string]struct{}) (bool, error) {
	if strings.EqualFold(string(cur), string(origin)) {
		return true, nil
	}
	key := strings.ToLower(string(cur))
	if _, ok := seen[key]; ok {
		return false, nil
	}
	seen[key] = struct{}{}
	g, err := s.repo.Get(ctx, cur)
	if err != nil {
		if fieldCode(err) == directory.FieldNotFound {
			return false, nil
		}
		return false, err
	}
	for _, raw := range g.Members {
		m := s.normalizeRef(raw)
		if !strings.EqualFold(m.Kind, "group") {
			continue
		}
		next := directory.GroupID(m.ID)
		if next == "" {
			next = directory.GroupID(leafCN(m.DN))
		}
		if next == "" {
			continue
		}
		hit, err := s.cycleFrom(ctx, origin, next, seen)
		if err != nil || hit {
			return hit, err
		}
	}
	return false, nil
}

func (s *Groups) rejectSelfMember(id directory.GroupID, members []directory.MemberRef) error {
	for _, raw := range members {
		if s.isSelfGroup(id, raw) {
			return apperr.New(apperr.CodeConfiguration, "group membership cycle").WithField(apperr.Field{
				Path: "members", Code: "cycle", Message: "group cannot contain itself",
			})
		}
	}
	return nil
}

func (s *Groups) isSelfGroup(id directory.GroupID, m directory.MemberRef) bool {
	m = s.normalizeRef(m)
	if !strings.EqualFold(m.Kind, "group") {
		return false
	}
	if m.ID != "" && strings.EqualFold(m.ID, string(id)) {
		return true
	}
	if m.DN != "" && s.groupsDN != "" {
		return dnEqualFold(m.DN, "cn="+string(id)+","+s.groupsDN)
	}
	return false
}

func (s *Groups) normalizeRef(m directory.MemberRef) directory.MemberRef {
	kind := strings.ToLower(strings.TrimSpace(m.Kind))
	if m.DN != "" && kind == "" {
		switch {
		case underDN(m.DN, s.groupsDN):
			kind = "group"
		case underDN(m.DN, s.peopleDN):
			kind = "user"
		}
	}
	if m.ID == "" && m.DN != "" {
		m.ID = leafCN(m.DN)
	}
	m.Kind = kind
	return m
}

func underDN(dn, container string) bool {
	d := strings.ToLower(strings.TrimSpace(dn))
	c := strings.ToLower(strings.TrimSpace(container))
	if d == "" || c == "" {
		return false
	}
	return strings.HasSuffix(d, ","+c)
}

func dnEqualFold(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

func leafCN(dn string) string {
	dn = strings.TrimSpace(dn)
	if dn == "" {
		return ""
	}
	head, _, _ := strings.Cut(dn, ",")
	_, val, ok := strings.Cut(head, "=")
	if !ok {
		return ""
	}
	return strings.TrimSpace(val)
}
