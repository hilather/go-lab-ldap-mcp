package app

import (
	"context"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

// Groups is group CRUD plus membership. v1 has no group attribute Modify.
type Groups struct {
	repo  directory.GroupRepository
	hooks hooks
}

func (s *Groups) List(ctx context.Context, p Principal, q directory.GroupListQuery) (directory.GroupPage, error) {
	if err := s.hooks.authorize(p, OpGroupList); err != nil {
		return directory.GroupPage{}, err
	}
	return s.repo.List(ctx, q)
}

func (s *Groups) Get(ctx context.Context, p Principal, id directory.GroupID) (directory.Group, error) {
	if err := s.hooks.authorize(p, OpGroupGet); err != nil {
		return directory.Group{}, err
	}
	return s.repo.Get(ctx, id)
}

func (s *Groups) Create(ctx context.Context, p Principal, spec directory.GroupSpec) (directory.Group, error) {
	if err := s.hooks.authorize(p, OpGroupCreate); err != nil {
		return directory.Group{}, err
	}
	if err := s.hooks.allowWrite(ctx); err != nil {
		return directory.Group{}, err
	}
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
	if err := rejectSelfMember(directory.GroupID(spec.ID), spec.Members); err != nil {
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
	if err := s.hooks.authorize(p, OpGroupDelete); err != nil {
		return err
	}
	if err := s.hooks.allowWrite(ctx); err != nil {
		return err
	}
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
		if authErr := s.hooks.authorize(p, OpGroupMembers); authErr != nil {
			return directory.MembershipSummary{}, authErr
		}
		s.hooks.record(ctx, p, "group.replace_members", string(id), AuditFailure, string(rev), "")
		return directory.MembershipSummary{}, err
	}
	if err := rejectSelfMember(id, members); err != nil {
		if authErr := s.hooks.authorize(p, OpGroupMembers); authErr != nil {
			return directory.MembershipSummary{}, authErr
		}
		s.hooks.record(ctx, p, "group.replace_members", string(id), AuditFailure, string(rev), "")
		return directory.MembershipSummary{}, err
	}
	return s.mutateMembers(ctx, p, id, members, rev, "group.replace_members", s.repo.ReplaceMembers)
}

type memberMutate func(context.Context, directory.GroupID, []directory.MemberRef, directory.Revision) (directory.MembershipSummary, error)

func (s *Groups) mutateMembers(ctx context.Context, p Principal, id directory.GroupID, members []directory.MemberRef, rev directory.Revision, action string, fn memberMutate) (directory.MembershipSummary, error) {
	if err := s.hooks.authorize(p, OpGroupMembers); err != nil {
		return directory.MembershipSummary{}, err
	}
	if err := s.hooks.allowWrite(ctx); err != nil {
		return directory.MembershipSummary{}, err
	}
	if err := requireRevision(rev); err != nil {
		s.hooks.record(ctx, p, action, string(id), AuditFailure, string(rev), "")
		return directory.MembershipSummary{}, err
	}
	if err := rejectSelfMember(id, members); err != nil && action != "group.remove_members" {
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
	for _, m := range incoming {
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
		if cycleFrom(ctx, s.repo, id, gid, map[directory.GroupID]struct{}{}) {
			return apperr.New(apperr.CodeConfiguration, "group membership cycle").WithField(apperr.Field{
				Path: "members", Code: "cycle", Message: "group membership cycle",
			})
		}
	}
	return nil
}

func cycleFrom(ctx context.Context, repo directory.GroupRepository, origin, cur directory.GroupID, seen map[directory.GroupID]struct{}) bool {
	if cur == origin {
		return true
	}
	if _, ok := seen[cur]; ok {
		return false
	}
	seen[cur] = struct{}{}
	g, err := repo.Get(ctx, cur)
	if err != nil {
		return false
	}
	for _, m := range g.Members {
		if !strings.EqualFold(m.Kind, "group") {
			continue
		}
		next := directory.GroupID(m.ID)
		if next == "" {
			next = directory.GroupID(leafCN(m.DN))
		}
		if next != "" && cycleFrom(ctx, repo, origin, next, seen) {
			return true
		}
	}
	return false
}

func rejectSelfMember(id directory.GroupID, members []directory.MemberRef) error {
	want := strings.ToLower(string(id))
	for _, m := range members {
		if !strings.EqualFold(m.Kind, "group") && m.Kind != "" {
			continue
		}
		if strings.EqualFold(m.Kind, "group") && strings.ToLower(m.ID) == want {
			return apperr.New(apperr.CodeConfiguration, "group membership cycle").WithField(apperr.Field{
				Path: "members", Code: "cycle", Message: "group cannot contain itself",
			})
		}
	}
	return nil
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
