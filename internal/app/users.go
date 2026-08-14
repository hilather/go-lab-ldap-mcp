package app

import (
	"context"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

// Users is the user application service. Unit-testable without HTTP or MCP.
type Users struct {
	repo  directory.UserRepository
	hooks hooks
}

func (s *Users) List(ctx context.Context, p Principal, q directory.UserListQuery) (directory.UserPage, error) {
	if err := s.hooks.authorize(p, OpUserList); err != nil {
		return directory.UserPage{}, err
	}
	return s.repo.List(ctx, q)
}

func (s *Users) Get(ctx context.Context, p Principal, id directory.UserID) (directory.User, error) {
	if err := s.hooks.authorize(p, OpUserGet); err != nil {
		return directory.User{}, err
	}
	return s.repo.Get(ctx, id)
}

func (s *Users) Create(ctx context.Context, p Principal, spec CreateUser) (directory.User, error) {
	if err := s.hooks.authorize(p, OpUserCreate); err != nil {
		return directory.User{}, err
	}
	if err := s.hooks.allowWrite(ctx); err != nil {
		return directory.User{}, err
	}
	unlock := s.hooks.lock(userLockKey(spec.ID))
	defer unlock()
	if err := validateCreateUser(spec); err != nil {
		s.hooks.record(ctx, p, OpUserCreate.Name, spec.ID, AuditFailure, "", "")
		return directory.User{}, err
	}
	u, err := s.repo.Add(ctx, spec)
	if err != nil {
		// Password failure after create must not leave a bindable no-password
		// account. Repo.Add also compensates; the service retries delete when
		// a leftover exists and the failure is not a pre-existing conflict.
		if !isConflict(err) {
			s.compensateCreate(ctx, directory.UserID(spec.ID))
		}
		s.hooks.record(ctx, p, OpUserCreate.Name, spec.ID, AuditFailure, "", "")
		return directory.User{}, err
	}
	s.hooks.record(ctx, p, OpUserCreate.Name, u.ID, AuditSuccess, "", string(u.Revision))
	return u, nil
}

func (s *Users) compensateCreate(ctx context.Context, id directory.UserID) {
	if s.repo == nil || id == "" {
		return
	}
	got, err := s.repo.Get(ctx, id)
	if err != nil {
		return
	}
	_ = s.repo.Delete(ctx, id, got.Revision)
}

func (s *Users) Update(ctx context.Context, p Principal, id directory.UserID, patch UpdateUser) (directory.User, error) {
	if err := s.hooks.authorize(p, OpUserUpdate); err != nil {
		return directory.User{}, err
	}
	if err := s.hooks.allowWrite(ctx); err != nil {
		return directory.User{}, err
	}
	unlock := s.hooks.lock(userLockKey(string(id)))
	defer unlock()
	if err := requireRevision(patch.Revision); err != nil {
		s.hooks.record(ctx, p, OpUserUpdate.Name, string(id), AuditFailure, string(patch.Revision), "")
		return directory.User{}, err
	}
	if err := validateUserPatch(patch.UserPatch); err != nil {
		s.hooks.record(ctx, p, OpUserUpdate.Name, string(id), AuditFailure, string(patch.Revision), "")
		return directory.User{}, err
	}
	cur, err := s.repo.Get(ctx, id)
	if err != nil {
		s.hooks.record(ctx, p, OpUserUpdate.Name, string(id), AuditFailure, string(patch.Revision), "")
		return directory.User{}, err
	}
	if cur.Revision != patch.Revision {
		s.hooks.record(ctx, p, OpUserUpdate.Name, string(id), AuditFailure, string(patch.Revision), string(cur.Revision))
		return directory.User{}, directory.Error("revision", directory.FieldConflict, "directory entry revision does not match")
	}
	u, err := s.repo.Modify(ctx, id, patch.UserPatch)
	if err != nil {
		s.hooks.record(ctx, p, OpUserUpdate.Name, string(id), AuditFailure, string(patch.Revision), "")
		return directory.User{}, err
	}
	s.hooks.record(ctx, p, OpUserUpdate.Name, string(id), AuditSuccess, string(patch.Revision), string(u.Revision))
	return u, nil
}

func (s *Users) Delete(ctx context.Context, p Principal, id directory.UserID, rev directory.Revision) error {
	if err := s.hooks.authorize(p, OpUserDelete); err != nil {
		return err
	}
	if err := s.hooks.allowWrite(ctx); err != nil {
		return err
	}
	unlock := s.hooks.lock(userLockKey(string(id)))
	defer unlock()
	if err := requireRevision(rev); err != nil {
		s.hooks.record(ctx, p, OpUserDelete.Name, string(id), AuditFailure, string(rev), "")
		return err
	}
	err := s.repo.Delete(ctx, id, rev)
	if err != nil {
		s.hooks.record(ctx, p, OpUserDelete.Name, string(id), AuditFailure, string(rev), "")
		return err
	}
	s.hooks.record(ctx, p, OpUserDelete.Name, string(id), AuditSuccess, string(rev), "")
	return nil
}

func (s *Users) SetEnabled(ctx context.Context, p Principal, id directory.UserID, enabled bool, rev directory.Revision) (directory.User, error) {
	if err := s.hooks.authorize(p, OpUserSetEnabled); err != nil {
		return directory.User{}, err
	}
	if err := s.hooks.allowWrite(ctx); err != nil {
		return directory.User{}, err
	}
	unlock := s.hooks.lock(userLockKey(string(id)))
	defer unlock()
	if err := requireRevision(rev); err != nil {
		s.hooks.record(ctx, p, OpUserSetEnabled.Name, string(id), AuditFailure, string(rev), "")
		return directory.User{}, err
	}
	u, err := s.repo.SetEnabled(ctx, id, enabled, rev)
	if err != nil {
		s.hooks.record(ctx, p, OpUserSetEnabled.Name, string(id), AuditFailure, string(rev), "")
		return directory.User{}, err
	}
	s.hooks.record(ctx, p, OpUserSetEnabled.Name, string(id), AuditSuccess, string(rev), string(u.Revision))
	return u, nil
}

func (s *Users) SetPassword(ctx context.Context, p Principal, id directory.UserID, pw observability.Secret, rev directory.Revision) error {
	if err := s.hooks.authorize(p, OpUserPassword); err != nil {
		return err
	}
	if err := s.hooks.allowWrite(ctx); err != nil {
		return err
	}
	if err := s.hooks.rateLimit(ctx, "password:"+p.ID); err != nil {
		return err
	}
	unlock := s.hooks.lock(userLockKey(string(id)))
	defer unlock()
	if err := requireRevision(rev); err != nil {
		s.hooks.record(ctx, p, OpUserPassword.Name, string(id), AuditFailure, string(rev), "")
		return err
	}
	if pw.Reveal() == "" {
		s.hooks.record(ctx, p, OpUserPassword.Name, string(id), AuditFailure, string(rev), "")
		return apperr.New(apperr.CodeConfiguration, "password is required").WithField(apperr.Field{
			Path: "password", Code: "required", Message: "password is required",
		})
	}
	err := s.repo.SetPassword(ctx, id, pw, rev)
	if err != nil {
		s.hooks.record(ctx, p, OpUserPassword.Name, string(id), AuditFailure, string(rev), "")
		return err
	}
	s.hooks.record(ctx, p, OpUserPassword.Name, string(id), AuditSuccess, string(rev), "")
	return nil
}

func validateCreateUser(spec CreateUser) error {
	if spec.ID == "" {
		return apperr.New(apperr.CodeConfiguration, "id is required").WithField(apperr.Field{
			Path: "id", Code: "required", Message: "id is required",
		})
	}
	if spec.Password.Reveal() == "" {
		return apperr.New(apperr.CodeConfiguration, "password is required").WithField(apperr.Field{
			Path: "password", Code: "required", Message: "password is required",
		})
	}
	return validateAttrMap(spec.Attributes)
}

func validateUserPatch(patch directory.UserPatch) error {
	return validateAttrMap(patch.Attributes)
}

func validateAttrMap(attrs map[string]string) error {
	for name := range attrs {
		if config.ForbiddenUserAttr(name) {
			return apperr.New(apperr.CodeConfiguration, "attribute is not allowed on users").WithField(apperr.Field{
				Path: "attributes." + name, Code: "forbidden_attribute", Message: "attribute is not allowed on users",
			})
		}
	}
	return nil
}
