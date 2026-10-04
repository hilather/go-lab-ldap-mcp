package app

import (
	"context"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

// Entries is the structured (not raw LDAP) entry application service.
type Entries struct {
	repo  directory.EntryRepository
	hooks hooks
}

func (s *Entries) Suffixes(ctx context.Context, p Principal) (directory.SuffixList, error) {
	if err := s.hooks.authorize(ctx, p, OpSuffixes); err != nil {
		return directory.SuffixList{}, err
	}
	release, err := s.hooks.acquireRead(ctx)
	if err != nil {
		return directory.SuffixList{}, err
	}
	defer release()
	if s.repo == nil {
		return directory.SuffixList{}, directoryUnavailable()
	}
	return s.repo.ManagedSuffixes(), nil
}

func (s *Entries) Get(ctx context.Context, p Principal, dn string) (directory.DirectoryEntry, error) {
	if err := s.hooks.authorize(ctx, p, OpEntryGet); err != nil {
		return directory.DirectoryEntry{}, err
	}
	release, err := s.hooks.acquireRead(ctx)
	if err != nil {
		return directory.DirectoryEntry{}, err
	}
	defer release()
	if s.repo == nil {
		return directory.DirectoryEntry{}, directoryUnavailable()
	}
	ent, err := s.repo.GetEntryMeta(ctx, dn)
	if err != nil {
		return directory.DirectoryEntry{}, err
	}
	return redactDirectoryEntry(ent), nil
}

func (s *Entries) ListTree(ctx context.Context, p Principal, q directory.TreeQuery) (directory.TreePage, error) {
	if err := s.hooks.authorize(ctx, p, OpEntryTree); err != nil {
		return directory.TreePage{}, err
	}
	release, err := s.hooks.acquireRead(ctx)
	if err != nil {
		return directory.TreePage{}, err
	}
	defer release()
	if s.repo == nil {
		return directory.TreePage{}, directoryUnavailable()
	}
	return s.repo.ListTree(ctx, q)
}

func (s *Entries) Create(ctx context.Context, p Principal, spec directory.EntrySpec) (directory.DirectoryEntry, error) {
	if err := s.hooks.authorize(ctx, p, OpEntryCreate); err != nil {
		return directory.DirectoryEntry{}, err
	}
	release, err := s.hooks.acquireWrite(ctx)
	if err != nil {
		return directory.DirectoryEntry{}, err
	}
	defer release()
	if s.repo == nil {
		return directory.DirectoryEntry{}, directoryUnavailable()
	}
	for name := range spec.Attributes {
		if directory.ForbiddenEntryAttr(name) {
			s.hooks.record(ctx, p, OpEntryCreate.Name, "entry", AuditFailure, "", "")
			return directory.DirectoryEntry{}, entryAttributeError("attributes." + name)
		}
	}

	unlock := s.hooks.lock(entryLockKey(spec.DN))
	defer unlock()
	ent, err := s.repo.CreateEntry(ctx, spec)
	if err != nil {
		s.hooks.record(ctx, p, OpEntryCreate.Name, "entry", AuditFailure, "", "")
		return directory.DirectoryEntry{}, err
	}
	s.hooks.record(ctx, p, OpEntryCreate.Name, "entry", AuditSuccess, "", string(ent.Revision))
	return redactDirectoryEntry(ent), nil
}

func (s *Entries) Update(ctx context.Context, p Principal, patch directory.EntryPatch) (directory.DirectoryEntry, error) {
	if err := s.hooks.authorize(ctx, p, OpEntryUpdate); err != nil {
		return directory.DirectoryEntry{}, err
	}
	release, err := s.hooks.acquireWrite(ctx)
	if err != nil {
		return directory.DirectoryEntry{}, err
	}
	defer release()
	if s.repo == nil {
		return directory.DirectoryEntry{}, directoryUnavailable()
	}
	for _, ch := range patch.Changes {
		if directory.ForbiddenEntryAttr(ch.Name) || config.CanonicalAttrType(ch.Name) == "objectclass" {
			s.hooks.record(ctx, p, OpEntryUpdate.Name, "entry", AuditFailure, string(patch.Revision), "")
			return directory.DirectoryEntry{}, entryAttributeError("changes.name")
		}
	}

	unlock := s.hooks.lock(entryLockKey(patch.DN))
	defer unlock()
	if err := requireRevision(patch.Revision); err != nil {
		s.hooks.record(ctx, p, OpEntryUpdate.Name, "entry", AuditFailure, string(patch.Revision), "")
		return directory.DirectoryEntry{}, err
	}
	ent, err := s.repo.UpdateEntry(ctx, patch)
	if err != nil {
		s.hooks.record(ctx, p, OpEntryUpdate.Name, "entry", AuditFailure, string(patch.Revision), "")
		return directory.DirectoryEntry{}, err
	}
	s.hooks.record(ctx, p, OpEntryUpdate.Name, "entry", AuditSuccess, string(patch.Revision), string(ent.Revision))
	return redactDirectoryEntry(ent), nil
}

func (s *Entries) Delete(ctx context.Context, p Principal, del directory.EntryDelete) error {
	if err := s.hooks.authorize(ctx, p, OpEntryDelete); err != nil {
		return err
	}
	release, err := s.hooks.acquireWrite(ctx)
	if err != nil {
		return err
	}
	defer release()
	if s.repo == nil {
		return directoryUnavailable()
	}
	if !del.Confirm {
		s.hooks.record(ctx, p, OpEntryDelete.Name, "entry", AuditFailure, string(del.Revision), "")
		return apperr.New(apperr.CodeConfiguration, "destructive delete requires confirm").WithField(apperr.Field{
			Path: "confirm", Code: "required", Message: "destructive delete requires confirm",
		})
	}
	unlock := s.hooks.lock(entryLockKey(del.DN))
	defer unlock()
	if err := requireRevision(del.Revision); err != nil {
		s.hooks.record(ctx, p, OpEntryDelete.Name, "entry", AuditFailure, string(del.Revision), "")
		return err
	}
	if err := s.repo.DeleteEntry(ctx, del); err != nil {
		s.hooks.record(ctx, p, OpEntryDelete.Name, "entry", AuditFailure, string(del.Revision), "")
		return err
	}
	s.hooks.record(ctx, p, OpEntryDelete.Name, "entry", AuditSuccess, string(del.Revision), "")
	return nil
}

func (s *Entries) Move(ctx context.Context, p Principal, move directory.EntryMove) (directory.DirectoryEntry, error) {
	if err := s.hooks.authorize(ctx, p, OpEntryMove); err != nil {
		return directory.DirectoryEntry{}, err
	}
	release, err := s.hooks.acquireWrite(ctx)
	if err != nil {
		return directory.DirectoryEntry{}, err
	}
	defer release()
	if s.repo == nil {
		return directory.DirectoryEntry{}, directoryUnavailable()
	}
	unlock := s.hooks.lock(entryLockKey(move.DN))
	defer unlock()
	if err := requireRevision(move.Revision); err != nil {
		s.hooks.record(ctx, p, OpEntryMove.Name, "entry", AuditFailure, string(move.Revision), "")
		return directory.DirectoryEntry{}, err
	}
	ent, err := s.repo.MoveEntry(ctx, move)
	if err != nil {
		s.hooks.record(ctx, p, OpEntryMove.Name, "entry", AuditFailure, string(move.Revision), "")
		return directory.DirectoryEntry{}, err
	}
	s.hooks.record(ctx, p, OpEntryMove.Name, "entry", AuditSuccess, string(move.Revision), string(ent.Revision))
	return redactDirectoryEntry(ent), nil
}

func entryLockKey(dn string) string {
	if parsed, err := config.ParseDN(dn); err == nil {
		return "entry:" + parsed.FoldedKey()
	}
	return "entry:" + strings.ToLower(strings.TrimSpace(dn))
}

func directoryUnavailable() error {
	return directory.Error("directory", directory.FieldUnavailable, "directory is not ready")
}

func redactDirectoryEntry(in directory.DirectoryEntry) directory.DirectoryEntry {
	in.Attributes = redactAttrs(in.Attributes)
	return in
}

func entryAttributeError(path string) error {
	return apperr.New(apperr.CodeConfiguration, "attribute is not allowed").WithField(apperr.Field{Path: path, Code: "forbidden_attribute", Message: "attribute is not allowed"})
}
