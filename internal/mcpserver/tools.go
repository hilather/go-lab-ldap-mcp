package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

const (
	mcpExportCeiling = 64 * 1024
	exportHandoff    = "GET /api/v1/export"
)

func (s *Server) registerTools(ms *mcp.Server) {
	for _, d := range Catalog() {
		if !d.ShouldRegister(s.flags) {
			continue
		}
		switch d.Name {
		case ToolSearch:
			mcp.AddTool(ms, toolMeta(d), s.callSearch)
		case ToolCapabilities:
			mcp.AddTool(ms, toolMeta(d), s.callCapabilities)
		case ToolBaseline:
			mcp.AddTool(ms, toolMeta(d), s.callBaseline)
		case ToolGetEntry:
			mcp.AddTool(ms, toolMeta(d), s.callGetEntry)
		case ToolCreateUser:
			mcp.AddTool(ms, toolMeta(d), s.callCreateUser)
		case ToolUpdateUser:
			mcp.AddTool(ms, toolMeta(d), s.callUpdateUser)
		case ToolDeleteUser:
			mcp.AddTool(ms, toolMeta(d), s.callDeleteUser)
		case ToolSetPassword:
			mcp.AddTool(ms, toolMeta(d), s.callSetPassword)
		case ToolAccountState:
			mcp.AddTool(ms, toolMeta(d), s.callAccountState)
		case ToolExpirePassword:
			mcp.AddTool(ms, toolMeta(d), s.callExpirePassword)
		case ToolClearPasswordExpiry:
			mcp.AddTool(ms, toolMeta(d), s.callClearPasswordExpiry)
		case ToolLockUser:
			mcp.AddTool(ms, toolMeta(d), s.callLockUser)
		case ToolUnlockUser:
			mcp.AddTool(ms, toolMeta(d), s.callUnlockUser)
		case ToolEnableUser:
			mcp.AddTool(ms, toolMeta(d), s.callEnableUser)
		case ToolDisableUser:
			mcp.AddTool(ms, toolMeta(d), s.callDisableUser)
		case ToolCreateGroup:
			mcp.AddTool(ms, toolMeta(d), s.callCreateGroup)
		case ToolDeleteGroup:
			mcp.AddTool(ms, toolMeta(d), s.callDeleteGroup)
		case ToolAddMembers:
			mcp.AddTool(ms, toolMeta(d), s.callAddMembers)
		case ToolRemoveMembers:
			mcp.AddTool(ms, toolMeta(d), s.callRemoveMembers)
		case ToolReplaceMembers:
			mcp.AddTool(ms, toolMeta(d), s.callReplaceMembers)
		case ToolListSuffixes:
			mcp.AddTool(ms, toolMeta(d), s.callListSuffixes)
		case ToolListTree:
			mcp.AddTool(ms, toolMeta(d), s.callListTree)
		case ToolCreateEntry:
			mcp.AddTool(ms, toolMeta(d), s.callCreateEntry)
		case ToolUpdateEntry:
			mcp.AddTool(ms, toolMeta(d), s.callUpdateEntry)
		case ToolDeleteEntry:
			mcp.AddTool(ms, toolMeta(d), s.callDeleteEntry)
		case ToolMoveEntry:
			mcp.AddTool(ms, toolMeta(d), s.callMoveEntry)
		case ToolBindTest:
			mcp.AddTool(ms, toolMeta(d), s.callBindTest)
		case ToolResetSuffix:
			mcp.AddTool(ms, toolMeta(d), s.callResetSuffix)
		case ToolExportLDIF:
			mcp.AddTool(ms, toolMeta(d), s.callExportLDIF)
		}
	}
}

func toolMeta(d ToolDef) *mcp.Tool {
	return &mcp.Tool{
		Name:        d.Name,
		Description: d.Description,
		Annotations: &mcp.ToolAnnotations{
			Title:           d.Name,
			ReadOnlyHint:    d.ReadOnly,
			DestructiveHint: boolPtr(d.Destructive),
			IdempotentHint:  d.Idempotent,
			OpenWorldHint:   boolPtr(d.OpenWorld),
		},
	}
}

func (s *Server) callSearch(ctx context.Context, _ *mcp.CallToolRequest, in directory.SearchQuery) (*mcp.CallToolResult, directory.SearchPage, error) {
	p, q, err := s.ready(ctx, ToolSearch)
	if err != nil {
		return nil, directory.SearchPage{}, err
	}
	page, err := q.Search(ctx, p, in)
	if err != nil {
		return nil, directory.SearchPage{}, publicToolErr(err)
	}
	return toolResult(ctx), normalizePage(page), nil
}

func (s *Server) callCapabilities(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, directory.Capabilities, error) {
	p, q, err := s.ready(ctx, ToolCapabilities)
	if err != nil {
		return nil, directory.Capabilities{}, err
	}
	caps, err := q.Capabilities(ctx, p)
	if err != nil {
		return nil, directory.Capabilities{}, publicToolErr(err)
	}
	return toolResult(ctx), caps, nil
}

func (s *Server) callBaseline(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, app.Baseline, error) {
	p, q, err := s.ready(ctx, ToolBaseline)
	if err != nil {
		return nil, app.Baseline{}, err
	}
	b, err := q.Baseline(ctx, p)
	if err != nil {
		return nil, app.Baseline{}, publicToolErr(err)
	}
	return toolResult(ctx), b, nil
}

func (s *Server) callGetEntry(ctx context.Context, _ *mcp.CallToolRequest, in GetEntryInput) (*mcp.CallToolResult, directory.SearchEntry, error) {
	p, q, err := s.ready(ctx, ToolGetEntry)
	if err != nil {
		return nil, directory.SearchEntry{}, err
	}
	entry, err := q.GetEntry(ctx, p, in.DN, in.Attributes)
	if err != nil {
		return nil, directory.SearchEntry{}, publicToolErr(err)
	}
	return toolResult(ctx), entry, nil
}

func (s *Server) callCreateUser(ctx context.Context, _ *mcp.CallToolRequest, in CreateUserInput) (*mcp.CallToolResult, directory.User, error) {
	p, users, err := s.readyUsers(ctx, ToolCreateUser)
	if err != nil {
		return nil, directory.User{}, err
	}
	spec := app.CreateUser{
		ID: in.ID, UID: in.UID, DN: in.DN, ParentDN: in.ParentDN, Enabled: in.Enabled,
		Password:   observability.Secret(in.Password),
		Attributes: in.Attributes,
	}
	in.Password = ""
	u, err := users.Create(ctx, p, spec)
	if err != nil {
		return nil, directory.User{}, publicToolErr(err)
	}
	return toolResult(ctx), u, nil
}

func (s *Server) callUpdateUser(ctx context.Context, _ *mcp.CallToolRequest, in UpdateUserInput) (*mcp.CallToolResult, directory.User, error) {
	p, users, err := s.readyUsers(ctx, ToolUpdateUser)
	if err != nil {
		return nil, directory.User{}, err
	}
	u, err := users.Update(ctx, p, directory.UserID(in.ID), app.UpdateUser{
		UserPatch: directory.UserPatch{Enabled: in.Enabled, Attributes: in.Attributes},
		Revision:  directory.Revision(in.Revision),
	})
	if err != nil {
		return nil, directory.User{}, publicToolErr(err)
	}
	return toolResult(ctx), u, nil
}

func (s *Server) callDeleteUser(ctx context.Context, _ *mcp.CallToolRequest, in DeleteInput) (*mcp.CallToolResult, IDResult, error) {
	p, users, err := s.readyUsers(ctx, ToolDeleteUser)
	if err != nil {
		return nil, IDResult{}, err
	}
	if err := requireConfirm(in.Confirm); err != nil {
		return nil, IDResult{}, err
	}
	if err := users.Delete(ctx, p, directory.UserID(in.ID), directory.Revision(in.Revision)); err != nil {
		return nil, IDResult{}, publicToolErr(err)
	}
	return toolResult(ctx), IDResult{ID: in.ID}, nil
}

func (s *Server) callSetPassword(ctx context.Context, _ *mcp.CallToolRequest, in SetPasswordInput) (*mcp.CallToolResult, IDResult, error) {
	p, users, err := s.readyUsers(ctx, ToolSetPassword)
	if err != nil {
		return nil, IDResult{}, err
	}
	pw := observability.Secret(in.Password)
	in.Password = ""
	if err := users.SetPassword(ctx, p, directory.UserID(in.ID), pw, directory.Revision(in.Revision), in.MustChange); err != nil {
		return nil, IDResult{}, publicToolErr(err)
	}
	return toolResult(ctx), IDResult{ID: in.ID}, nil
}

func (s *Server) callAccountState(ctx context.Context, _ *mcp.CallToolRequest, in IDOnlyInput) (*mcp.CallToolResult, directory.AccountState, error) {
	p, users, err := s.readyUsers(ctx, ToolAccountState)
	if err != nil {
		return nil, directory.AccountState{}, err
	}
	st, err := users.AccountState(ctx, p, directory.UserID(in.ID))
	if err != nil {
		return nil, directory.AccountState{}, publicToolErr(err)
	}
	return toolResult(ctx), st, nil
}

func (s *Server) callExpirePassword(ctx context.Context, _ *mcp.CallToolRequest, in RevisionIDInput) (*mcp.CallToolResult, directory.AccountState, error) {
	return s.callAccountMut(ctx, ToolExpirePassword, in, func(users *app.Users, p app.Principal) (directory.AccountState, error) {
		return users.ExpirePassword(ctx, p, directory.UserID(in.ID), directory.Revision(in.Revision))
	})
}

func (s *Server) callClearPasswordExpiry(ctx context.Context, _ *mcp.CallToolRequest, in RevisionIDInput) (*mcp.CallToolResult, directory.AccountState, error) {
	return s.callAccountMut(ctx, ToolClearPasswordExpiry, in, func(users *app.Users, p app.Principal) (directory.AccountState, error) {
		return users.ClearPasswordExpiry(ctx, p, directory.UserID(in.ID), directory.Revision(in.Revision))
	})
}

func (s *Server) callLockUser(ctx context.Context, _ *mcp.CallToolRequest, in RevisionIDInput) (*mcp.CallToolResult, directory.AccountState, error) {
	return s.callAccountMut(ctx, ToolLockUser, in, func(users *app.Users, p app.Principal) (directory.AccountState, error) {
		return users.Lock(ctx, p, directory.UserID(in.ID), directory.Revision(in.Revision))
	})
}

func (s *Server) callUnlockUser(ctx context.Context, _ *mcp.CallToolRequest, in RevisionIDInput) (*mcp.CallToolResult, directory.AccountState, error) {
	return s.callAccountMut(ctx, ToolUnlockUser, in, func(users *app.Users, p app.Principal) (directory.AccountState, error) {
		return users.Unlock(ctx, p, directory.UserID(in.ID), directory.Revision(in.Revision))
	})
}

func (s *Server) callEnableUser(ctx context.Context, _ *mcp.CallToolRequest, in RevisionIDInput) (*mcp.CallToolResult, directory.User, error) {
	return s.callSetEnabled(ctx, ToolEnableUser, in, true)
}

func (s *Server) callDisableUser(ctx context.Context, _ *mcp.CallToolRequest, in RevisionIDInput) (*mcp.CallToolResult, directory.User, error) {
	return s.callSetEnabled(ctx, ToolDisableUser, in, false)
}

func (s *Server) callSetEnabled(ctx context.Context, tool string, in RevisionIDInput, enabled bool) (*mcp.CallToolResult, directory.User, error) {
	p, users, err := s.readyUsers(ctx, tool)
	if err != nil {
		return nil, directory.User{}, err
	}
	u, err := users.SetEnabled(ctx, p, directory.UserID(in.ID), enabled, directory.Revision(in.Revision))
	if err != nil {
		return nil, directory.User{}, publicToolErr(err)
	}
	return toolResult(ctx), u, nil
}

func (s *Server) callAccountMut(ctx context.Context, tool string, in RevisionIDInput, fn func(*app.Users, app.Principal) (directory.AccountState, error)) (*mcp.CallToolResult, directory.AccountState, error) {
	p, users, err := s.readyUsers(ctx, tool)
	if err != nil {
		return nil, directory.AccountState{}, err
	}
	st, err := fn(users, p)
	if err != nil {
		return nil, directory.AccountState{}, publicToolErr(err)
	}
	return toolResult(ctx), st, nil
}

func (s *Server) callCreateGroup(ctx context.Context, _ *mcp.CallToolRequest, in directory.GroupSpec) (*mcp.CallToolResult, directory.Group, error) {
	p, groups, err := s.readyGroups(ctx, ToolCreateGroup)
	if err != nil {
		return nil, directory.Group{}, err
	}
	g, err := groups.Create(ctx, p, in)
	if err != nil {
		return nil, directory.Group{}, publicToolErr(err)
	}
	return toolResult(ctx), g, nil
}

func (s *Server) callDeleteGroup(ctx context.Context, _ *mcp.CallToolRequest, in DeleteInput) (*mcp.CallToolResult, IDResult, error) {
	p, groups, err := s.readyGroups(ctx, ToolDeleteGroup)
	if err != nil {
		return nil, IDResult{}, err
	}
	if err := requireConfirm(in.Confirm); err != nil {
		return nil, IDResult{}, err
	}
	if err := groups.Delete(ctx, p, directory.GroupID(in.ID), directory.Revision(in.Revision)); err != nil {
		return nil, IDResult{}, publicToolErr(err)
	}
	return toolResult(ctx), IDResult{ID: in.ID}, nil
}

func (s *Server) callAddMembers(ctx context.Context, _ *mcp.CallToolRequest, in MembersInput) (*mcp.CallToolResult, directory.MembershipSummary, error) {
	return s.callMembers(ctx, ToolAddMembers, in, func(g *app.Groups, p app.Principal) (directory.MembershipSummary, error) {
		return g.AddMembers(ctx, p, directory.GroupID(in.ID), in.Members, directory.Revision(in.Revision))
	})
}

func (s *Server) callRemoveMembers(ctx context.Context, _ *mcp.CallToolRequest, in MembersInput) (*mcp.CallToolResult, directory.MembershipSummary, error) {
	return s.callMembers(ctx, ToolRemoveMembers, in, func(g *app.Groups, p app.Principal) (directory.MembershipSummary, error) {
		return g.RemoveMembers(ctx, p, directory.GroupID(in.ID), in.Members, directory.Revision(in.Revision))
	})
}

func (s *Server) callReplaceMembers(ctx context.Context, _ *mcp.CallToolRequest, in MembersInput) (*mcp.CallToolResult, directory.MembershipSummary, error) {
	return s.callMembers(ctx, ToolReplaceMembers, in, func(g *app.Groups, p app.Principal) (directory.MembershipSummary, error) {
		return g.ReplaceMembers(ctx, p, directory.GroupID(in.ID), in.Members, directory.Revision(in.Revision))
	})
}

func (s *Server) callMembers(ctx context.Context, tool string, _ MembersInput, fn func(*app.Groups, app.Principal) (directory.MembershipSummary, error)) (*mcp.CallToolResult, directory.MembershipSummary, error) {
	p, groups, err := s.readyGroups(ctx, tool)
	if err != nil {
		return nil, directory.MembershipSummary{}, err
	}
	sum, err := fn(groups, p)
	if err != nil {
		return nil, directory.MembershipSummary{}, publicToolErr(err)
	}
	return toolResult(ctx), sum, nil
}

func (s *Server) callListSuffixes(ctx context.Context, _ *mcp.CallToolRequest, _ emptyInput) (*mcp.CallToolResult, directory.SuffixList, error) {
	p, entries, err := s.readyEntries(ctx, ToolListSuffixes)
	if err != nil {
		return nil, directory.SuffixList{}, err
	}
	out, err := entries.Suffixes(ctx, p)
	if err != nil {
		return nil, directory.SuffixList{}, publicToolErr(err)
	}
	return toolResult(ctx), out, nil
}

func (s *Server) callListTree(ctx context.Context, _ *mcp.CallToolRequest, in directory.TreeQuery) (*mcp.CallToolResult, directory.TreePage, error) {
	p, entries, err := s.readyEntries(ctx, ToolListTree)
	if err != nil {
		return nil, directory.TreePage{}, err
	}
	page, err := entries.ListTree(ctx, p, in)
	if err != nil {
		return nil, directory.TreePage{}, publicToolErr(err)
	}
	if page.Nodes == nil {
		page.Nodes = []directory.TreeNode{}
	}
	return toolResult(ctx), page, nil
}

func (s *Server) callCreateEntry(ctx context.Context, _ *mcp.CallToolRequest, in directory.EntrySpec) (*mcp.CallToolResult, directory.DirectoryEntry, error) {
	p, entries, err := s.readyEntries(ctx, ToolCreateEntry)
	if err != nil {
		return nil, directory.DirectoryEntry{}, err
	}
	ent, err := entries.Create(ctx, p, in)
	if err != nil {
		return nil, directory.DirectoryEntry{}, publicToolErr(err)
	}
	return toolResult(ctx), ent, nil
}

func (s *Server) callUpdateEntry(ctx context.Context, _ *mcp.CallToolRequest, in UpdateEntryInput) (*mcp.CallToolResult, directory.DirectoryEntry, error) {
	p, entries, err := s.readyEntries(ctx, ToolUpdateEntry)
	if err != nil {
		return nil, directory.DirectoryEntry{}, err
	}
	ent, err := entries.Update(ctx, p, directory.EntryPatch{
		DN: in.DN, Revision: directory.Revision(in.Revision), Changes: in.Changes,
	})
	if err != nil {
		return nil, directory.DirectoryEntry{}, publicToolErr(err)
	}
	return toolResult(ctx), ent, nil
}

func (s *Server) callDeleteEntry(ctx context.Context, _ *mcp.CallToolRequest, in DeleteEntryInput) (*mcp.CallToolResult, IDResult, error) {
	p, entries, err := s.readyEntries(ctx, ToolDeleteEntry)
	if err != nil {
		return nil, IDResult{}, err
	}
	if err := requireConfirm(in.Confirm); err != nil {
		return nil, IDResult{}, err
	}
	if err := entries.Delete(ctx, p, directory.EntryDelete{
		DN: in.DN, Revision: directory.Revision(in.Revision), Confirm: in.Confirm, Recursive: in.Recursive,
	}); err != nil {
		return nil, IDResult{}, publicToolErr(err)
	}
	return toolResult(ctx), IDResult{ID: in.DN}, nil
}

func (s *Server) callMoveEntry(ctx context.Context, _ *mcp.CallToolRequest, in MoveEntryInput) (*mcp.CallToolResult, directory.DirectoryEntry, error) {
	p, entries, err := s.readyEntries(ctx, ToolMoveEntry)
	if err != nil {
		return nil, directory.DirectoryEntry{}, err
	}
	ent, err := entries.Move(ctx, p, directory.EntryMove{
		DN: in.DN, NewDN: in.NewDN, Revision: directory.Revision(in.Revision), DeleteOld: in.DeleteOldRDN,
	})
	if err != nil {
		return nil, directory.DirectoryEntry{}, publicToolErr(err)
	}
	return toolResult(ctx), ent, nil
}

func (s *Server) callBindTest(ctx context.Context, _ *mcp.CallToolRequest, in BindTestInput) (*mcp.CallToolResult, directory.BindTestResult, error) {
	p, q, err := s.ready(ctx, ToolBindTest)
	if err != nil {
		return nil, directory.BindTestResult{}, err
	}
	if q == nil {
		return nil, directory.BindTestResult{}, directoryUnavailable()
	}
	transport, err := parseBindTransport(in.Transport)
	if err != nil {
		return nil, directory.BindTestResult{}, err
	}
	identity := strings.TrimSpace(in.Identity)
	pw := observability.Secret(in.Password)
	in.Password = ""
	if identity == "" {
		return nil, directory.BindTestResult{}, apperr.New(apperr.CodeConfiguration, "identity is required").WithField(apperr.Field{
			Path: "identity", Code: "empty", Message: "identity is required",
		})
	}
	res, err := q.BindTest(ctx, p, identity, pw, transport)
	if diagnosticOutcome(res.Outcome) {
		return toolResult(ctx), res, nil
	}
	if err != nil {
		return nil, directory.BindTestResult{}, publicToolErr(err)
	}
	return toolResult(ctx), res, nil
}

func (s *Server) callResetSuffix(ctx context.Context, _ *mcp.CallToolRequest, in ResetSuffixInput) (*mcp.CallToolResult, app.ResetStatus, error) {
	p, rst, err := s.readyReset(ctx, ToolResetSuffix)
	if err != nil {
		return nil, app.ResetStatus{}, err
	}
	if err := requireConfirm(in.Confirm); err != nil {
		return nil, app.ResetStatus{}, err
	}
	st, err := rst.Start(ctx, p, app.ResetRequest{Name: in.Name, ExpectedRevision: in.ExpectedRevision})
	if err != nil {
		return nil, st, publicToolErr(err)
	}
	return toolResult(ctx), st, nil
}

func (s *Server) callExportLDIF(ctx context.Context, _ *mcp.CallToolRequest, in ExportLDIFInput) (*mcp.CallToolResult, ExportLDIFOutput, error) {
	p, exp, err := s.readyExport(ctx, ToolExportLDIF)
	if err != nil {
		return nil, ExportLDIFOutput{}, err
	}
	var buf bytes.Buffer
	req := app.ExportRequest{OmitSecrets: in.OmitSecrets, MaxBytes: mcpExportCeiling}
	err = exp.Write(ctx, p, &buf, req)
	if exportLimit(err) {
		return toolResult(ctx), ExportLDIFOutput{Handoff: exportHandoff}, nil
	}
	if err != nil {
		return nil, ExportLDIFOutput{}, publicToolErr(err)
	}
	return toolResult(ctx), ExportLDIFOutput{LDIF: buf.String(), Bytes: buf.Len()}, nil
}

func (s *Server) ready(ctx context.Context, tool string) (app.Principal, *app.Query, error) {
	p, err := s.principal(ctx)
	if err != nil {
		return app.Principal{}, nil, err
	}
	s.logTool(ctx, tool, p)
	q, err := s.query()
	if err != nil {
		return app.Principal{}, nil, err
	}
	return p, q, nil
}

func (s *Server) readyUsers(ctx context.Context, tool string) (app.Principal, *app.Users, error) {
	p, err := s.principal(ctx)
	if err != nil {
		return app.Principal{}, nil, err
	}
	s.logTool(ctx, tool, p)
	if s == nil || s.svc == nil || s.svc.Users == nil {
		return app.Principal{}, nil, directoryUnavailable()
	}
	return p, s.svc.Users, nil
}

func (s *Server) readyGroups(ctx context.Context, tool string) (app.Principal, *app.Groups, error) {
	p, err := s.principal(ctx)
	if err != nil {
		return app.Principal{}, nil, err
	}
	s.logTool(ctx, tool, p)
	if s == nil || s.svc == nil || s.svc.Groups == nil {
		return app.Principal{}, nil, directoryUnavailable()
	}
	return p, s.svc.Groups, nil
}

func (s *Server) readyEntries(ctx context.Context, tool string) (app.Principal, *app.Entries, error) {
	p, err := s.principal(ctx)
	if err != nil {
		return app.Principal{}, nil, err
	}
	s.logTool(ctx, tool, p)
	if s == nil || s.svc == nil || s.svc.Entries == nil {
		return app.Principal{}, nil, directoryUnavailable()
	}
	return p, s.svc.Entries, nil
}

func (s *Server) readyReset(ctx context.Context, tool string) (app.Principal, *app.Reset, error) {
	p, err := s.principal(ctx)
	if err != nil {
		return app.Principal{}, nil, err
	}
	s.logTool(ctx, tool, p)
	if s == nil || s.svc == nil || s.svc.Reset == nil {
		return app.Principal{}, nil, directoryUnavailable()
	}
	return p, s.svc.Reset, nil
}

func (s *Server) readyExport(ctx context.Context, tool string) (app.Principal, *app.Export, error) {
	p, err := s.principal(ctx)
	if err != nil {
		return app.Principal{}, nil, err
	}
	s.logTool(ctx, tool, p)
	if s == nil || s.svc == nil || s.svc.Export == nil {
		return app.Principal{}, nil, directoryUnavailable()
	}
	return p, s.svc.Export, nil
}

func exportLimit(err error) bool {
	if apperr.CodeOf(err) != apperr.CodeExport {
		return false
	}
	var e *apperr.Error
	if !errors.As(err, &e) {
		return false
	}
	for _, f := range e.Fields() {
		if f.Code == "limit" {
			return true
		}
	}
	return false
}

func requireConfirm(ok bool) error {
	if ok {
		return nil
	}
	return apperr.New(apperr.CodeConfiguration, "confirmation is required").WithField(apperr.Field{
		Path: "confirm", Code: "required", Message: "confirm must be true",
	})
}

func parseBindTransport(raw string) (directory.Transport, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "", nil
	case string(directory.TransportLDAP):
		return directory.TransportLDAP, nil
	case string(directory.TransportLDAPS):
		return directory.TransportLDAPS, nil
	case string(directory.TransportStartTLS):
		return directory.TransportStartTLS, nil
	default:
		return "", apperr.New(apperr.CodeConfiguration, "unknown bind transport").WithField(apperr.Field{
			Path: "transport", Code: "invalid", Message: "unknown bind transport",
		})
	}
}

func diagnosticOutcome(outcome string) bool {
	switch outcome {
	case directory.BindOutcomeInvalidCredentials, directory.BindOutcomeLocked, directory.BindOutcomeDisabled, directory.BindOutcomeMustChange:
		return true
	default:
		return false
	}
}

func publicToolErr(err error) error {
	if err == nil {
		return nil
	}
	msg := apperr.PublicMessageOf(err)
	if msg == "" {
		msg = "tool failed"
	}
	var e *apperr.Error
	if errors.As(err, &e) {
		for _, f := range e.Fields() {
			// Missing-scope errors name the required grant (Field.Message),
			// never a token ID. REST returns the same field.
			if (f.Path == "scope" || f.Code == "forbidden") && f.Message != "" {
				return errors.New(msg + " (" + f.Message + ")")
			}
			if f.Code != "" {
				return errors.New(msg + " (" + f.Code + ")")
			}
		}
	}
	return errors.New(msg)
}

func normalizePage(page directory.SearchPage) directory.SearchPage {
	if page.Entries == nil {
		page.Entries = []directory.SearchEntry{}
	}
	return page
}

func toolResult(ctx context.Context) *mcp.CallToolResult {
	return &mcp.CallToolResult{Meta: requestMeta(ctx)}
}

func (s *Server) registerResources(ms *mcp.Server) {
	ms.AddResource(&mcp.Resource{
		URI: resourceCapabilities, Name: "capabilities", MIMEType: mimeJSON,
		Description: "Measured engine capabilities.",
	}, s.readResource)
	ms.AddResource(&mcp.Resource{
		URI: resourceBaseline, Name: "baseline", MIMEType: mimeJSON,
		Description: "Compiled versus applied baseline revisions.",
	}, s.readResource)
	ms.AddResource(&mcp.Resource{
		URI: resourceRootDSE, Name: "rootdse", MIMEType: mimeJSON,
		Description: "Root DSE.",
	}, s.readResource)
	ms.AddResource(&mcp.Resource{
		URI: resourceSchema, Name: "schema", MIMEType: mimeJSON,
		Description: "Directory schema.",
	}, s.readResource)
	ms.AddResourceTemplate(&mcp.ResourceTemplate{
		URITemplate: templateObjectClass, Name: "objectclass", MIMEType: mimeJSON,
		Description: "One object class by name.",
	}, s.readResource)
	ms.AddResourceTemplate(&mcp.ResourceTemplate{
		URITemplate: templateAttribute, Name: "attribute", MIMEType: mimeJSON,
		Description: "One attribute type by name.",
	}, s.readResource)
	ms.AddResourceTemplate(&mcp.ResourceTemplate{
		URITemplate: templateEntry, Name: "entry", MIMEType: mimeJSON,
		Description: "One directory entry by DN.",
	}, s.readResource)
}

func (s *Server) readResource(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
	p, err := s.principal(ctx)
	if err != nil {
		return nil, err
	}
	q, err := s.query()
	if err != nil {
		return nil, err
	}
	uri := ""
	if req != nil && req.Params != nil {
		uri = req.Params.URI
	}
	body, err := s.resourceBody(ctx, q, p, uri)
	if err != nil {
		return nil, err
	}
	return &mcp.ReadResourceResult{
		Contents: []*mcp.ResourceContents{{
			URI:      uri,
			MIMEType: mimeJSON,
			Text:     string(body),
		}},
	}, nil
}

func (s *Server) resourceBody(ctx context.Context, q *app.Query, p app.Principal, uri string) ([]byte, error) {
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "labldap" {
		return nil, mcp.ResourceNotFoundError(uri)
	}
	host := strings.ToLower(u.Host)
	path := strings.TrimPrefix(u.EscapedPath(), "/")
	switch {
	case host == "capabilities" && path == "":
		caps, err := q.Capabilities(ctx, p)
		if err != nil {
			return nil, err
		}
		return json.Marshal(caps)
	case host == "baseline" && path == "":
		b, err := q.Baseline(ctx, p)
		if err != nil {
			return nil, err
		}
		return json.Marshal(b)
	case host == "rootdse" && path == "":
		dse, err := q.RootDSE(ctx, p)
		if err != nil {
			return nil, err
		}
		return json.Marshal(dse)
	case host == "schema" && path == "":
		sch, err := q.Schema(ctx, p)
		if err != nil {
			return nil, err
		}
		return json.Marshal(sch)
	case host == "schema" && strings.HasPrefix(path, "objectclass/"):
		name, _ := url.PathUnescape(strings.TrimPrefix(path, "objectclass/"))
		return lookupObjectClass(ctx, q, p, name)
	case host == "schema" && strings.HasPrefix(path, "attribute/"):
		name, _ := url.PathUnescape(strings.TrimPrefix(path, "attribute/"))
		return lookupAttribute(ctx, q, p, name)
	case host == "entry":
		entry, err := q.GetEntry(ctx, p, u.Query().Get("dn"), nil)
		if err != nil {
			return nil, err
		}
		return json.Marshal(entry)
	default:
		return nil, mcp.ResourceNotFoundError(uri)
	}
}

func lookupObjectClass(ctx context.Context, q *app.Query, p app.Principal, name string) ([]byte, error) {
	sch, err := q.Schema(ctx, p)
	if err != nil {
		return nil, err
	}
	for _, oc := range sch.ObjectClasses {
		if strings.EqualFold(oc.Name, name) {
			return json.Marshal(oc)
		}
	}
	return nil, mcp.ResourceNotFoundError("labldap://schema/objectclass/" + name)
}

func lookupAttribute(ctx context.Context, q *app.Query, p app.Principal, name string) ([]byte, error) {
	sch, err := q.Schema(ctx, p)
	if err != nil {
		return nil, err
	}
	for _, at := range sch.Attributes {
		if strings.EqualFold(at.Name, name) {
			return json.Marshal(at)
		}
	}
	return nil, mcp.ResourceNotFoundError("labldap://schema/attribute/" + name)
}
