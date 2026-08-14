package mcpserver

import (
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
		case ToolBindTest:
			mcp.AddTool(ms, toolMeta(d), s.callBindTest)
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
		ID: in.ID, UID: in.UID, Enabled: in.Enabled,
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
	if err := users.SetPassword(ctx, p, directory.UserID(in.ID), pw, directory.Revision(in.Revision)); err != nil {
		return nil, IDResult{}, publicToolErr(err)
	}
	return toolResult(ctx), IDResult{ID: in.ID}, nil
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
	case directory.BindOutcomeInvalidCredentials, directory.BindOutcomeLocked, directory.BindOutcomeDisabled:
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
