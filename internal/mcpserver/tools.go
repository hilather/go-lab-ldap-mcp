package mcpserver

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

func (s *Server) registerReadTools(ms *mcp.Server) {
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
		return nil, directory.SearchPage{}, err
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
		return nil, directory.Capabilities{}, err
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
		return nil, app.Baseline{}, err
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
		return nil, directory.SearchEntry{}, err
	}
	return toolResult(ctx), entry, nil
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
