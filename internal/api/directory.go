package api

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

var (
	_ Users  = (*app.Users)(nil)
	_ Groups = (*app.Groups)(nil)
	_ Query  = (*app.Query)(nil)
	_ Reset  = (*app.Reset)(nil)
	_ Export = (*app.Export)(nil)
)

// Users is the application user surface. *app.Users implements it.
type Users interface {
	List(ctx context.Context, p app.Principal, q directory.UserListQuery) (directory.UserPage, error)
	Get(ctx context.Context, p app.Principal, id directory.UserID) (directory.User, error)
	Create(ctx context.Context, p app.Principal, spec app.CreateUser) (directory.User, error)
	Update(ctx context.Context, p app.Principal, id directory.UserID, patch app.UpdateUser) (directory.User, error)
	Delete(ctx context.Context, p app.Principal, id directory.UserID, rev directory.Revision) error
	SetEnabled(ctx context.Context, p app.Principal, id directory.UserID, enabled bool, rev directory.Revision) (directory.User, error)
	SetPassword(ctx context.Context, p app.Principal, id directory.UserID, pw app.Secret, rev directory.Revision) error
}

// Query is the application search, bind-test, and schema surface.
// *app.Query implements it.
type Query interface {
	Search(ctx context.Context, p app.Principal, q directory.SearchQuery) (directory.SearchPage, error)
	BindTest(ctx context.Context, p app.Principal, identity string, password app.Secret, transport directory.Transport) (directory.BindTestResult, error)
	RootDSE(ctx context.Context, p app.Principal) (directory.RootDSE, error)
	Schema(ctx context.Context, p app.Principal) (directory.Schema, error)
	ObjectClass(ctx context.Context, p app.Principal, name string) (directory.ObjectClass, error)
	AttributeType(ctx context.Context, p app.Principal, name string) (directory.AttributeType, error)
}

// Groups is the application group surface. *app.Groups implements it.
// v1 has no group attribute Modify.
type Groups interface {
	List(ctx context.Context, p app.Principal, q directory.GroupListQuery) (directory.GroupPage, error)
	Get(ctx context.Context, p app.Principal, id directory.GroupID) (directory.Group, error)
	Create(ctx context.Context, p app.Principal, spec directory.GroupSpec) (directory.Group, error)
	Delete(ctx context.Context, p app.Principal, id directory.GroupID, rev directory.Revision) error
	AddMembers(ctx context.Context, p app.Principal, id directory.GroupID, members []directory.MemberRef, rev directory.Revision) (directory.MembershipSummary, error)
	RemoveMembers(ctx context.Context, p app.Principal, id directory.GroupID, members []directory.MemberRef, rev directory.Revision) (directory.MembershipSummary, error)
	ReplaceMembers(ctx context.Context, p app.Principal, id directory.GroupID, members []directory.MemberRef, rev directory.Revision) (directory.MembershipSummary, error)
}

func (s *Server) requireUsers(w http.ResponseWriter, r *http.Request) bool {
	if s == nil || s.users == nil {
		writeProblemStatus(w, r, http.StatusServiceUnavailable, "directory", "not ready", nil)
		return false
	}
	return true
}

func (s *Server) requireGroups(w http.ResponseWriter, r *http.Request) bool {
	if s == nil || s.groups == nil {
		writeProblemStatus(w, r, http.StatusServiceUnavailable, "directory", "not ready", nil)
		return false
	}
	return true
}

func (s *Server) requireQuery(w http.ResponseWriter, r *http.Request) bool {
	if s == nil || s.query == nil {
		writeProblemStatus(w, r, http.StatusServiceUnavailable, "directory", "not ready", nil)
		return false
	}
	return true
}

func pathID(r *http.Request) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(r.PathValue("id"))
}

func requireJSONBody(w http.ResponseWriter, r *http.Request) bool {
	if isJSON(r) {
		return true
	}
	writeProblemStatus(w, r, http.StatusUnsupportedMediaType, "configuration", "content type must be application/json", nil)
	return false
}

func writeCreated(w http.ResponseWriter, r *http.Request, location string, rev directory.Revision, v any) {
	if location != "" {
		w.Header().Set("Location", location)
	}
	setNoStore(w)
	SetETag(w, rev)
	writeJSON(w, r, http.StatusCreated, "application/json", v)
}

func writeEntity(w http.ResponseWriter, r *http.Request, rev directory.Revision, v any) {
	setNoStore(w)
	SetETag(w, rev)
	writeJSON(w, r, http.StatusOK, "application/json", v)
}

func userResource(id string) string {
	return "/api/v1/users/" + url.PathEscape(id)
}

func groupResource(id string) string {
	return "/api/v1/groups/" + url.PathEscape(id)
}

func userView(u directory.User) directory.User {
	if u.ObjectClasses == nil {
		u.ObjectClasses = []string{}
	}
	if u.Attributes == nil {
		u.Attributes = []directory.AttrKV{}
	}
	return u
}

func groupView(g directory.Group) directory.Group {
	if g.Members == nil {
		g.Members = []directory.MemberRef{}
	}
	return g
}

func membershipView(s directory.MembershipSummary) directory.MembershipSummary {
	if s.Added == nil {
		s.Added = []directory.MemberRef{}
	}
	if s.Removed == nil {
		s.Removed = []directory.MemberRef{}
	}
	if s.Unchanged == nil {
		s.Unchanged = []directory.MemberRef{}
	}
	if s.Rejected == nil {
		s.Rejected = []directory.MemberRef{}
	}
	return s
}

func userViews(in []directory.User) []directory.User {
	if in == nil {
		return []directory.User{}
	}
	out := make([]directory.User, len(in))
	for i, u := range in {
		out[i] = userView(u)
	}
	return out
}

func groupViews(in []directory.Group) []directory.Group {
	if in == nil {
		return []directory.Group{}
	}
	out := make([]directory.Group, len(in))
	for i, g := range in {
		out[i] = groupView(g)
	}
	return out
}
