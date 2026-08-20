package api

import (
	"context"
	"net/http"

	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

type groupSpecBody struct {
	ID       string                `json:"id"`
	DN       string                `json:"dn,omitempty"`
	ParentDN string                `json:"parentDN,omitempty"`
	Members  []directory.MemberRef `json:"members"`
}

type memberListBody struct {
	Members []directory.MemberRef `json:"members"`
}

type memberWrite func(ctx context.Context, p app.Principal, id directory.GroupID, members []directory.MemberRef, rev directory.Revision) (directory.MembershipSummary, error)

func (s *Server) handleListGroups(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireScope(w, r, auth.ScopeDirectoryRead)
	if !ok || !s.requireGroups(w, r) {
		return
	}
	page, err := s.parsePageParams(r)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	q := directory.GroupListQuery{PageSize: page.PageSize, Cursor: page.Cursor}
	if r.URL != nil {
		q.Q = r.URL.Query().Get("q")
	}
	out, err := s.groups.List(r.Context(), p, q)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeList(w, r, groupViews(out.Items), out.NextCursor)
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireScope(w, r, auth.ScopeDirectoryWrite)
	if !ok || !s.requireGroups(w, r) || !requireJSONBody(w, r) {
		return
	}
	var body groupSpecBody
	if err := DecodeJSON(r.Body, &body); err != nil {
		writeProblem(w, r, err)
		return
	}
	g, err := s.groups.Create(r.Context(), p, directory.GroupSpec{ID: body.ID, DN: body.DN, ParentDN: body.ParentDN, Members: body.Members})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	view := groupView(g)
	writeCreated(w, r, groupResource(view.ID), view.Revision, view)
}

func (s *Server) handleGetGroup(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireScope(w, r, auth.ScopeDirectoryRead)
	if !ok || !s.requireGroups(w, r) {
		return
	}
	g, err := s.groups.Get(r.Context(), p, directory.GroupID(pathID(r)))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	view := groupView(g)
	writeEntity(w, r, view.Revision, view)
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireScope(w, r, auth.ScopeDirectoryWrite)
	if !ok || !s.requireGroups(w, r) {
		return
	}
	rev, err := RequireIfMatch(r)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	if err := s.groups.Delete(r.Context(), p, directory.GroupID(pathID(r)), rev); err != nil {
		writeProblem(w, r, err)
		return
	}
	writeNoContent(w, r)
}

func (s *Server) handleAddGroupMembers(w http.ResponseWriter, r *http.Request) {
	s.handleMemberWrite(w, r, func(g Groups) memberWrite { return g.AddMembers })
}

func (s *Server) handleRemoveGroupMembers(w http.ResponseWriter, r *http.Request) {
	s.handleMemberWrite(w, r, func(g Groups) memberWrite { return g.RemoveMembers })
}

func (s *Server) handleReplaceGroupMembers(w http.ResponseWriter, r *http.Request) {
	s.handleMemberWrite(w, r, func(g Groups) memberWrite { return g.ReplaceMembers })
}

func (s *Server) handleMemberWrite(w http.ResponseWriter, r *http.Request, bind func(Groups) memberWrite) {
	p, ok := s.requireScope(w, r, auth.ScopeDirectoryWrite)
	if !ok || !s.requireGroups(w, r) || !requireJSONBody(w, r) {
		return
	}
	rev, err := RequireIfMatch(r)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	var body memberListBody
	if err := DecodeJSON(r.Body, &body); err != nil {
		writeProblem(w, r, err)
		return
	}
	sum, err := bind(s.groups)(r.Context(), p, directory.GroupID(pathID(r)), body.Members, rev)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	view := membershipView(sum)
	writeEntity(w, r, view.Revision, view)
}
