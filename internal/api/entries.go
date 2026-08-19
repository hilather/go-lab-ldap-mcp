package api

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

type entrySpecBody struct {
	DN            string            `json:"dn"`
	ObjectClasses []string          `json:"objectClasses"`
	Attributes    map[string]string `json:"attributes,omitempty"`
}

type entryPatchBody struct {
	Changes []directory.EntryChange `json:"changes"`
}

type entryMoveBody struct {
	DN           string `json:"dn"`
	NewDN        string `json:"newDN"`
	DeleteOldRDN bool   `json:"deleteOldRdn"`
}

type treeQueryBody struct {
	Base     string `json:"base"`
	PageSize int    `json:"pageSize,omitempty"`
	Cursor   string `json:"cursor,omitempty"`
}

func (s *Server) handleListSuffixes(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireScope(w, r, auth.ScopeDirectoryRead)
	if !ok || !s.requireEntries(w, r) {
		return
	}
	out, err := s.entries.Suffixes(r.Context(), p)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	if out.Additional == nil {
		out.Additional = []string{}
	}
	if out.All == nil {
		out.All = []string{}
	}
	setNoStore(w)
	writeJSON(w, r, http.StatusOK, "application/json", out)
}

func (s *Server) handleListTree(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireScope(w, r, auth.ScopeDirectoryRead)
	if !ok || !s.requireEntries(w, r) || !requireJSONBody(w, r) {
		return
	}
	var body treeQueryBody
	if err := DecodeJSON(r.Body, &body); err != nil {
		writeProblem(w, r, err)
		return
	}
	page, err := s.searchPageSize(body.PageSize)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	out, err := s.entries.ListTree(r.Context(), p, directory.TreeQuery{
		Base: body.Base, PageSize: page, Cursor: body.Cursor,
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	if out.Nodes == nil {
		out.Nodes = []directory.TreeNode{}
	}
	setNoStore(w)
	writeJSON(w, r, http.StatusOK, "application/json", out)
}

func (s *Server) handleGetEntry(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireScope(w, r, auth.ScopeDirectoryRead)
	if !ok || !s.requireEntries(w, r) {
		return
	}
	dn := strings.TrimSpace(r.URL.Query().Get("dn"))
	ent, err := s.entries.Get(r.Context(), p, dn)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeEntity(w, r, ent.Revision, entryView(ent))
}

func (s *Server) handleCreateEntry(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireScope(w, r, auth.ScopeDirectoryWrite)
	if !ok || !s.requireEntries(w, r) || !requireJSONBody(w, r) {
		return
	}
	var body entrySpecBody
	if err := DecodeJSON(r.Body, &body); err != nil {
		writeProblem(w, r, err)
		return
	}
	ent, err := s.entries.Create(r.Context(), p, directory.EntrySpec{
		DN: body.DN, ObjectClasses: body.ObjectClasses, Attributes: body.Attributes,
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	view := entryView(ent)
	writeCreated(w, r, entryResource(view.DN), view.Revision, view)
}

func (s *Server) handleUpdateEntry(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireScope(w, r, auth.ScopeDirectoryWrite)
	if !ok || !s.requireEntries(w, r) || !requireJSONBody(w, r) {
		return
	}
	rev, err := RequireIfMatch(r)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	var body entryPatchBody
	if err := DecodeJSON(r.Body, &body); err != nil {
		writeProblem(w, r, err)
		return
	}
	ent, err := s.entries.Update(r.Context(), p, directory.EntryPatch{
		DN: strings.TrimSpace(r.URL.Query().Get("dn")), Revision: rev, Changes: body.Changes,
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	view := entryView(ent)
	writeEntity(w, r, view.Revision, view)
}

func (s *Server) handleDeleteEntry(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireScope(w, r, auth.ScopeDirectoryWrite)
	if !ok || !s.requireEntries(w, r) {
		return
	}
	rev, err := RequireIfMatch(r)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	q := r.URL.Query()
	if err := s.entries.Delete(r.Context(), p, directory.EntryDelete{
		DN:        strings.TrimSpace(q.Get("dn")),
		Revision:  rev,
		Confirm:   queryBool(q.Get("confirm")),
		Recursive: queryBool(q.Get("recursive")),
	}); err != nil {
		writeProblem(w, r, err)
		return
	}
	writeNoContent(w, r)
}

func (s *Server) handleMoveEntry(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireScope(w, r, auth.ScopeDirectoryWrite)
	if !ok || !s.requireEntries(w, r) || !requireJSONBody(w, r) {
		return
	}
	rev, err := RequireIfMatch(r)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	var body entryMoveBody
	if err := DecodeJSON(r.Body, &body); err != nil {
		writeProblem(w, r, err)
		return
	}
	ent, err := s.entries.Move(r.Context(), p, directory.EntryMove{
		DN: body.DN, NewDN: body.NewDN, Revision: rev, DeleteOld: body.DeleteOldRDN,
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	view := entryView(ent)
	writeEntity(w, r, view.Revision, view)
}

func queryBool(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

func entryResource(dn string) string {
	return "/api/v1/entries?dn=" + url.QueryEscape(dn)
}

func entryView(e directory.DirectoryEntry) directory.DirectoryEntry {
	if e.ObjectClasses == nil {
		e.ObjectClasses = []string{}
	}
	if e.Attributes == nil {
		e.Attributes = []directory.AttrKV{}
	}
	return e
}
