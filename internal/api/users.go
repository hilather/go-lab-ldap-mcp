package api

import (
	"context"
	"net/http"

	"github.com/hilather/go-lab-ldap-mcp/internal/app"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

type userSpecBody struct {
	ID         string               `json:"id"`
	UID        string               `json:"uid,omitempty"`
	DN         string               `json:"dn,omitempty"`
	ParentDN   string               `json:"parentDN,omitempty"`
	Enabled    *bool                `json:"enabled,omitempty"`
	Password   observability.Secret `json:"password"`
	Attributes map[string]string    `json:"attributes,omitempty"`
}

type userPatchBody struct {
	Enabled    *bool             `json:"enabled,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type passwordBody struct {
	Password   observability.Secret `json:"password"`
	Revision   string               `json:"revision"`
	MustChange bool                 `json:"mustChange"`
}

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireScope(w, r, auth.ScopeDirectoryRead)
	if !ok || !s.requireUsers(w, r) {
		return
	}
	page, err := s.parsePageParams(r)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	q := directory.UserListQuery{PageSize: page.PageSize, Cursor: page.Cursor}
	if r.URL != nil {
		q.Q = r.URL.Query().Get("q")
	}
	out, err := s.users.List(r.Context(), p, q)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeList(w, r, userViews(out.Items), out.NextCursor)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireScope(w, r, auth.ScopeDirectoryWrite)
	if !ok || !s.requireUsers(w, r) || !requireJSONBody(w, r) {
		return
	}
	var body userSpecBody
	if err := DecodeJSON(r.Body, &body); err != nil {
		writeProblem(w, r, err)
		return
	}
	spec := app.CreateUser{
		ID:         body.ID,
		UID:        body.UID,
		DN:         body.DN,
		ParentDN:   body.ParentDN,
		Enabled:    body.Enabled,
		Password:   body.Password,
		Attributes: body.Attributes,
	}
	body.Password = ""
	u, err := s.users.Create(r.Context(), p, spec)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	view := userView(u)
	writeCreated(w, r, userResource(view.ID), view.Revision, view)
}

func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireScope(w, r, auth.ScopeDirectoryRead)
	if !ok || !s.requireUsers(w, r) {
		return
	}
	u, err := s.users.Get(r.Context(), p, directory.UserID(pathID(r)))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	view := userView(u)
	writeEntity(w, r, view.Revision, view)
}

func (s *Server) handlePatchUser(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireScope(w, r, auth.ScopeDirectoryWrite)
	if !ok || !s.requireUsers(w, r) || !requireJSONBody(w, r) {
		return
	}
	rev, err := RequireIfMatch(r)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	var body userPatchBody
	if err := DecodeJSON(r.Body, &body); err != nil {
		writeProblem(w, r, err)
		return
	}
	u, err := s.users.Update(r.Context(), p, directory.UserID(pathID(r)), app.UpdateUser{
		UserPatch: directory.UserPatch{Enabled: body.Enabled, Attributes: body.Attributes},
		Revision:  rev,
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	view := userView(u)
	writeEntity(w, r, view.Revision, view)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireScope(w, r, auth.ScopeDirectoryWrite)
	if !ok || !s.requireUsers(w, r) {
		return
	}
	rev, err := RequireIfMatch(r)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	if err := s.users.Delete(r.Context(), p, directory.UserID(pathID(r)), rev); err != nil {
		writeProblem(w, r, err)
		return
	}
	writeNoContent(w, r)
}

func (s *Server) handleSetUserPassword(w http.ResponseWriter, r *http.Request) {
	// directory:write does not imply directory:password (§3.6).
	p, ok := s.requireScope(w, r, auth.ScopeDirectoryPassword)
	if !ok || !s.requireUsers(w, r) || !requireJSONBody(w, r) {
		return
	}
	var body passwordBody
	if err := DecodeJSON(r.Body, &body); err != nil {
		writeProblem(w, r, err)
		return
	}
	pw := body.Password
	rev := directory.Revision(body.Revision)
	body.Password = ""
	if err := s.users.SetPassword(r.Context(), p, directory.UserID(pathID(r)), pw, rev, body.MustChange); err != nil {
		writeProblem(w, r, err)
		return
	}
	writeNoContent(w, r)
}

func (s *Server) handleEnableUser(w http.ResponseWriter, r *http.Request) {
	s.setUserEnabled(w, r, true)
}

func (s *Server) handleDisableUser(w http.ResponseWriter, r *http.Request) {
	s.setUserEnabled(w, r, false)
}

func (s *Server) setUserEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	p, ok := s.requireScope(w, r, auth.ScopeDirectoryWrite)
	if !ok || !s.requireUsers(w, r) {
		return
	}
	// User mutations use If-Match even though enable/disable have no body.
	rev, err := RequireIfMatch(r)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	u, err := s.users.SetEnabled(r.Context(), p, directory.UserID(pathID(r)), enabled, rev)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	view := userView(u)
	writeEntity(w, r, view.Revision, view)
}

func (s *Server) handleGetAccountState(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireScope(w, r, auth.ScopeDirectoryRead)
	if !ok || !s.requireUsers(w, r) {
		return
	}
	st, err := s.users.AccountState(r.Context(), p, directory.UserID(pathID(r)))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeEntity(w, r, st.Revision, st)
}

func (s *Server) handleExpirePassword(w http.ResponseWriter, r *http.Request) {
	s.mutateAccountState(w, r, auth.ScopeDirectoryPassword, s.users.ExpirePassword)
}

func (s *Server) handleClearPasswordExpiry(w http.ResponseWriter, r *http.Request) {
	s.mutateAccountState(w, r, auth.ScopeDirectoryPassword, s.users.ClearPasswordExpiry)
}

func (s *Server) handleLockUser(w http.ResponseWriter, r *http.Request) {
	s.mutateAccountState(w, r, auth.ScopeDirectoryWrite, s.users.Lock)
}

func (s *Server) handleUnlockUser(w http.ResponseWriter, r *http.Request) {
	s.mutateAccountState(w, r, auth.ScopeDirectoryWrite, s.users.Unlock)
}

func (s *Server) mutateAccountState(w http.ResponseWriter, r *http.Request, scope string, fn func(context.Context, app.Principal, directory.UserID, directory.Revision) (directory.AccountState, error)) {
	p, ok := s.requireScope(w, r, scope)
	if !ok || !s.requireUsers(w, r) {
		return
	}
	rev, err := RequireIfMatch(r)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	st, err := fn(r.Context(), p, directory.UserID(pathID(r)), rev)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	writeEntity(w, r, st.Revision, st)
}

func (s *Server) handleListUserGroups(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireScope(w, r, auth.ScopeDirectoryRead)
	if !ok || !s.requireUsers(w, r) || !s.requireGroups(w, r) {
		return
	}
	u, err := s.users.Get(r.Context(), p, directory.UserID(pathID(r)))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	items := make([]directory.Group, 0, len(u.Groups))
	for _, gid := range u.Groups {
		g, err := s.groups.Get(r.Context(), p, gid)
		if err != nil {
			if hasFieldCode(fieldsOf(err), directory.FieldNotFound) {
				continue
			}
			writeProblem(w, r, err)
			return
		}
		items = append(items, groupView(g))
	}
	writeList(w, r, items, "")
}
