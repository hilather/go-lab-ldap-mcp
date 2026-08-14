package api

import (
	"net/http"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

func (s *Server) handleRootDSE(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireScope(w, r, auth.ScopeSchemaRead)
	if !ok || !s.requireQuery(w, r) {
		return
	}
	dse, err := s.query.RootDSE(r.Context(), p)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	setNoStore(w)
	writeJSON(w, r, http.StatusOK, "application/json", rootDSEView(dse))
}

func (s *Server) handleSchema(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireScope(w, r, auth.ScopeSchemaRead)
	if !ok || !s.requireQuery(w, r) {
		return
	}
	sch, err := s.query.Schema(r.Context(), p)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	setNoStore(w)
	writeJSON(w, r, http.StatusOK, "application/json", schemaView(sch))
}

func (s *Server) handleObjectClass(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireScope(w, r, auth.ScopeSchemaRead)
	if !ok || !s.requireQuery(w, r) {
		return
	}
	oc, err := s.query.ObjectClass(r.Context(), p, pathName(r))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	setNoStore(w)
	writeJSON(w, r, http.StatusOK, "application/json", objectClassView(oc))
}

func (s *Server) handleAttributeType(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireScope(w, r, auth.ScopeSchemaRead)
	if !ok || !s.requireQuery(w, r) {
		return
	}
	at, err := s.query.AttributeType(r.Context(), p, pathName(r))
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	setNoStore(w)
	writeJSON(w, r, http.StatusOK, "application/json", at)
}

func pathName(r *http.Request) string {
	if r == nil {
		return ""
	}
	return strings.TrimSpace(r.PathValue("name"))
}

func rootDSEView(d directory.RootDSE) directory.RootDSE {
	if d.NamingContexts == nil {
		d.NamingContexts = []string{}
	}
	if d.SupportedControls == nil {
		d.SupportedControls = []string{}
	}
	if d.SupportedSASL == nil {
		d.SupportedSASL = []string{}
	}
	return d
}

func schemaView(s directory.Schema) directory.Schema {
	if s.ObjectClasses == nil {
		s.ObjectClasses = []directory.ObjectClass{}
	}
	if s.Attributes == nil {
		s.Attributes = []directory.AttributeType{}
	}
	for i := range s.ObjectClasses {
		s.ObjectClasses[i] = objectClassView(s.ObjectClasses[i])
	}
	return s
}

func objectClassView(oc directory.ObjectClass) directory.ObjectClass {
	if oc.Must == nil {
		oc.Must = []string{}
	}
	if oc.May == nil {
		oc.May = []string{}
	}
	if oc.Sup == nil {
		oc.Sup = []string{}
	}
	return oc
}
