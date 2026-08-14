package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/audit"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

func apperrCursorInvalid() error {
	return apperr.New(apperr.CodeConfiguration, "cursor is invalid").WithField(apperr.Field{
		Path: "cursor", Code: "invalid", Message: "cursor is invalid",
	})
}

type auditEventBody struct {
	Time      string             `json:"time"`
	Action    string             `json:"action"`
	Actor     string             `json:"actor"`
	Target    string             `json:"target"`
	Result    string             `json:"result"`
	RequestID string             `json:"requestId"`
	Revisions auditRevisionsBody `json:"revisions"`
}

type auditRevisionsBody struct {
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireScope(w, r, auth.ScopeAuditRead); !ok {
		return
	}
	if s.audit == nil {
		writeList(w, r, []auditEventBody{}, "")
		return
	}
	page, err := s.parsePageParams(r)
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	action := ""
	actor := ""
	if r.URL != nil {
		action = r.URL.Query().Get("action")
		actor = r.URL.Query().Get("actor")
	}
	queryKey := "audit|" + action + "|" + actor
	cur, err := DecodeCursor(s.cursorKey, page.Cursor, queryKey, time.Now())
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	var after uint64
	if cur.Page != "" {
		after, err = strconv.ParseUint(cur.Page, 10, 64)
		if err != nil {
			writeProblem(w, r, apperrCursorInvalid())
			return
		}
	}
	out, err := s.audit.List(r.Context(), audit.ListQuery{
		Action:   action,
		Actor:    actor,
		PageSize: page.PageSize,
		AfterSeq: after,
	})
	if err != nil {
		writeProblem(w, r, err)
		return
	}
	next := ""
	if out.HasMore && out.NextSeq != 0 {
		next, err = EncodeCursor(s.cursorKey, config.Cursor{Query: queryKey, Page: strconv.FormatUint(out.NextSeq, 10)}, time.Now())
		if err != nil {
			writeProblem(w, r, err)
			return
		}
	}
	items := make([]auditEventBody, 0, len(out.Items))
	for _, ev := range out.Items {
		items = append(items, auditView(ev))
	}
	writeList(w, r, items, next)
}

func auditView(ev audit.Event) auditEventBody {
	t := ev.Time.UTC()
	if t.IsZero() {
		t = time.Now().UTC()
	}
	return auditEventBody{
		Time:      t.Format(time.RFC3339),
		Action:    ev.Action,
		Actor:     ev.Actor,
		Target:    ev.Target,
		Result:    ev.Result,
		RequestID: ev.RequestID,
		Revisions: auditRevisionsBody{Before: ev.Revisions.Before, After: ev.Revisions.After},
	}
}

func (s *Server) emitAudit(r *http.Request, action, actor, target, result string) {
	if s == nil || s.auditHook == nil || r == nil {
		return
	}
	s.auditHook.Emit(r.Context(), audit.Event{
		Time:      time.Now().UTC(),
		RequestID: requestIDOf(r),
		Actor:     actor,
		Action:    action,
		Target:    target,
		Result:    result,
	})
}
