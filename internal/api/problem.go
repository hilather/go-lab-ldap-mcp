package api

import (
	"errors"
	"net/http"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

const problemTypePrefix = "https://labldap.dev/problems/"

type problemBody struct {
	Type       string            `json:"type"`
	Title      string            `json:"title"`
	Status     int               `json:"status"`
	Errors     []problemField    `json:"errors,omitempty"`
	Extensions problemExtensions `json:"extensions"`
}

type problemField struct {
	Path    string `json:"path"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type problemExtensions struct {
	RequestID string `json:"requestId"`
}

func statusFor(err error) int {
	switch apperr.CodeOf(err) {
	case apperr.CodeAuth:
		var e *apperr.Error
		if errors.As(err, &e) {
			for _, f := range e.Fields() {
				if f.Code == "forbidden" || f.Path == "csrf" || f.Path == "origin" || f.Path == "scope" {
					return http.StatusForbidden
				}
			}
		}
		return http.StatusUnauthorized
	case apperr.CodeConfiguration:
		return http.StatusBadRequest
	case apperr.CodeDirectory:
		return http.StatusBadGateway
	case apperr.CodeReset, apperr.CodeExport:
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

func writeProblem(w http.ResponseWriter, r *http.Request, err error) {
	status := statusFor(err)
	code := string(apperr.CodeOf(err))
	if code == "" {
		code = "internal"
	}
	title := apperr.PublicMessageOf(err)
	if title == "" {
		title = http.StatusText(status)
	}
	var fields []apperr.Field
	var e *apperr.Error
	if errors.As(err, &e) {
		fields = e.Fields()
	}
	writeProblemStatus(w, r, status, code, title, fields)
}

func writeProblemStatus(w http.ResponseWriter, r *http.Request, status int, code, title string, fields []apperr.Field) {
	body := problemBody{
		Type:   problemTypePrefix + code,
		Title:  title,
		Status: status,
		Extensions: problemExtensions{
			RequestID: observability.RequestID(r.Context()),
		},
	}
	for _, f := range fields {
		body.Errors = append(body.Errors, problemField{Path: f.Path, Code: f.Code, Message: f.Message})
	}
	writeJSON(w, r, status, "application/problem+json", body)
}
