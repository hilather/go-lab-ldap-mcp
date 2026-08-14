package api

import (
	"errors"
	"net/http"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
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
	fields := fieldsOf(err)
	if isPrecondition(fields) {
		return http.StatusPreconditionFailed
	}
	switch apperr.CodeOf(err) {
	case apperr.CodeAuth:
		if hasForbiddenAuth(fields) {
			return http.StatusForbidden
		}
		return http.StatusUnauthorized
	case apperr.CodeConfiguration:
		return http.StatusBadRequest
	case apperr.CodeDirectory:
		return directoryStatus(fields)
	case apperr.CodeReset:
		if retryable(err) || hasFieldCode(fields, "reset_in_progress") {
			return http.StatusServiceUnavailable
		}
		return http.StatusConflict
	case apperr.CodeExport:
		if retryable(err) || hasFieldCode(fields, directory.FieldUnavailable) {
			return http.StatusServiceUnavailable
		}
		if hasFieldCode(fields, "limit") {
			return http.StatusBadRequest
		}
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

func directoryStatus(fields []apperr.Field) int {
	switch firstFieldCode(fields) {
	case directory.FieldNotFound:
		return http.StatusNotFound
	case directory.FieldConflict:
		if hasFieldPath(fields, "revision") {
			return http.StatusPreconditionFailed
		}
		return http.StatusConflict
	case directory.FieldConstraint:
		return http.StatusBadRequest
	case directory.FieldForbidden:
		return http.StatusForbidden
	case directory.FieldUnavailable:
		return http.StatusServiceUnavailable
	case directory.FieldInvalidCredentials:
		// Bind-test surfaces this as a 200 diagnostic. If it leaks as an
		// error, do not emit HTTP 401 (that would clear a browser session).
		return http.StatusBadRequest
	default:
		return http.StatusBadGateway
	}
}

func isPrecondition(fields []apperr.Field) bool {
	for _, f := range fields {
		if f.Path != "If-Match" && f.Path != "revision" {
			continue
		}
		switch f.Code {
		case "required", directory.FieldConflict, "precondition":
			return true
		}
	}
	return false
}

func hasForbiddenAuth(fields []apperr.Field) bool {
	for _, f := range fields {
		if f.Code == "forbidden" || f.Path == "csrf" || f.Path == "origin" || f.Path == "scope" {
			return true
		}
	}
	return false
}

func fieldsOf(err error) []apperr.Field {
	var e *apperr.Error
	if errors.As(err, &e) {
		return e.Fields()
	}
	return nil
}

func firstFieldCode(fields []apperr.Field) string {
	for _, f := range fields {
		if f.Code != "" {
			return f.Code
		}
	}
	return ""
}

func hasFieldCode(fields []apperr.Field, code string) bool {
	for _, f := range fields {
		if f.Code == code {
			return true
		}
	}
	return false
}

func hasFieldPath(fields []apperr.Field, path string) bool {
	for _, f := range fields {
		if f.Path == path {
			return true
		}
	}
	return false
}

func retryable(err error) bool {
	var e *apperr.Error
	return errors.As(err, &e) && e.Retryable()
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
	writeProblemStatus(w, r, status, code, title, fieldsOf(err))
}

func writeProblemStatus(w http.ResponseWriter, r *http.Request, status int, code, title string, fields []apperr.Field) {
	id := requestIDOf(r)
	body := problemBody{
		Type:   problemTypePrefix + code,
		Title:  title,
		Status: status,
		Extensions: problemExtensions{
			RequestID: id,
		},
	}
	for _, f := range fields {
		body.Errors = append(body.Errors, problemField{Path: f.Path, Code: f.Code, Message: f.Message})
	}
	// Auth and mutation errors must not be stored by shared caches.
	w.Header().Set("Cache-Control", "no-store")
	if id != "" {
		w.Header().Set(headerRequestID, id)
	}
	writeJSON(w, r, status, "application/problem+json", body)
}

func requestIDOf(r *http.Request) string {
	if r != nil {
		if id := observability.RequestID(r.Context()); id != "" {
			return id
		}
	}
	return observability.NewRequestID()
}
