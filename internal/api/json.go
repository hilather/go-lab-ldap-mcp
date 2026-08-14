package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
)

// DecodeJSON rejects unknown fields and trailing content.
func DecodeJSON(r io.Reader, dst any) error {
	if r == nil {
		return apperr.New(apperr.CodeConfiguration, "invalid json").
			WithField(apperr.Field{Path: "body", Code: "invalid", Message: "empty body"})
	}
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return jsonError(err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return apperr.New(apperr.CodeConfiguration, "invalid json").
				WithField(apperr.Field{Path: "body", Code: "trailing", Message: "trailing content after JSON value"})
		}
		return jsonError(err)
	}
	return nil
}

func jsonError(err error) error {
	msg := "invalid json"
	code := "invalid"
	var syn *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syn):
		msg = "malformed json"
	case errors.As(err, &typ):
		msg = "json type mismatch"
	case errors.Is(err, io.EOF):
		msg = "empty body"
		code = "empty"
	default:
		if strings.Contains(err.Error(), "unknown field") {
			code = "unknown_field"
			msg = "unknown field"
		}
	}
	return apperr.New(apperr.CodeConfiguration, "invalid json").
		WithField(apperr.Field{Path: "body", Code: code, Message: msg}).
		Wrap(err)
}

func encodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
