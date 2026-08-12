package apperr

import (
	"errors"
	"fmt"
	"strings"
)

// Code is a stable public error category.
type Code string

const (
	CodeConfiguration Code = "configuration"
	CodeAuth          Code = "auth"
	CodeDirectory     Code = "directory"
	CodeReset         Code = "reset"
	CodeExport        Code = "export"
	CodeBootstrap     Code = "bootstrap"
)

// Field is a safe, path-scoped diagnostic. It must not contain secrets.
type Field struct {
	Path    string
	Code    string
	Message string
}

// Error is a structured application error. Identity is the *Error value:
// wrapping with fmt.Errorf("%w") preserves it for errors.Is / errors.As.
type Error struct {
	code    Code
	public  string
	fields  []Field
	retry   bool
	wrapped error
}

func New(code Code, public string) *Error {
	return &Error{code: code, public: public}
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.wrapped != nil {
		return e.public + ": " + e.wrapped.Error()
	}
	return e.public
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.wrapped
}

func (e *Error) Code() Code {
	if e == nil {
		return ""
	}
	return e.code
}

func (e *Error) PublicMessage() string {
	if e == nil {
		return ""
	}
	return e.public
}

func (e *Error) Fields() []Field {
	if e == nil || len(e.fields) == 0 {
		return nil
	}
	out := make([]Field, len(e.fields))
	copy(out, e.fields)
	return out
}

func (e *Error) Retryable() bool {
	return e != nil && e.retry
}

func (e *Error) WithField(f Field) *Error {
	if e == nil {
		return nil
	}
	clone := *e
	clone.fields = append(append([]Field{}, e.fields...), f)
	return &clone
}

func (e *Error) WithFields(fields ...Field) *Error {
	if e == nil {
		return nil
	}
	clone := *e
	clone.fields = append(append([]Field{}, e.fields...), fields...)
	return &clone
}

func (e *Error) Retry() *Error {
	if e == nil {
		return nil
	}
	clone := *e
	clone.retry = true
	return &clone
}

func (e *Error) Wrap(err error) *Error {
	if e == nil {
		return nil
	}
	clone := *e
	clone.wrapped = err
	return &clone
}

func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok || e == nil || t == nil {
		return false
	}
	if e == t {
		return true
	}
	// Category match only when the target is a bare New(code, "") probe.
	return t.public == "" && t.wrapped == nil && len(t.fields) == 0 && e.code == t.code
}

func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code()
	}
	return ""
}

func PublicMessageOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.PublicMessage()
	}
	return ""
}

func KnownCodes() []Code {
	return []Code{CodeConfiguration, CodeAuth, CodeDirectory, CodeReset, CodeExport, CodeBootstrap}
}

func JoinPublic(errs []*Error) string {
	parts := make([]string, 0, len(errs))
	for _, e := range errs {
		if e == nil {
			continue
		}
		parts = append(parts, e.PublicMessage())
	}
	return strings.Join(parts, "; ")
}

func FormatField(f Field) string {
	return fmt.Sprintf("%s: %s (%s)", f.Path, f.Message, f.Code)
}
