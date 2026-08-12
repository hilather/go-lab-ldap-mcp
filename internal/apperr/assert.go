package apperr

import (
	"errors"
	"testing"
)

// Assert is a test helper that checks code, public message, fields, cause, and retry independently.
type Assertion struct {
	t   *testing.T
	err error
	e   *Error
}

func Assert(t *testing.T, err error) *Assertion {
	t.Helper()
	a := &Assertion{t: t, err: err}
	if !errors.As(err, &a.e) {
		t.Fatalf("error %v is not *apperr.Error", err)
	}
	return a
}

func (a *Assertion) Code(want Code) *Assertion {
	a.t.Helper()
	if a.e.Code() != want {
		a.t.Fatalf("code = %s, want %s", a.e.Code(), want)
	}
	return a
}

func (a *Assertion) Public(want string) *Assertion {
	a.t.Helper()
	if a.e.PublicMessage() != want {
		a.t.Fatalf("public = %q, want %q", a.e.PublicMessage(), want)
	}
	return a
}

func (a *Assertion) Retryable(want bool) *Assertion {
	a.t.Helper()
	if a.e.Retryable() != want {
		a.t.Fatalf("retryable = %v, want %v", a.e.Retryable(), want)
	}
	return a
}

func (a *Assertion) FieldPath(path string) *Assertion {
	a.t.Helper()
	for _, f := range a.e.Fields() {
		if f.Path == path {
			return a
		}
	}
	a.t.Fatalf("missing field path %q in %#v", path, a.e.Fields())
	return a
}

func (a *Assertion) Cause(want error) *Assertion {
	a.t.Helper()
	if !errors.Is(a.err, want) {
		a.t.Fatalf("cause %v not found in %v", want, a.err)
	}
	return a
}
