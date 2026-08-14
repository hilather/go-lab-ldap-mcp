package auth

import (
	"errors"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

func TestPasswordResetExportIndependentOfWrite(t *testing.T) {
	t.Parallel()
	write := directory.ScopeSet{ScopeDirectoryWrite}
	for _, scope := range IndependentOfWrite() {
		err := Require(write, scope)
		if err == nil {
			t.Fatalf("directory:write granted %s", scope)
		}
		apperr.Assert(t, err).Code(apperr.CodeAuth)
		if !strings.Contains(err.Error(), "missing required scope") {
			t.Fatalf("public: %v", err)
		}
		var e *apperr.Error
		if !errors.As(err, &e) || len(e.Fields()) == 0 || e.Fields()[0].Message != scope {
			t.Fatalf("required scope not named: %v", err)
		}
		if strings.Contains(err.Error(), "token-") || strings.Contains(err.Error(), "admin") {
			t.Fatal("token id leaked")
		}
	}
	if err := Require(write, ScopeDirectoryWrite); err != nil {
		t.Fatal(err)
	}
}

func TestMatrixGenerator(t *testing.T) {
	t.Parallel()
	rows := Matrix()
	if len(rows) < len(Scopes())*4 {
		t.Fatalf("matrix too small: %d", len(rows))
	}
	for _, c := range rows {
		err := Require(c.Have, c.Required)
		if c.Allow && err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		if !c.Allow && err == nil {
			t.Fatalf("%s allowed", c.Name)
		}
	}
}
