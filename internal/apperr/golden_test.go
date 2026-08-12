package apperr_test

import (
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
)

func TestEqualGoldenPublicMessage(t *testing.T) {
	err := apperr.New(apperr.CodeReset, "reset in progress")
	apperr.EqualGolden(t, "public-reset.txt", []byte(err.PublicMessage()+"\n"))
}
