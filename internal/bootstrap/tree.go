package bootstrap

import (
	"context"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

// TreeRequest is the suffix / OU / runtime-account reconcile input.
type TreeRequest struct {
	Suffix          string
	PeopleDN        string
	GroupsDN        string
	RuntimeDN       string
	RuntimePassword observability.Secret
	DMPassword      observability.Secret
	LDAPURL         string
	LDAPAddr        string
	LDAPSAddr       string
	CAFile          string
	Host            string
	UseLDAPS        bool
	StartTLS        bool
	Insecure        bool
	Write           bool
	DialTimeout     time.Duration
}

// TreeResult is secret-free.
type TreeResult struct {
	Created []string
	Matched []string
}

// TreeReconciler creates or verifies the compiled base tree and runtime account.
type TreeReconciler interface {
	ReconcileTree(ctx context.Context, req TreeRequest) (TreeResult, error)
}
