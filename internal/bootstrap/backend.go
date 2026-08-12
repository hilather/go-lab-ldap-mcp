package bootstrap

import "context"

// BackendRequest is the dsconf backend reconcile input. The password is
// referenced by file path only.
type BackendRequest struct {
	PasswordFile string
	Instance     string
	Name         string
	Suffix       string
	Write        bool
}

// BackendResult is secret-free.
type BackendResult struct {
	Action string
	Name   string
	Suffix string
}

// BackendReconciler creates or verifies the planned backend/suffix.
type BackendReconciler interface {
	Reconcile(ctx context.Context, req BackendRequest) (BackendResult, error)
}
