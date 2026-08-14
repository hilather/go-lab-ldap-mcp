package reset

import (
	"sync"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
)

// Destructive phases used by T-080 failure injection.
const (
	PhaseDeleteGroups  = "delete.groups"
	PhaseDeleteUsers   = "delete.users"
	PhaseDeleteExtra   = "delete.extra"
	PhaseReapplyUsers  = "reapply.users"
	PhaseReapplyGroups = "reapply.groups"
	PhaseVerify        = "verify"
)

// Injector trips a single controlled failure point.
type Injector struct {
	mu    sync.Mutex
	point string
}

func (i *Injector) Set(phase string) {
	if i == nil {
		return
	}
	i.mu.Lock()
	i.point = phase
	i.mu.Unlock()
}

func (i *Injector) Trip(phase string) error {
	if i == nil {
		return nil
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.point == "" || i.point != phase {
		return nil
	}
	i.point = ""
	return apperr.New(apperr.CodeReset, "injected reset failure").
		WithField(apperr.Field{Path: "reset", Code: "injected", Message: phase})
}
