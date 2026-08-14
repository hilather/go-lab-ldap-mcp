package app

import (
	"context"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

// Services is the transport-neutral application surface.
type Services struct {
	Users  *Users
	Groups *Groups
	Query  *Query
}

// Deps are injected repositories and hooks. Transports never see ds389 types.
type Deps struct {
	Users  directory.UserRepository
	Groups directory.GroupRepository
	Search directory.SearchRepository
	Bind   directory.BindTester
	Schema directory.SchemaRepository
	Caps   directory.CapabilityInspector
	Marker directory.MarkerReader

	Authz Authorizer
	Audit Auditor
	Gate  MutationGate
	Limit RateLimiter

	// ExpectedRevision is the compiled directory revision.
	ExpectedRevision string
	// ControlRevision is the compiled control-plane revision.
	ControlRevision string
}

func New(d Deps) *Services {
	if d.Authz == nil {
		d.Authz = ScopeAuthorizer{}
	}
	if d.Gate == nil {
		d.Gate = OpenGate{}
	}
	h := hooks{authz: d.Authz, audit: d.Audit, gate: d.Gate, limit: d.Limit}
	return &Services{
		Users:  &Users{repo: d.Users, hooks: h},
		Groups: &Groups{repo: d.Groups, hooks: h},
		Query: &Query{
			search: d.Search, bind: d.Bind, schema: d.Schema,
			caps: d.Caps, marker: d.Marker,
			expected: d.ExpectedRevision, control: d.ControlRevision,
			hooks: h,
		},
	}
}

type hooks struct {
	authz Authorizer
	audit Auditor
	gate  MutationGate
	limit RateLimiter
}

func (h hooks) authorize(p Principal, op Operation) error {
	if h.authz == nil {
		return ScopeAuthorizer{}.Authorize(p, op)
	}
	return h.authz.Authorize(p, op)
}

func (h hooks) allowWrite(ctx context.Context) error {
	if h.gate == nil {
		return nil
	}
	return h.gate.Allow(ctx)
}

func (h hooks) rateLimit(ctx context.Context, key string) error {
	if h.limit == nil {
		return nil
	}
	return h.limit.Allow(ctx, key)
}

func (h hooks) record(ctx context.Context, p Principal, action, target, result, before, after string) {
	if h.audit == nil {
		return
	}
	h.audit.Record(ctx, AuditIntent{
		RequestID: requestID(ctx),
		Actor:     actorOf(p),
		Action:    action,
		Target:    target,
		Result:    result,
		Before:    before,
		After:     after,
	})
}

func requireRevision(rev directory.Revision) error {
	if rev == "" {
		return apperr.New(apperr.CodeConfiguration, "revision is required").WithField(apperr.Field{
			Path: "revision", Code: "required", Message: "revision is required",
		})
	}
	return nil
}

func fieldCode(err error) string {
	var e *apperr.Error
	if err == nil || !apperrAs(err, &e) {
		return ""
	}
	for _, f := range e.Fields() {
		if f.Code != "" {
			return f.Code
		}
	}
	return ""
}

func apperrAs(err error, target **apperr.Error) bool {
	return err != nil && target != nil && asError(err, target)
}
