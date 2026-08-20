package app

import (
	"context"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/reset"
)

// Services is the transport-neutral application surface.
type Services struct {
	Users   *Users
	Groups  *Groups
	Query   *Query
	Entries *Entries
	Reset   *Reset
	Export  *Export
}

// Deps are injected repositories and hooks. Transports never see ds389 types.
type Deps struct {
	Users   directory.UserRepository
	Groups  directory.GroupRepository
	Entries directory.EntryRepository
	Search  directory.SearchRepository
	Bind    directory.BindTester
	Schema  directory.SchemaRepository
	Caps    directory.CapabilityInspector
	Marker  directory.MarkerReader

	Authz Authorizer
	Audit Auditor
	Gate  MutationGate
	Limit RateLimiter
	Locks *Coordinator

	// ExpectedRevision is the compiled directory revision.
	ExpectedRevision string
	// ControlRevision is the compiled control-plane revision.
	ControlRevision string

	PeopleDN  string
	GroupsDN  string
	Suffix    string
	RuntimeDN string
	MarkerDN  string

	ResetDir      directory.ResetSupport
	Secrets       config.SecretResolver
	SoftReset     bool
	ScenarioName  string
	ResetUsers    []config.NormalizedUser
	ResetGroups   []config.NormalizedGroup
	ResetLock     *reset.Gate
	BindTransport directory.Transport

	ExportMaxEntries int
	ExportMaxBytes   int64
	ObserveExport    func(outcome string)
}

func New(d Deps) *Services {
	if d.Authz == nil {
		d.Authz = ScopeAuthorizer{}
	}
	lock := d.ResetLock
	if lock == nil {
		if g, ok := d.Gate.(*reset.Gate); ok {
			lock = g
		}
	}
	if d.Gate == nil {
		if lock == nil {
			lock = reset.NewGate()
		}
		d.Gate = lock
	}
	if d.Locks == nil {
		d.Locks = NewCoordinator()
	}
	h := hooks{authz: d.Authz, audit: d.Audit, gate: d.Gate, limit: d.Limit, locks: d.Locks}
	return &Services{
		Users:   &Users{repo: d.Users, hooks: h},
		Groups:  &Groups{repo: d.Groups, hooks: h, peopleDN: d.PeopleDN, groupsDN: d.GroupsDN},
		Entries: &Entries{repo: d.Entries, hooks: h},
		Query: &Query{
			search: d.Search, bind: d.Bind, schema: d.Schema,
			caps: d.Caps, marker: d.Marker,
			expected: d.ExpectedRevision, control: d.ControlRevision,
			hooks: h,
		},
		Reset: newReset(d, h, lock),
		Export: &Export{
			hooks:      h,
			dir:        d.ResetDir,
			maxEntries: d.ExportMaxEntries,
			maxBytes:   d.ExportMaxBytes,
			observe:    d.ObserveExport,
		},
	}
}

func newReset(d Deps, h hooks, lock *reset.Gate) *Reset {
	return &Reset{
		hooks:    h,
		gate:     lock,
		dir:      d.ResetDir,
		users:    d.Users,
		groups:   d.Groups,
		marker:   d.Marker,
		bind:     d.Bind,
		secrets:  d.Secrets,
		soft:     d.SoftReset,
		name:     d.ScenarioName,
		expected: d.ExpectedRevision,
		plan: reset.PlanConfig{
			PeopleDN:         d.PeopleDN,
			GroupsDN:         d.GroupsDN,
			Suffix:           d.Suffix,
			RuntimeDN:        d.RuntimeDN,
			MarkerDN:         d.MarkerDN,
			ConfiguredUsers:  userDNs(d.ResetUsers),
			ConfiguredGroups: groupDNs(d.ResetGroups),
		},
		seedU:     d.ResetUsers,
		seedG:     d.ResetGroups,
		transport: d.BindTransport,
	}
}

func userDNs(in []config.NormalizedUser) []string {
	out := make([]string, 0, len(in))
	for _, u := range in {
		out = append(out, u.DN)
	}
	return out
}

func groupDNs(in []config.NormalizedGroup) []string {
	out := make([]string, 0, len(in))
	for _, g := range in {
		out = append(out, g.DN)
	}
	return out
}

type hooks struct {
	authz Authorizer
	audit Auditor
	gate  MutationGate
	limit RateLimiter
	locks *Coordinator
}

func (h hooks) lock(key string) func() {
	if h.locks == nil {
		return func() {}
	}
	return h.locks.Lock(key)
}

func (h hooks) authorize(ctx context.Context, p Principal, op Operation) error {
	var err error
	if h.authz == nil {
		err = ScopeAuthorizer{}.Authorize(p, op)
	} else {
		err = h.authz.Authorize(p, op)
	}
	if err != nil {
		h.record(ctx, p, "authz.deny", op.Name, AuditFailure, "", "")
	}
	return err
}

func (h hooks) allowWrite(ctx context.Context) error {
	if h.gate == nil {
		return nil
	}
	return h.gate.Allow(ctx)
}

func (h hooks) allowRead(ctx context.Context) error {
	if h.gate == nil {
		return nil
	}
	return h.gate.AllowRead(ctx)
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
