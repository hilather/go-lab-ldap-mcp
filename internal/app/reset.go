package app

import (
	"context"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
	"github.com/hilather/go-lab-ldap-mcp/internal/reset"
)

// ResetRequest is the transport-neutral start body (T-081 wires REST).
type ResetRequest struct {
	Name             string `json:"name"`
	ExpectedRevision string `json:"expectedRevision"`
}

// ResetStatus is GET /api/v1/reset. No secrets or password material.
type ResetStatus struct {
	Phase             string       `json:"phase"`
	State             string       `json:"state"`
	Counts            reset.Counts `json:"counts"`
	ExpectedRevision  string       `json:"expectedRevision"`
	AppliedRevision   string       `json:"appliedRevision"`
	InventoryChecksum string       `json:"inventoryChecksum,omitempty"`
	Error             string       `json:"error,omitempty"`
	Recovery          string       `json:"recovery,omitempty"`
}

// Reset is the soft-reset coordinator (T-076–T-080). It never writes the marker.
type Reset struct {
	hooks     hooks
	gate      *reset.Gate
	dir       directory.ResetSupport
	users     directory.UserRepository
	groups    directory.GroupRepository
	marker    directory.MarkerReader
	bind      directory.BindTester
	secrets   config.SecretResolver
	soft      bool
	name      string
	expected  string
	plan      reset.PlanConfig
	seedU     []config.NormalizedUser
	seedG     []config.NormalizedGroup
	transport directory.Transport
	inject    *reset.Injector
	fixup     func(context.Context) error
}

func statusFrom(op reset.Operation) ResetStatus {
	return ResetStatus{
		Phase:             op.Phase,
		State:             string(op.State),
		Counts:            op.Counts,
		ExpectedRevision:  op.ExpectedRevision,
		AppliedRevision:   op.AppliedRevision,
		InventoryChecksum: op.InventoryChecksum,
		Error:             op.Error,
		Recovery:          op.Recovery,
	}
}

func (s *Reset) Status() ResetStatus {
	if s == nil || s.gate == nil {
		return ResetStatus{Phase: string(reset.Ready), State: string(reset.Ready)}
	}
	return statusFrom(s.gate.Snapshot())
}

// Current is GET /api/v1/reset. lab:reset is required.
func (s *Reset) Current(ctx context.Context, p Principal) (ResetStatus, error) {
	if s == nil {
		return ResetStatus{}, apperr.New(apperr.CodeReset, "reset is not configured").
			WithField(apperr.Field{Path: "reset", Code: "unavailable", Message: "reset is not configured"})
	}
	if err := s.hooks.authorize(ctx, p, OpReset); err != nil {
		return ResetStatus{}, err
	}
	return s.Status(), nil
}

func (s *Reset) State() string {
	if s == nil || s.gate == nil {
		return string(reset.Ready)
	}
	return string(s.gate.State())
}

// Start runs one exclusive soft reset. It refuses when softReset is false,
// when seed files are unreadable, or when another reset is running.
func (s *Reset) Start(ctx context.Context, p Principal, req ResetRequest) (ResetStatus, error) {
	if s == nil {
		return ResetStatus{}, apperr.New(apperr.CodeReset, "reset is not configured").
			WithField(apperr.Field{Path: "reset", Code: "unavailable", Message: "reset is not configured"})
	}
	if err := s.hooks.authorize(ctx, p, OpReset); err != nil {
		return ResetStatus{}, err
	}
	if !s.soft {
		err := reset.Disabled()
		s.hooks.record(ctx, p, OpReset.Name, "reset", AuditFailure, "", "")
		return s.Status(), err
	}
	if strings.TrimSpace(req.Name) == "" {
		return s.Status(), apperr.New(apperr.CodeConfiguration, "scenario name is required").
			WithField(apperr.Field{Path: "name", Code: "required", Message: "scenario name is required"})
	}
	if req.Name != s.name {
		s.hooks.record(ctx, p, OpReset.Name, "reset", AuditFailure, "", "")
		return s.Status(), apperr.New(apperr.CodeReset, "scenario confirmation does not match").
			WithField(apperr.Field{Path: "name", Code: "confirmation", Message: "scenario name does not match compiled metadata.name"})
	}
	if strings.TrimSpace(req.ExpectedRevision) == "" {
		return s.Status(), apperr.New(apperr.CodeConfiguration, "expected revision is required").
			WithField(apperr.Field{Path: "expectedRevision", Code: "required", Message: "expected revision is required"})
	}
	if req.ExpectedRevision != s.expected {
		s.hooks.record(ctx, p, OpReset.Name, "reset", AuditFailure, "", "")
		return s.Status(), apperr.New(apperr.CodeReset, "expected revision does not match").
			WithField(apperr.Field{Path: "expectedRevision", Code: "conflict", Message: "expected revision does not match compiled directory revision"})
	}
	// Charge the reset budget only after confirmation matches so typos
	// and stale revisions do not burn resetPerHour.
	if err := s.hooks.rateLimit(ctx, "reset:"+actorOf(p)); err != nil {
		return s.Status(), err
	}

	seeds, err := s.reloadSeeds(ctx)
	if err != nil {
		s.hooks.record(ctx, p, OpReset.Name, "reset", AuditFailure, "", "")
		return s.Status(), err
	}

	if s.gate == nil {
		return s.Status(), apperr.New(apperr.CodeReset, "reset gate is not configured").
			WithField(apperr.Field{Path: "reset", Code: "unavailable", Message: "reset gate is not configured"})
	}
	// Honor cancel only before the exclusive lock. After Begin, mutation
	// must finish or Failed — a client disconnect / HTTP write timeout
	// must not tear the suffix mid-delete.
	if err := ctx.Err(); err != nil {
		return s.Status(), err
	}
	tok, err := s.gate.Begin()
	if err != nil {
		s.hooks.record(ctx, p, OpReset.Name, "reset", AuditFailure, "", "")
		return s.Status(), err
	}

	st, err := s.run(context.WithoutCancel(ctx), tok, seeds)
	if err != nil {
		// Pre-mutation failures release the lock. After delete/reapply
		// starts, Failed keeps readiness false (T-080).
		if !resetMutated(s.gate.State()) {
			if s.gate.State() == reset.PreparingReset {
				_ = s.gate.Advance(tok, reset.Ready)
			}
			s.hooks.record(ctx, p, OpReset.Name, "reset", AuditFailure, s.expected, "")
			return s.Status(), err
		}
		s.gate.Finish(tok, false, reset.Operation{
			Phase:            st.Phase,
			Counts:           st.Counts,
			ExpectedRevision: s.expected,
			AppliedRevision:  st.AppliedRevision,
			Error:            publicResetErr(err),
			Recovery:         reset.RecoveryInstructions,
		})
		s.hooks.record(ctx, p, OpReset.Name, "reset", AuditFailure, s.expected, "")
		return s.Status(), err
	}
	s.gate.Finish(tok, true, reset.Operation{
		Counts:            st.Counts,
		ExpectedRevision:  st.ExpectedRevision,
		AppliedRevision:   st.AppliedRevision,
		InventoryChecksum: st.InventoryChecksum,
	})
	s.hooks.record(ctx, p, OpReset.Name, "reset", AuditSuccess, s.expected, st.AppliedRevision)
	return s.Status(), nil
}

func resetMutated(st reset.State) bool {
	return st == reset.Resetting || st == reset.Verifying || st == reset.Failed
}

func (s *Reset) run(ctx context.Context, tok reset.Token, seeds []config.NormalizedUser) (ResetStatus, error) {
	if err := ctx.Err(); err != nil {
		return s.Status(), err
	}
	if s.dir == nil {
		return s.Status(), apperr.New(apperr.CodeReset, "reset inventory is not configured").
			WithField(apperr.Field{Path: "reset", Code: "unavailable", Message: "reset inventory is not configured"})
	}

	inv, err := s.dir.Inventory(ctx)
	if err != nil {
		return s.Status(), err
	}
	plan := reset.BuildPlan(inv, s.plan)
	s.gate.Update(tok, func(op *reset.Operation) {
		op.Counts = plan.Counts
		op.ExpectedRevision = s.expected
	})

	if err := s.gate.Advance(tok, reset.Resetting); err != nil {
		return s.Status(), err
	}
	if err := s.executeDeletes(ctx, plan); err != nil {
		return statusFrom(s.gate.Current()), err
	}
	if err := s.reapply(ctx, seeds); err != nil {
		return statusFrom(s.gate.Current()), err
	}
	if s.fixup != nil {
		if err := s.fixup(ctx); err != nil {
			return statusFrom(s.gate.Current()), err
		}
	}

	if err := s.gate.Advance(tok, reset.Verifying); err != nil {
		return statusFrom(s.gate.Current()), err
	}
	st, err := s.verify(ctx, seeds, plan.Counts)
	if err != nil {
		return st, err
	}
	return st, nil
}

func (s *Reset) executeDeletes(ctx context.Context, plan reset.Plan) error {
	for _, step := range plan.Deletes {
		if err := ctx.Err(); err != nil {
			return err
		}
		phase := reset.PhaseDeleteExtra
		switch step.Kind {
		case reset.KindGroup:
			phase = reset.PhaseDeleteGroups
		case reset.KindUser:
			phase = reset.PhaseDeleteUsers
		}
		if err := s.inject.Trip(phase); err != nil {
			return err
		}
		if err := s.dir.DeleteManaged(ctx, step.DN); err != nil {
			return err
		}
	}
	return nil
}

func (s *Reset) reapply(ctx context.Context, seeds []config.NormalizedUser) error {
	if s.users == nil || s.groups == nil {
		return apperr.New(apperr.CodeReset, "reset repositories are not configured").
			WithField(apperr.Field{Path: "reset", Code: "unavailable", Message: "reset repositories are not configured"})
	}
	if err := s.inject.Trip(reset.PhaseReapplyUsers); err != nil {
		return err
	}
	for _, u := range seeds {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.upsertUser(ctx, u); err != nil {
			return err
		}
	}
	if err := s.inject.Trip(reset.PhaseReapplyGroups); err != nil {
		return err
	}
	for _, g := range s.seedG {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.upsertGroup(ctx, g); err != nil {
			return err
		}
	}
	return nil
}

func (s *Reset) upsertUser(ctx context.Context, u config.NormalizedUser) error {
	pw := observability.Secret("")
	if u.Password != nil {
		pw = u.Password.Value
	}
	spec := directory.UserSpec{
		ID:         u.ID,
		UID:        u.UID,
		Enabled:    boolPtr(u.Enabled),
		Password:   pw,
		Attributes: attrMap(u.Attributes),
	}
	if _, err := s.users.Add(ctx, spec); err == nil {
		return nil
	} else if fieldCode(err) != directory.FieldConflict {
		return err
	}
	got, gerr := s.users.Get(ctx, directory.UserID(u.ID))
	if gerr != nil {
		return gerr
	}
	if _, merr := s.users.Modify(ctx, directory.UserID(u.ID), directory.UserPatch{
		Enabled:    spec.Enabled,
		Attributes: spec.Attributes,
	}, got.Revision); merr != nil {
		return merr
	}
	fresh, ferr := s.users.Get(ctx, directory.UserID(u.ID))
	if ferr != nil {
		return ferr
	}
	return s.users.SetPassword(ctx, directory.UserID(u.ID), pw, fresh.Revision, false)
}

func (s *Reset) upsertGroup(ctx context.Context, g config.NormalizedGroup) error {
	members := make([]directory.MemberRef, 0, len(g.Members))
	for _, m := range g.Members {
		members = append(members, directory.MemberRef{Kind: m.Kind, ID: m.ID, DN: m.DN})
	}
	_, err := s.groups.Add(ctx, directory.GroupSpec{ID: g.ID, Members: members})
	if err == nil {
		return nil
	}
	if fieldCode(err) != directory.FieldConflict {
		return err
	}
	got, gerr := s.groups.Get(ctx, directory.GroupID(g.ID))
	if gerr != nil {
		return gerr
	}
	_, err = s.groups.ReplaceMembers(ctx, directory.GroupID(g.ID), members, got.Revision)
	return err
}

func (s *Reset) verify(ctx context.Context, seeds []config.NormalizedUser, counts reset.Counts) (ResetStatus, error) {
	if err := s.inject.Trip(reset.PhaseVerify); err != nil {
		return statusFrom(s.gate.Current()), err
	}
	markerSerial := ""
	if s.marker != nil {
		m, err := s.marker.ReadMarker(ctx)
		if err != nil {
			return statusFrom(s.gate.Current()), err
		}
		markerSerial = m.AppliedRevision
	}

	inv, err := s.dir.Inventory(ctx)
	if err != nil {
		return statusFrom(s.gate.Current()), err
	}
	livePlan := reset.BuildPlan(inv, s.plan)
	want := s.wantSnaps()
	live, missing := s.liveSnaps(ctx)
	ver := reset.Compare(s.expected, markerSerial, reset.Checksum(live), reset.Checksum(want), len(livePlan.Extra), missing)
	st := ResetStatus{
		Phase:             string(reset.Verifying),
		State:             string(reset.Verifying),
		Counts:            counts,
		ExpectedRevision:  ver.ExpectedRevision,
		AppliedRevision:   ver.AppliedRevision,
		InventoryChecksum: ver.InventoryChecksum,
	}
	if !ver.OK {
		st.Error = ver.Reason
		st.Recovery = reset.RecoveryInstructions
		return st, apperr.New(apperr.CodeReset, "reset verification failed").
			WithField(apperr.Field{Path: "reset", Code: "verify_failed", Message: ver.Reason})
	}
	if err := s.bindCheck(ctx, seeds); err != nil {
		st.Error = publicResetErr(err)
		st.Recovery = reset.RecoveryInstructions
		return st, err
	}
	st.Phase = string(reset.Ready)
	st.State = string(reset.Ready)
	return st, nil
}

func (s *Reset) wantSnaps() []reset.ObjectSnap {
	var out []reset.ObjectSnap
	for _, u := range s.seedU {
		out = append(out, reset.ObjectSnap{DN: u.DN, Kind: "user"})
	}
	for _, g := range s.seedG {
		members := make([]string, 0, len(g.Members))
		for _, m := range g.Members {
			members = append(members, m.DN)
		}
		out = append(out, reset.ObjectSnap{DN: g.DN, Kind: "group", Members: members})
	}
	return out
}

func (s *Reset) liveSnaps(ctx context.Context) ([]reset.ObjectSnap, int) {
	var out []reset.ObjectSnap
	missing := 0
	for _, u := range s.seedU {
		got, err := s.users.Get(ctx, directory.UserID(u.ID))
		if err != nil {
			missing++
			continue
		}
		dn := got.DN
		if dn == "" {
			dn = u.DN
		}
		out = append(out, reset.ObjectSnap{DN: dn, Kind: "user"})
	}
	for _, g := range s.seedG {
		got, err := s.groups.Get(ctx, directory.GroupID(g.ID))
		if err != nil {
			missing++
			continue
		}
		compiled := map[string]string{}
		for _, m := range g.Members {
			compiled[m.ID] = m.DN
		}
		members := make([]string, 0, len(got.Members))
		for _, m := range got.Members {
			dn := m.DN
			if dn == "" {
				dn = compiled[m.ID]
			}
			if dn == "" && m.ID != "" && s.plan.PeopleDN != "" {
				dn = "uid=" + m.ID + "," + s.plan.PeopleDN
			}
			if dn != "" {
				members = append(members, dn)
			}
		}
		dn := got.DN
		if dn == "" {
			dn = g.DN
		}
		out = append(out, reset.ObjectSnap{DN: dn, Kind: "group", Members: members})
	}
	return out, missing
}

func (s *Reset) bindCheck(ctx context.Context, seeds []config.NormalizedUser) error {
	if s.bind == nil {
		return nil
	}
	for _, u := range seeds {
		if !u.Enabled || u.Password == nil {
			continue
		}
		res, err := s.bind.BindTest(ctx, u.UID, u.Password.Value, s.transport)
		if err != nil {
			return err
		}
		if res.Outcome != directory.BindOutcomeSuccess {
			return apperr.New(apperr.CodeReset, "reset verification failed").
				WithField(apperr.Field{Path: "reset", Code: "bind_failed", Message: "baseline user could not bind with seed password"})
		}
	}
	return nil
}

func (s *Reset) reloadSeeds(ctx context.Context) ([]config.NormalizedUser, error) {
	out := make([]config.NormalizedUser, len(s.seedU))
	copy(out, s.seedU)
	for i := range out {
		u := &out[i]
		owner := "spec.users[" + u.ID + "].passwordFile"
		if s.secrets != nil && u.Password != nil && u.Password.Path != "" {
			sec, err := s.secrets.Resolve(ctx, owner, u.Password.Path)
			if err != nil {
				return nil, err
			}
			cp := sec
			u.Password = &cp
			continue
		}
		if u.Password == nil || u.Password.Value.Reveal() == "" {
			return nil, apperr.New(apperr.CodeConfiguration, "secret file unreadable").
				WithField(apperr.Field{Path: owner, Code: "secret_unreadable", Message: "required seed password is unavailable"})
		}
	}
	return out, nil
}

// BaselinePresent is the cheap ready-path check: compiled users/groups
// exist. Transport errors are treated as unknown (true) so Ping owns outages.
func (s *Reset) BaselinePresent(ctx context.Context) bool {
	ok, err := s.compiledPresent(ctx)
	if err != nil {
		return true
	}
	return ok
}

func (s *Reset) compiledPresent(ctx context.Context) (bool, error) {
	if s == nil {
		return false, nil
	}
	for _, u := range s.seedU {
		if s.users == nil {
			return false, apperr.New(apperr.CodeReset, "reset repositories are not configured").
				WithField(apperr.Field{Path: "reset", Code: "unavailable", Message: "reset repositories are not configured"})
		}
		if _, err := s.users.Get(ctx, directory.UserID(u.ID)); err != nil {
			if fieldCode(err) == directory.FieldNotFound {
				return false, nil
			}
			return false, err
		}
	}
	for _, g := range s.seedG {
		if s.groups == nil {
			return false, apperr.New(apperr.CodeReset, "reset repositories are not configured").
				WithField(apperr.Field{Path: "reset", Code: "unavailable", Message: "reset repositories are not configured"})
		}
		if _, err := s.groups.Get(ctx, directory.GroupID(g.ID)); err != nil {
			if fieldCode(err) == directory.FieldNotFound {
				return false, nil
			}
			return false, err
		}
	}
	return true, nil
}

// Inspect runs a read-only verify at process start (T-080). Missing compiled
// objects, leftover extras, or a checksum mismatch MarkFailed. Transport
// errors do not flip Failed.
func (s *Reset) Inspect(ctx context.Context) ResetStatus {
	if s == nil {
		return ResetStatus{State: string(reset.Ready), Phase: string(reset.Ready)}
	}
	reason, err := s.inspectReason(ctx)
	if err != nil || reason == "" {
		return s.Status()
	}
	if s.gate != nil {
		s.gate.MarkFailed(reason)
	}
	st := s.Status()
	if st.Recovery == "" {
		st.Recovery = reset.RecoveryInstructions
	}
	return st
}

func (s *Reset) inspectReason(ctx context.Context) (string, error) {
	ok, err := s.compiledPresent(ctx)
	if err != nil {
		return "", err
	}
	if !ok {
		return "compiled baseline objects are missing", nil
	}
	if s.dir == nil {
		return "", nil
	}
	if _, err := s.dir.Inventory(ctx); err != nil {
		return "", err
	}
	markerSerial := s.expected
	if s.marker != nil {
		m, merr := s.marker.ReadMarker(ctx)
		if merr != nil {
			return "", merr
		}
		markerSerial = m.AppliedRevision
	}
	live, missing := s.liveSnaps(ctx)
	// Merge preserves runtime extras. Startup inspect must not treat them
	// as a failed reset (control recreate / T-120). T-080 uses missing
	// compiled objects and an in-process Failed gate. Soft-reset verify
	// still passes extras into Compare.
	ver := reset.Compare(s.expected, markerSerial, reset.Checksum(live), reset.Checksum(s.wantSnaps()), 0, missing)
	if ver.OK {
		return "", nil
	}
	return ver.Reason, nil
}

func publicResetErr(err error) string {
	if err == nil {
		return ""
	}
	if msg := apperr.PublicMessageOf(err); msg != "" {
		return msg
	}
	return "reset failed"
}

func boolPtr(v bool) *bool { return &v }

func attrMap(in []config.AttrKV) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := map[string]string{}
	for _, a := range in {
		out[a.Name] = a.Value
	}
	return out
}
