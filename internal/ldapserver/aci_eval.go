package ldapserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// aci_eval.go is the T-139 evaluator behind the pinned ACIEngine seam
// (aci.go): it decides access from the ACI text the LabLDAP compiler emits
// (parity contract C8 — the four runtime ACIs plus operator ACLs parsed by
// T-138's ParseACITextA).
//
// Semantics (C8, 389-observed on the T-036 matrix):
//
//   - BypassACI subjects (the Directory Manager identity, ADR-0009 decision
//     13) are allowed without evaluation.
//   - An ACI applies to a check when the target entry is the ACI's target
//     DN or a descendant (the target rule), the ACI lists the requested
//     permission, the targetattr clause covers the requested attribute
//     (entry-level checks with an empty attribute skip targetattr, matching
//     389 where add/delete target the entry itself), and the bind-rule
//     subject matches.
//   - Deny wins: any applicable deny ACI denies the check. Otherwise the
//     check is allowed only when at least one applicable allow ACI granted
//     it. With no applicable ACI the default is deny.
//
// This is the authorization enforcement point, so every ambiguity fails
// closed: an unknown subject kind, a missing or unreadable group entry, or
// a store error denies the check (store errors also surface as an error so
// dispatch logs them). Denials are logged at debug without secrets and the
// evaluator never panics on adversarial state.
//
// Evaluation runs per search candidate, so groupdn resolution is bounded:
// each distinct groupdn is read through tx at most once per Allowed call
// (lazy per-call cache), in the same store snapshot as the operation being
// authorized.

// aciEngine is the concrete ACIEngine over a fixed parsed ACI set.
type aciEngine struct {
	acis   []*ParsedACI
	logger *slog.Logger
}

var _ ACIEngine = (*aciEngine)(nil)

// NewACIEngine parses each ACI text in the T-138 compiler-subset grammar
// and returns the evaluating engine. Any parse failure rejects the whole
// set: a partial access policy is never enforced (fail-closed). An empty
// set is valid and denies everything except BypassACI subjects. A nil
// logger discards debug output.
func NewACIEngine(texts []string, logger *slog.Logger) (ACIEngine, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	eng := &aciEngine{logger: logger}
	for _, text := range texts {
		p, err := ParseACITextA(text)
		if err != nil {
			return nil, fmt.Errorf("ldapserver: aci set: %w", err)
		}
		eng.acis = append(eng.acis, p)
	}
	return eng, nil
}

// Allowed implements ACIEngine.
func (eng *aciEngine) Allowed(ctx context.Context, tx ReadTx, check ACICheck) (bool, error) {
	if check.Subject.BypassACI {
		return true, nil
	}
	allowed := false
	// groups caches groupdn membership verdicts for this call, keyed by the
	// group's folded DN, so repeated groupdn clauses cost one read each.
	var groups map[string]bool
	for _, aci := range eng.acis {
		if !aciTargetScopeA(check.Target, aci.TargetDN) {
			continue
		}
		if !aci.HasPerm(check.Perm) {
			continue
		}
		if check.Attribute != "" && !aci.TargetsAttr(check.Attribute) {
			continue
		}
		match, err := eng.subjectMatchA(ctx, tx, aci, check, &groups)
		if err != nil {
			return false, err
		}
		if !match {
			continue
		}
		if aci.Deny {
			eng.logDeny(ctx, "deny rule matched", aci, check)
			return false, nil
		}
		allowed = true
	}
	return allowed, nil
}

// aciTargetScopeA reports whether target is the ACI target DN or a
// descendant (C8 target rule). Comparison is fold-correct: EqualFold for
// the RDNs plus a parent walk, so value casing on the wire cannot escape
// or widen a grant. The walk is bounded by the target's depth (a handful
// of RDNs) and never panics on the zero DN.
func aciTargetScopeA(target, aciTarget config.DN) bool {
	for d := target; ; {
		if d.EqualFold(aciTarget) {
			return true
		}
		parent, ok := parentDN(d)
		if !ok {
			return false
		}
		d = parent
	}
}

// subjectMatchA evaluates one parsed bind rule against the check's
// subject. Unauthenticated subjects match only the anyone rule.
func (eng *aciEngine) subjectMatchA(ctx context.Context, tx ReadTx, aci *ParsedACI, check ACICheck, groups *map[string]bool) (bool, error) {
	subj := check.Subject
	switch aci.Subject.Kind {
	case ACISubjectAnyoneA:
		return true, nil
	case ACISubjectAllA:
		return aciAuthenticatedA(subj), nil
	case ACISubjectUserDNA:
		return aciAuthenticatedA(subj) && subj.DN.EqualFold(aci.Subject.DN), nil
	case ACISubjectSelfA:
		return aciAuthenticatedA(subj) && subj.DN.EqualFold(check.Target), nil
	case ACISubjectGroupDNA:
		if !aciAuthenticatedA(subj) {
			return false, nil
		}
		return eng.groupMemberA(ctx, tx, aci, subj.DN, groups)
	default:
		// The parser only emits the kinds above, so an unknown kind means a
		// hand-built or corrupted ACI set: fail closed.
		eng.logDeny(ctx, "unknown ACI subject kind", aci, check)
		return false, nil
	}
}

// aciAuthenticatedA reports whether the subject carries an authenticated
// identity. Bind attempts always set Anonymous, but a connection that has
// never bound holds the zero Subject (Anonymous unset, zero DN), so both
// markers are checked: 389 treats a pre-bind connection as anonymous, and
// "all" must never grant it.
func aciAuthenticatedA(s Subject) bool {
	return !s.Anonymous && s.DN.Depth() > 0
}

// groupMemberA reports whether userDN is a member/uniqueMember of the
// group entry at aci.Subject.DN, reading the group through tx (the same
// snapshot as the authorized operation). Verdicts are cached per Allowed
// call. A missing group or one listing no parseable membership never
// matches; a store error other than ErrNoSuchObject is returned so the
// caller denies with a logged reason.
func (eng *aciEngine) groupMemberA(ctx context.Context, tx ReadTx, aci *ParsedACI, userDN config.DN, groups *map[string]bool) (bool, error) {
	key := aci.Subject.DN.FoldedKey()
	if *groups == nil {
		*groups = map[string]bool{}
	}
	if verdict, ok := (*groups)[key]; ok {
		return verdict, nil
	}
	member := false
	entry, err := tx.Entry(ctx, aci.Subject.DN)
	switch {
	case errors.Is(err, ErrNoSuchObject):
		eng.logDeny(ctx, "groupdn group entry is absent", aci, ACICheck{})
	case err != nil:
		return false, fmt.Errorf("ldapserver: aci groupdn lookup: %w", err)
	default:
		want := userDN.FoldedKey()
		for _, m := range memberDNs(entry) {
			if m.FoldedKey() == want {
				member = true
				break
			}
		}
	}
	(*groups)[key] = member
	return member, nil
}

// logDeny records a deny decision at debug level. The ACI id is
// parser-bounded and control-character-free; DNs are configuration, not
// secrets. Passwords and attribute values never reach this path.
func (eng *aciEngine) logDeny(ctx context.Context, reason string, aci *ParsedACI, check ACICheck) {
	eng.logger.LogAttrs(ctx, slog.LevelDebug, "aci denied",
		slog.String("reason", reason),
		slog.String("aci", aci.ID),
		slog.String("perm", string(check.Perm)),
		slog.String("target", check.Target.String()))
}
