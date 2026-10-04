package ldapserver

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

// errSearchLimit stops candidate iteration once the size or time limit has
// been recorded on the search outcome.
var errSearchLimit = errors.New("ldapserver: search limit reached")

// handleSearch runs one RFC 4511 search against a store snapshot (T-127).
//
// Authorization follows parity contract C8 with 389-observed behavior:
// entries the subject may not search are filtered out of the result set
// rather than failing the whole search, and attributes the subject may not
// read are dropped from returned entries — a denied search looks like an
// empty result, never like an existence leak.
//
// Server size and time limits always apply (C6); a smaller client-requested
// limit wins. Partial results are returned with sizeLimitExceeded or
// timeLimitExceeded in the SearchResultDone.
func (s *Server) handleSearch(ctx context.Context, c *conn, m *Message, req *SearchRequest) ResultCode {
	return s.runSearch(ctx, c, m, req, operationSubject(ctx, c))
}

func (s *Server) runSearch(ctx context.Context, c *conn, m *Message, req *SearchRequest, subj Subject) ResultCode {
	sendDone := func(res Result, controls []Control) {
		if ctx.Err() != nil {
			return
		}
		_ = c.send(&Message{ID: m.ID, Op: &SearchResultDone{Result: res}, Controls: controls})
	}
	fail := func(code ResultCode, diag string) ResultCode {
		sendDone(Result{Code: code, DiagnosticMessage: diag}, nil)
		return code
	}

	// An empty base addresses the Root DSE, and the subschema subentry is
	// served from the schema registry (T-132, parity contract C10). Both
	// live outside the store and the managed suffix.
	if req.BaseDN == "" {
		return s.searchRootDSE(ctx, c, m, req)
	}
	base, err := config.ParseDN(req.BaseDN)
	if err != nil {
		return fail(ResultInvalidDNSyntax, "invalid base DN")
	}
	if isSubschemaDN(base) {
		return s.searchSubschema(ctx, c, m, req)
	}
	page, res, err := s.parsePagedControl(m.Controls, base, req)
	if err != nil {
		sendDone(res, nil)
		return res.Code
	}
	sel := parseAttrSelection(req.Attributes)

	limits := s.opts.Limits
	sizeLimit := limits.SearchSizeLimit
	if req.SizeLimit > 0 && req.SizeLimit < sizeLimit {
		sizeLimit = req.SizeLimit
	}
	timeLimit := limits.SearchTimeLimit
	if req.TimeLimit > 0 {
		if d := time.Duration(req.TimeLimit) * time.Second; d < timeLimit {
			timeLimit = d
		}
	}
	deadline := time.Now().Add(timeLimit)

	var matched []*Entry
	code := ResultSuccess
	viewErr := s.opts.Store.View(ctx, func(tx ReadTx) error {
		visit := func(e *Entry) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if time.Now().After(deadline) {
				code = ResultTimeLimitExceeded
				return errSearchLimit
			}
			entryDN, err := config.ParseDN(e.DN)
			if err != nil {
				return nil
			}
			if !s.allowed(ctx, tx, subj, entryDN, "", PermSearch) {
				return nil
			}
			if s.matchSearchFilter(ctx, tx, subj, entryDN, e, req.Filter) != filterTrue {
				return nil
			}
			// C8 visibility runs after the filter so only matching
			// entries pay the per-attribute read checks.
			if !s.entryReadable(ctx, tx, subj, entryDN, e) {
				return nil
			}
			if len(matched) >= sizeLimit {
				code = ResultSizeLimitExceeded
				return errSearchLimit
			}
			matched = append(matched, s.projectEntry(ctx, tx, subj, entryDN, e, sel, req.TypesOnly))
			return nil
		}
		if predicate := indexedSearchPredicate(req.Filter); req.Scope != ScopeBaseObject && predicate != nil {
			if walker, ok := tx.(SearchEqualWalker); ok {
				if _, err := tx.Entry(ctx, base); err != nil {
					return err
				}
				indexed, err := walker.WalkEqual(ctx, predicate.Attr, predicate.Value, func(e *Entry) error {
					if err := ctx.Err(); err != nil {
						return err
					}
					if time.Now().After(deadline) {
						code = ResultTimeLimitExceeded
						return errSearchLimit
					}
					dn, err := config.ParseDN(e.DN)
					if err != nil || !searchScopeContains(base, dn, req.Scope) {
						return nil
					}
					return visit(e)
				})
				if indexed || err != nil {
					return err
				}
			}
		}
		// Production bbolt visits one entry at a time, so size/time limits
		// stop decoding and traversal before the whole subtree is allocated.
		if walker, ok := tx.(SearchWalker); ok {
			return walker.WalkSearch(ctx, base, req.Scope, visit)
		}
		var candidates []*Entry
		var err error
		switch req.Scope {
		case ScopeBaseObject:
			e, lookupErr := tx.Entry(ctx, base)
			if lookupErr != nil {
				return lookupErr
			}
			candidates = []*Entry{e}
		case ScopeSingleLevel, ScopeChildren:
			candidates, err = tx.Children(ctx, base)
		case ScopeWholeSubtree:
			candidates, err = tx.Subtree(ctx, base)
		}
		if err != nil {
			return err
		}
		for _, e := range candidates {
			if err := visit(e); err != nil {
				return err
			}
		}
		return nil
	})
	switch {
	case errors.Is(viewErr, errSearchLimit):
		// code already set; partial results stand.
	case viewErr != nil && errors.Is(viewErr, ErrNoSuchObject):
		return fail(ResultNoSuchObject, "no such object")
	case viewErr != nil && ctx.Err() != nil:
		return ResultOperationsError // abandoned or shutting down: no response
	case viewErr != nil:
		return fail(ResultOperationsError, "internal error")
	}

	pageControls, paged := s.applyPaging(matched, page, sizeLimit)
	entries := matched
	if paged.out != nil {
		entries = paged.out
	}
	for _, e := range entries {
		if ctx.Err() != nil {
			return code
		}
		if err := c.send(&Message{ID: m.ID, Op: &SearchResultEntry{DN: e.DN, Attributes: e.Attributes}}); err != nil {
			return ResultOperationsError
		}
	}
	sendDone(Result{Code: code}, pageControls)
	return code
}

// searchEntryVisible is the full entry-level access check for a search
// result (contract C8): the entry-level search grant plus entryReadable.
// runSearch runs the two halves around the filter; tests use this form.
func (s *Server) searchEntryVisible(ctx context.Context, tx ReadTx, subj Subject, dn config.DN, e *Entry) bool {
	return s.allowed(ctx, tx, subj, dn, "", PermSearch) && s.entryReadable(ctx, tx, subj, dn, e)
}

// entryReadable reports whether subj may read at least one attribute of e
// that counts for search-result visibility. 389 returns an entry only if
// the subject may read such an attribute (oracle probes 8, 10 and 13: read
// on nothing but operational attributes, or search without read, hides the
// entry even when the filter is True; objectClass and memberOf count,
// nsAccountLock does not). Unknown attributes count, as in
// clientModifiable.
func (s *Server) entryReadable(ctx context.Context, tx ReadTx, subj Subject, dn config.DN, e *Entry) bool {
	for _, a := range e.Attributes {
		if !s.countsForVisibility(a.Name) {
			continue
		}
		if s.allowed(ctx, tx, subj, dn, a.Name, PermRead) {
			return true
		}
	}
	return false
}

// visibilityOperational lists stored attributes whose 389 usage differs
// from the native registry's Operational flag, keyed by lowercase base name
// (probes 13 and 15 compared every registry attribute with the pinned
// image's cn=schema; the subschema attributes already agree): true means 389 treats the attribute as operational,
// false as a user attribute. pwdChangedTime and passwordHistory are not in
// the registry; pwdChangedTime is native-only (389's counterpart
// pwdUpdateTime is directoryOperation).
var visibilityOperational = map[string]bool{
	"memberof":        false,
	"nsaccountlock":   true,
	"aci":             true,
	"passwordhistory": true,
	"pwdchangedtime":  true,
}

func (s *Server) countsForVisibility(name string) bool {
	base, _, _ := strings.Cut(name, ";")
	if op, ok := visibilityOperational[strings.ToLower(base)]; ok {
		return !op
	}
	at, ok := s.opts.Schema.AttributeType(base)
	return !ok || !at.Operational
}

// projectEntry applies attribute selection and per-attribute ACI read
// checks (C8), and strips values for typesOnly searches.
func (s *Server) projectEntry(ctx context.Context, tx ReadTx, subj Subject, dn config.DN, e *Entry, sel attrSelection, typesOnly bool) *Entry {
	out := &Entry{DN: e.DN}
	for _, a := range e.Attributes {
		if !sel.wants(s.opts.Schema, a.Name) {
			continue
		}
		// C8: a read-denied attribute is silently dropped, matching 389.
		if !s.allowed(ctx, tx, subj, dn, a.Name, PermRead) {
			continue
		}
		proj := Attribute{Name: a.Name}
		if !typesOnly {
			proj.Values = a.Values
		}
		out.Attributes = append(out.Attributes, proj)
	}
	return out
}

// VendorName is the native engine's vendor identity (parity Delta D1):
// deliberately distinct from the 389 "389-Directory/..." strings; parity
// tests assert inequality, never a specific value.
const VendorName = "LabLDAP"

// rootDSE builds the RFC 4512 section 5.1 Root DSE (parity contract C10).
// Only capabilities the engine honors are advertised (C9: never
// advertise-and-no-op): supportedControl lists Simple Paged Results
// (T-127, cookie integrity since T-140) and the RFC 4528 assertion control
// (T-141). supportedExtension lists the recognized extension OIDs whose
// handlers land in T-133 (StartTLS) and T-142 (WhoAmI) — dispatch answers
// them with unwillingToPerform until then. Delta D6: unknown 389 extras
// are omitted.
func namingContextValues(dns []config.DN) []string {
	out := make([]string, 0, len(dns))
	for _, d := range dns {
		out = append(out, d.String())
	}
	return out
}

func (s *Server) rootDSE() *Entry {
	return &Entry{
		DN: "",
		Attributes: []Attribute{
			StringAttribute("objectClass", "top"),
			StringAttribute("namingContexts", namingContextValues(s.suffixes)...),
			StringAttribute("subschemaSubentry", SubschemaDN),
			StringAttribute("supportedLDAPVersion", "3"),
			StringAttribute("supportedControl", OIDSimplePagedResults, OIDAssertion),
			StringAttribute("supportedExtension", OIDStartTLS, OIDWhoAmI),
			StringAttribute("vendorName", VendorName),
			StringAttribute("vendorVersion", observability.CurrentBuild("labldapd").Version),
		},
	}
}

// searchRootDSE answers a base-object search on the empty DN with the Root
// DSE (T-132, parity contract C10). Like 389, the DSE is readable without
// a bind and is not subject to ACI: capability inspection runs pre-bind.
// One-level and subtree searches on "" miss the DSE (RFC 4511 section
// 4.5.1: it belongs to no naming context); 389 answers those with
// noSuchObject, matched here (Delta candidate for the T-147 oracle).
func (s *Server) searchRootDSE(ctx context.Context, c *conn, m *Message, req *SearchRequest) ResultCode {
	if req.Scope != ScopeBaseObject {
		return s.answerSynthetic(ctx, c, m, req, nil, "root DSE requires a base-object search")
	}
	return s.answerSynthetic(ctx, c, m, req, s.rootDSE(), "")
}

// searchSubschema answers searches addressed at the subschema subentry
// (cn=subschema, plus the 389-shaped cn=schema alias the control plane's
// capability inspect reads). Base and subtree return the subentry when the
// filter matches; one-level has no subordinates. Like 389, the subschema
// is world-readable.
func (s *Server) searchSubschema(ctx context.Context, c *conn, m *Message, req *SearchRequest) ResultCode {
	entry := subschemaEntry(s.opts.Schema, req.BaseDN)
	if req.Scope == ScopeSingleLevel || req.Scope == ScopeChildren {
		return s.answerSynthetic(ctx, c, m, req, nil, "")
	}
	return s.answerSynthetic(ctx, c, m, req, entry, "")
}

// answerSynthetic completes a search against one synthetic entry (Root DSE
// or subschema). A nil entry answers success with no entries; a non-nil
// entry is filter-evaluated, attribute-selected, and sent. diag non-empty
// converts the whole search to noSuchObject (Root DSE with a non-base
// scope).
func (s *Server) answerSynthetic(ctx context.Context, c *conn, m *Message, req *SearchRequest, e *Entry, diag string) ResultCode {
	done := func(res Result) ResultCode {
		if ctx.Err() == nil {
			_ = c.send(&Message{ID: m.ID, Op: &SearchResultDone{Result: res}})
		}
		return res.Code
	}
	if diag != "" {
		return done(Result{Code: ResultNoSuchObject, DiagnosticMessage: diag})
	}
	if e == nil || (req.Filter != nil && !matchFilter(e, req.Filter, s.opts.Schema)) {
		return done(Result{Code: ResultSuccess})
	}
	out := selectDSEAttrs(e, parseAttrSelection(req.Attributes))
	if ctx.Err() != nil {
		return ResultOperationsError
	}
	if err := c.send(&Message{ID: m.ID, Op: &SearchResultEntry{DN: out.DN, Attributes: out.Attributes}}); err != nil {
		return ResultOperationsError
	}
	return done(Result{Code: ResultSuccess})
}

// selectDSEAttrs applies the attribute selection to a synthetic entry
// (Root DSE, subschema). 389 returns the full published set for an empty
// or "*" selection rather than hiding operational attributes behind "+"
// (observed); the capability inspector names its attributes explicitly, so
// both paths agree. "1.1" still suppresses everything.
func selectDSEAttrs(e *Entry, sel attrSelection) *Entry {
	out := &Entry{DN: e.DN}
	if sel.none {
		return out
	}
	for _, a := range e.Attributes {
		_, named := sel.names[strings.ToLower(a.Name)]
		if named || sel.allUser || sel.allOperational {
			out.Attributes = append(out.Attributes, a)
		}
	}
	return out
}

// Search permission applies to each filter attribute, independently of read
// permission for returned values. Denied assertions are Undefined rather than
// false so NOT cannot turn an inaccessible attribute into an existence oracle.
type filterTruth uint8

const (
	filterFalse filterTruth = iota
	filterTrue
	filterUndefined
)

func (s *Server) matchSearchFilter(ctx context.Context, tx ReadTx, subj Subject, dn config.DN, e *Entry, f Filter) filterTruth {
	var attr string
	switch n := f.(type) {
	case *FilterAnd:
		result := filterTrue
		for _, child := range n.Children {
			v := s.matchSearchFilter(ctx, tx, subj, dn, e, child)
			if v == filterFalse {
				return filterFalse
			}
			if v == filterUndefined {
				result = filterUndefined
			}
		}
		return result
	case *FilterOr:
		result := filterFalse
		for _, child := range n.Children {
			v := s.matchSearchFilter(ctx, tx, subj, dn, e, child)
			if v == filterTrue {
				return filterTrue
			}
			if v == filterUndefined {
				result = filterUndefined
			}
		}
		return result
	case *FilterNot:
		switch s.matchSearchFilter(ctx, tx, subj, dn, e, n.Child) {
		case filterTrue:
			return filterFalse
		case filterFalse:
			return filterTrue
		default:
			return filterUndefined
		}
	case *FilterEquality:
		attr = n.Attr
	case *FilterSubstrings:
		attr = n.Attr
	case *FilterPresent:
		attr = n.Attr
	case *FilterGreaterOrEqual:
		attr = n.Attr
	case *FilterLessOrEqual:
		attr = n.Attr
	case *FilterApproxMatch:
		attr = n.Attr
	default:
		return filterUndefined
	}
	// The search-permission identity of a leaf is the attribute type its
	// description resolves to (userid, the uid OID and uid;x-test are all
	// uid). An unresolved description (second descriptor or OID with
	// options) is checked under its literal base, as the oracle does; its
	// value set is always empty, so allowing it reveals no attribute data.
	d := parseAttrDesc(s.opts.Schema, attr)
	if !s.allowedIdentity(ctx, tx, subj, dn, d.name, PermSearch) {
		return filterUndefined
	}
	if matchLeaf(e, f, d, NewRuleMatcher(s.opts.Schema)) {
		return filterTrue
	}
	return filterFalse
}

// Only a required equality term (standalone or within AND) may narrow the
// result. DN-valued postings deliberately retain traversal fallback because
// their lowercased keys do not cover every Unicode EqualFold equivalence.
func indexedSearchPredicate(f Filter) *FilterEquality {
	switch n := f.(type) {
	case *FilterEquality:
		switch strings.ToLower(n.Attr) {
		case "uid", "cn", "objectclass":
			return n
		}
	case *FilterAnd:
		for _, child := range n.Children {
			if p := indexedSearchPredicate(child); p != nil {
				return p
			}
		}
	}
	return nil
}

func searchScopeContains(base, dn config.DN, scope Scope) bool {
	switch scope {
	case ScopeBaseObject:
		return dn.EqualFold(base)
	case ScopeWholeSubtree:
		return aciTargetScopeA(dn, base)
	case ScopeSingleLevel, ScopeChildren:
		parent, ok := parentDN(dn)
		return ok && parent.EqualFold(base)
	default:
		return false
	}
}
