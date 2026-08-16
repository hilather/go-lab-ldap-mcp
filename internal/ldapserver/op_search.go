package ldapserver

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

// errSearchLimit stops candidate iteration once the size or time limit has
// been recorded on the search outcome.
var errSearchLimit = errors.New("ldapserver: search limit reached")

// pageRequest is the decoded Simple Paged Results control (RFC 2696,
// OIDSimplePagedResults).
type pageRequest struct {
	size   int
	offset int
}

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
	return s.runSearch(ctx, c, m, req, c.subject())
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
	page, res, err := parsePagedControl(m.Controls)
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
		var candidates []*Entry
		var err error
		switch req.Scope {
		case ScopeBaseObject:
			e, err2 := tx.Entry(ctx, base)
			if err2 != nil {
				return err2
			}
			candidates = []*Entry{e}
		case ScopeSingleLevel, ScopeChildren:
			candidates, err = tx.Children(ctx, base)
			if err != nil {
				return err
			}
		case ScopeWholeSubtree:
			candidates, err = tx.Subtree(ctx, base)
			if err != nil {
				return err
			}
		}
		for _, e := range candidates {
			if err := ctx.Err(); err != nil {
				return err
			}
			if time.Now().After(deadline) {
				code = ResultTimeLimitExceeded
				return errSearchLimit
			}
			if len(matched) >= sizeLimit {
				code = ResultSizeLimitExceeded
				return errSearchLimit
			}
			entryDN, err := config.ParseDN(e.DN)
			if err != nil {
				continue // store invariant violation; never fail the search
			}
			// C8: search-permission denial filters the entry out.
			if !s.allowed(ctx, tx, subj, entryDN, "", PermSearch) {
				continue
			}
			if !matchFilter(e, req.Filter, s.opts.Schema) {
				continue
			}
			matched = append(matched, s.projectEntry(ctx, tx, subj, entryDN, e, sel, req.TypesOnly))
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

	pageControls, paged := applyPaging(matched, page, sizeLimit)
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
// Only capabilities the engine honors are advertised: supportedControl
// lists Simple Paged Results (T-127); the RFC 4528 assertion control stays
// unadvertised until T-141 honors it (C9: never advertise-and-no-op).
// supportedExtension lists the recognized extension OIDs whose handlers
// land in T-133 (StartTLS) and T-142 (WhoAmI) — dispatch answers them with
// unwillingToPerform until then. Delta D6: unknown 389 extras are omitted.
func (s *Server) rootDSE() *Entry {
	return &Entry{
		DN: "",
		Attributes: []Attribute{
			StringAttribute("objectClass", "top"),
			StringAttribute("namingContexts", s.suffix.String()),
			StringAttribute("subschemaSubentry", SubschemaDN),
			StringAttribute("supportedLDAPVersion", "3"),
			StringAttribute("supportedControl", OIDSimplePagedResults),
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

// pagedResult is the sliced page plus the next cookie.
type pagedResult struct {
	out        []*Entry
	nextCookie []byte
	size       int
}

// applyPaging slices the full result set for a paged search. An offset past
// the end yields an empty page with an empty cookie (RFC 2696; the
// index-out-of-range behavior pinned for T-127). Cookie integrity arrives
// with T-140; the cookie is the plain next offset until then.
func applyPaging(matched []*Entry, page *pageRequest, sizeLimit int) ([]Control, pagedResult) {
	if page == nil {
		return nil, pagedResult{}
	}
	size := page.size
	if size <= 0 || size > sizeLimit {
		size = sizeLimit
	}
	start := page.offset
	if start > len(matched) {
		start = len(matched)
	}
	end := start + size
	if end > len(matched) {
		end = len(matched)
	}
	var cookie []byte
	if end < len(matched) {
		cookie = []byte(strconv.Itoa(end))
	}
	return []Control{{OID: OIDSimplePagedResults, Value: encodePagedCookie(size, cookie)}},
		pagedResult{out: matched[start:end], nextCookie: cookie, size: size}
}

// parsePagedControl decodes the RFC 2696 control value. A malformed value
// or cookie fails with protocolError / unwillingToPerform; an absent
// control yields a nil page request.
func parsePagedControl(controls []Control) (*pageRequest, Result, error) {
	var raw []byte
	found := false
	for _, ctrl := range controls {
		if ctrl.OID == OIDSimplePagedResults {
			raw, found = ctrl.Value, true
		}
	}
	if !found {
		return nil, Result{}, nil
	}
	pkt := ber.DecodePacket(raw)
	if pkt == nil || pkt.ClassType != ber.ClassUniversal || pkt.TagType != ber.TypeConstructed || len(pkt.Children) != 2 {
		return nil, Result{Code: ResultProtocolError, DiagnosticMessage: "malformed paged results control"}, fmt.Errorf("ldapserver: paged results control decode")
	}
	size, err := packetInt(pkt.Children[0])
	if err != nil || size < 0 || size > maxInt32 {
		return nil, Result{Code: ResultProtocolError, DiagnosticMessage: "malformed paged results size"}, fmt.Errorf("ldapserver: paged results size decode")
	}
	offset := 0
	if c := pkt.Children[1].Data.Bytes(); len(c) > 0 {
		// RFC 2696 leaves a malformed cookie to the server; T-140 adds
		// real cookie integrity, until then an unparsable cookie fails.
		n, err := strconv.Atoi(string(c))
		if err != nil || n < 0 {
			return nil, Result{Code: ResultUnwillingToPerform, DiagnosticMessage: "invalid paged results cookie"}, fmt.Errorf("ldapserver: paged results cookie decode")
		}
		offset = n
	}
	return &pageRequest{size: int(size), offset: offset}, Result{}, nil
}

// encodePagedCookie builds the RFC 2696 response control value: the server
// size estimate (0: unknown) and the opaque cookie.
func encodePagedCookie(size int, cookie []byte) []byte {
	pkt := ber.NewSequence("pagedResultsControl")
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(size), "size"))
	c := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "cookie")
	c.Data.Write(cookie)
	pkt.AppendChild(c)
	return pkt.Bytes()
}
