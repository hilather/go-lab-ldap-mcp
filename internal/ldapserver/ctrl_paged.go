package ldapserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// Simple Paged Results control (RFC 2696, OIDSimplePagedResults) with
// cookie integrity (T-140, parity contract C9).
//
// The cookie is opaque to clients and carries the next offset plus an
// HMAC-SHA256 tag keyed by a server-held random secret generated at startup
// (Server.pageKey). The tag also binds the query identity — canonical base
// DN, scope, and filter — so a cookie replayed against a different search
// fails instead of silently paging the wrong result set. Consequences:
//
//   - Cookies are per-server-instance: the key is never persisted, never
//     configured, and never logged, so a restart invalidates outstanding
//     cookies and the client simply restarts paging (RFC 2696 already
//     requires clients to cope with invalidated cookies).
//   - A tampered, foreign, or cross-query cookie fails with
//     unwillingToPerform (53). 389's exact result code for a bad cookie is
//     unverified — recorded as a Delta candidate for the T-147 oracle.
//   - The client may still change page size between requests (RFC 2696);
//     the size is not part of the binding.
//
// Cookie values are never logged: they embed query state and are treated
// as sensitive diagnostics input (AGENTS.md logging rules).

// pageCookiePrefix versions the cookie format so a future format change is
// distinguishable from v1 cookies (which then fail closed, never misparse).
const pageCookiePrefix = "v1."

// maxCookieBytes bounds the cookie length accepted off the wire; a valid v1
// cookie is at most a 20-digit offset plus prefix, separator, and a 43-byte
// base64url tag.
const maxCookieBytes = 128

// pageRequest is the decoded Simple Paged Results control (RFC 2696,
// OIDSimplePagedResults).
type pageRequest struct {
	size   int
	offset int
	// binding is the query binding the presented cookie verified against;
	// the response cookie is signed with the same binding.
	binding []byte
}

// pagedResult is the sliced page plus the next cookie.
type pagedResult struct {
	out        []*Entry
	nextCookie []byte
	size       int
}

// pagedQueryBinding derives the canonical query identity a cookie is bound
// to: the folded base DN, the scope, and the BER encoding of the filter
// (the encoder is deterministic, so equal queries bind equally). Attribute
// selection, typesOnly, and limits are deliberately excluded: varying them
// between pages does not change the result set the offset walks.
func pagedQueryBinding(base config.DN, req *SearchRequest) ([]byte, error) {
	fp, err := encodeFilter(req.Filter, 0)
	if err != nil {
		return nil, fmt.Errorf("ldapserver: paged results binding: %w", err)
	}
	var b []byte
	b = append(b, base.FoldedKey()...)
	b = append(b, 0)
	b = append(b, byte(req.Scope))
	b = append(b, 0)
	b = append(b, fp.Bytes()...)
	return b, nil
}

// pageCookieMAC tags one offset under one query binding with the
// per-instance key.
func (s *Server) pageCookieMAC(binding []byte, offset int) []byte {
	mac := hmac.New(sha256.New, s.pageKey)
	mac.Write([]byte("labldapd-paged-v1"))
	mac.Write([]byte{0})
	mac.Write(binding)
	mac.Write([]byte{0})
	mac.Write([]byte(strconv.Itoa(offset)))
	return mac.Sum(nil)
}

// encodePageCookie builds the signed cookie for the next page.
func (s *Server) encodePageCookie(binding []byte, offset int) []byte {
	sum := s.pageCookieMAC(binding, offset)
	return []byte(pageCookiePrefix + strconv.Itoa(offset) + "." + base64.RawURLEncoding.EncodeToString(sum))
}

// errPagedCookie marks any cookie integrity failure: bad shape, bad tag,
// or a cookie issued for a different query. It maps to
// unwillingToPerform; the diagnostic is a static string so cookie content
// never reaches the wire or the log.
var errPagedCookie = errors.New("ldapserver: invalid paged results cookie")

// decodePageCookie verifies and decodes a cookie. The empty cookie starts
// the first page at offset 0 (RFC 2696).
func (s *Server) decodePageCookie(binding []byte, cookie []byte) (int, error) {
	if len(cookie) == 0 {
		return 0, nil
	}
	if len(cookie) > maxCookieBytes {
		return 0, errPagedCookie
	}
	rest, ok := strings.CutPrefix(string(cookie), pageCookiePrefix)
	if !ok {
		return 0, errPagedCookie
	}
	offStr, macStr, ok := strings.Cut(rest, ".")
	if !ok {
		return 0, errPagedCookie
	}
	offset, err := strconv.Atoi(offStr)
	if err != nil || offset < 0 {
		return 0, errPagedCookie
	}
	got, err := base64.RawURLEncoding.DecodeString(macStr)
	if err != nil {
		return 0, errPagedCookie
	}
	if !hmac.Equal(got, s.pageCookieMAC(binding, offset)) {
		return 0, errPagedCookie
	}
	return offset, nil
}

// parsePagedControl decodes the RFC 2696 control value and verifies cookie
// integrity against this search's query binding. A malformed value fails
// protocolError; a cookie that fails integrity fails unwillingToPerform;
// an absent control yields a nil page request.
func (s *Server) parsePagedControl(controls []Control, base config.DN, req *SearchRequest) (*pageRequest, Result, error) {
	var raw []byte
	found := false
	for _, ctrl := range controls {
		if ctrl.OID != OIDSimplePagedResults {
			continue
		}
		if found {
			// RFC 2696 section 3: the control must not appear more than
			// once on a request.
			return nil, Result{Code: ResultProtocolError, DiagnosticMessage: "duplicate paged results control"}, fmt.Errorf("ldapserver: duplicate paged results control")
		}
		raw, found = ctrl.Value, true
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
	binding, err := pagedQueryBinding(base, req)
	if err != nil {
		return nil, Result{Code: ResultProtocolError, DiagnosticMessage: "malformed search filter"}, err
	}
	offset := 0
	if c := pkt.Children[1].Data.Bytes(); len(c) > 0 {
		n, err := s.decodePageCookie(binding, c)
		if err != nil {
			return nil, Result{Code: ResultUnwillingToPerform, DiagnosticMessage: "invalid paged results cookie"}, err
		}
		offset = n
	}
	return &pageRequest{size: int(size), offset: offset, binding: binding}, Result{}, nil
}

// applyPaging slices the full result set for a paged search and signs the
// continuation cookie. An offset past the end (the result set shrank
// between pages) yields an empty page with an empty cookie, not an error
// (RFC 2696; the T-127 behavior, kept).
func (s *Server) applyPaging(matched []*Entry, page *pageRequest, sizeLimit int) ([]Control, pagedResult) {
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
		cookie = s.encodePageCookie(page.binding, end)
	}
	return []Control{{OID: OIDSimplePagedResults, Value: encodePagedCookie(size, cookie)}},
		pagedResult{out: matched[start:end], nextCookie: cookie, size: size}
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
