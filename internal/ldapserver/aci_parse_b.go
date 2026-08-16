package ldapserver

import (
	"errors"
	"fmt"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// This file is the T-138 (attempt B) parser for the ACI text the LabLDAP
// compiler emits (parity contract C8). The grammar is deliberately the
// compiler subset and nothing more:
//
//	aci        := 1*(clause)
//	clause     := target | targetattr | body
//	target     := "(" "target" "=" %x22 "ldap:///" dn %x22 ")"
//	targetattr := "(" "targetattr" ("=" / "!=") %x22 attr *("|" attr) %x22 ")"
//	body       := "(" "version" "3.0" ";" "acl" %x22 name %x22 ";"
//	              ("allow" / "deny") "(" perm *("," perm) ")" who ";" ")"
//	who        := ("userdn" / "groupdn") "=" %x22 "ldap:///" (dn / "all" / "anyone" / "self") %x22
//
// Quoted productions carry the compiler's escaping (aciEscape in
// internal/config): \\, \", and \HH hex bytes. Anything else between quotes
// — parens, semicolons, commas, asterisks — is data and can never open a new
// clause. Out-of-grammar input is rejected (fail-closed), never ignored.
//
// Parsing is single-pass recursive descent over a byte cursor: no regex, no
// recursion, input length bounded. The parser never panics and never echoes
// quoted input values into error messages (ACIs carry no credentials, and
// stable errors are easier to match in tests and logs).

// maxACITextLenB bounds accepted ACI text. Compiler-emitted ACIs are a few
// hundred bytes; 64 KiB leaves generous headroom for operator raw ACI while
// rejecting absurd input before any scanning work.
const maxACITextLenB = 1 << 16

// ErrACIParseB is the stable identity of every ACI parse failure. Callers
// match it with errors.Is; the wrapped detail is secret-free.
var ErrACIParseB = errors.New("ldapserver: invalid ACI")

// ACIAttrsB is the parsed targetattr rule. Exactly one of three shapes holds:
// all attributes (All), an allow list (Names), or a deny list (Except with
// Names: every attribute except the listed ones).
type ACIAttrsB struct {
	// All is true when the clause was omitted or was targetattr="*".
	All bool
	// Except is true for the targetattr!= form.
	Except bool
	// Names holds the listed attribute types, lowercased. Nil when All.
	Names []string
}

// Includes reports whether the rule covers attr (case-insensitive, per LDAP
// attribute description matching).
func (a ACIAttrsB) Includes(attr string) bool {
	if a.Except {
		return !aciAttrListedB(a.Names, attr)
	}
	if a.All {
		return true
	}
	return aciAttrListedB(a.Names, attr)
}

func aciAttrListedB(names []string, attr string) bool {
	for _, n := range names {
		if strings.EqualFold(n, attr) {
			return true
		}
	}
	return false
}

// ACISubjectKindB identifies which bind-rule form the ACI grants to.
type ACISubjectKindB int

const (
	// ACISubjectDNB is userdn="ldap:///<dn>": the bound entry exactly.
	ACISubjectDNB ACISubjectKindB = iota
	// ACISubjectGroupB is groupdn="ldap:///<dn>": members of that group.
	ACISubjectGroupB
	// ACISubjectAllB is userdn="ldap:///all": any authenticated identity.
	ACISubjectAllB
	// ACISubjectAnyoneB is userdn="ldap:///anyone": including anonymous.
	ACISubjectAnyoneB
	// ACISubjectSelfB is userdn="ldap:///self": the target entry itself.
	ACISubjectSelfB
)

func (k ACISubjectKindB) String() string {
	switch k {
	case ACISubjectDNB:
		return "userdn"
	case ACISubjectGroupB:
		return "groupdn"
	case ACISubjectAllB:
		return "all"
	case ACISubjectAnyoneB:
		return "anyone"
	case ACISubjectSelfB:
		return "self"
	default:
		return "unknown"
	}
}

// ACISubjectB is the parsed bind rule. DN is meaningful for ACISubjectDNB
// and ACISubjectGroupB only.
type ACISubjectB struct {
	Kind ACISubjectKindB
	DN   config.DN
}

// ParsedACIB is one ACI in structured form, ready for the ACIEngine seam
// (T-139): which identity (Subject) gets which effect (Deny) for which
// Permissions on entries under TargetDN for attributes per Attrs.
type ParsedACIB struct {
	// ID is the acl "<name>" value, e.g. "labldap:runtime-suffix-read".
	ID string
	// TargetDN scopes the ACI: the entry is this DN or a descendant (C8).
	TargetDN config.DN
	// Attrs is the targetattr rule.
	Attrs ACIAttrsB
	// Deny is true for deny, false for allow. Deny wins at evaluation (C8).
	Deny bool
	// Permissions are the granted/denied rights in emitted order.
	Permissions []Permission
	// Subject is the bind rule.
	Subject ACISubjectB
}

// HasPermission reports whether perm is in the ACI's permission set.
func (p *ParsedACIB) HasPermission(perm Permission) bool {
	for _, q := range p.Permissions {
		if q == perm {
			return true
		}
	}
	return false
}

// aciPermSetB is the closed compiler permission vocabulary (C8).
var aciPermSetB = map[string]Permission{
	"read":    PermRead,
	"search":  PermSearch,
	"compare": PermCompare,
	"add":     PermAdd,
	"delete":  PermDelete,
	"write":   PermWrite,
}

// aciLDAPPrefixB is the only bind/target URL scheme the compiler emits.
const aciLDAPPrefixB = "ldap:///"

// ParseACITextB parses one ACI string in the compiler subset into structured
// form. The whole input must be consumed; unknown clauses, keywords, or
// permissions are rejected (fail-closed per C8). Every failure wraps
// ErrACIParseB and the parser never panics on malformed input.
func ParseACITextB(text string) (*ParsedACIB, error) {
	if text == "" {
		return nil, fmt.Errorf("%w: empty input", ErrACIParseB)
	}
	if len(text) > maxACITextLenB {
		return nil, fmt.Errorf("%w: input exceeds %d bytes", ErrACIParseB, maxACITextLenB)
	}
	if strings.IndexByte(text, 0) >= 0 {
		return nil, fmt.Errorf("%w: input contains NUL", ErrACIParseB)
	}
	p := &aciParserB{s: text}
	out := &ParsedACIB{}
	var haveTarget, haveAttrs, haveBody bool
	for {
		p.skipWS()
		if p.atEnd() {
			break
		}
		if err := p.expectByte('(', "start of ACI clause"); err != nil {
			return nil, err
		}
		p.skipWS()
		switch {
		case p.keyword("targetattr"):
			if haveAttrs {
				return nil, p.errf("duplicate targetattr clause")
			}
			a, err := p.parseTargetAttrB()
			if err != nil {
				return nil, err
			}
			out.Attrs = a
			haveAttrs = true
		case p.keyword("target"):
			if haveTarget {
				return nil, p.errf("duplicate target clause")
			}
			d, err := p.parseTargetB()
			if err != nil {
				return nil, err
			}
			out.TargetDN = d
			haveTarget = true
		case p.keyword("version"):
			if haveBody {
				return nil, p.errf("duplicate version/acl body clause")
			}
			if err := p.parseBodyB(out); err != nil {
				return nil, err
			}
			haveBody = true
		default:
			return nil, p.errf("unknown ACI clause")
		}
		p.skipWS()
		if err := p.expectByte(')', "end of ACI clause"); err != nil {
			return nil, err
		}
	}
	if !haveTarget {
		return nil, fmt.Errorf("%w: missing target clause", ErrACIParseB)
	}
	if !haveBody {
		return nil, fmt.Errorf("%w: missing version/acl body clause", ErrACIParseB)
	}
	if !haveAttrs {
		// 389 semantics for an omitted targetattr: all attributes.
		out.Attrs = ACIAttrsB{All: true}
	}
	return out, nil
}

// aciParserB is a single-pass byte cursor over the input.
type aciParserB struct {
	s string
	i int
}

func (p *aciParserB) errf(format string, args ...any) error {
	return fmt.Errorf("%w: offset %d: %s", ErrACIParseB, p.i, fmt.Sprintf(format, args...))
}

func (p *aciParserB) atEnd() bool { return p.i >= len(p.s) }

func isACISpaceB(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

func (p *aciParserB) skipWS() {
	for !p.atEnd() && isACISpaceB(p.s[p.i]) {
		p.i++
	}
}

func (p *aciParserB) expectByte(c byte, what string) error {
	if p.atEnd() || p.s[p.i] != c {
		return p.errf("expected %s", what)
	}
	p.i++
	return nil
}

func isACIKeywordCharB(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

// keyword consumes kw when it appears at the cursor followed by a non-keyword
// boundary, so "target" never matches the head of "targetattr".
func (p *aciParserB) keyword(kw string) bool {
	if !strings.HasPrefix(p.s[p.i:], kw) {
		return false
	}
	if p.i+len(kw) < len(p.s) && isACIKeywordCharB(p.s[p.i+len(kw)]) {
		return false
	}
	p.i += len(kw)
	return true
}

func isACIHexB(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func aciUnhexB(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// quoted parses a '"' ... '"' production and returns the unescaped value.
// The scan is escape-aware, so a quote preceded by a backslash never
// terminates the value and parentheses or semicolons inside the quotes are
// data. Escape rules mirror the compiler: \HH is a hex byte, \c for any
// non-hex c is the literal c (covers \\ and \").
func (p *aciParserB) quoted(what string) (string, error) {
	if err := p.expectByte('"', "opening quote for "+what); err != nil {
		return "", err
	}
	var b strings.Builder
	for {
		if p.atEnd() {
			return "", p.errf("unterminated quoted %s", what)
		}
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return b.String(), nil
		case c == 0:
			return "", p.errf("NUL byte in quoted %s", what)
		case c == '\\':
			if p.i+1 >= len(p.s) {
				return "", p.errf("dangling escape in quoted %s", what)
			}
			n := p.s[p.i+1]
			if isACIHexB(n) {
				if p.i+2 >= len(p.s) || !isACIHexB(p.s[p.i+2]) {
					return "", p.errf("incomplete hex escape in quoted %s", what)
				}
				v := aciUnhexB(n)<<4 | aciUnhexB(p.s[p.i+2])
				if v == 0 {
					return "", p.errf("NUL escape in quoted %s", what)
				}
				b.WriteByte(v)
				p.i += 3
			} else {
				b.WriteByte(n)
				p.i += 2
			}
		default:
			b.WriteByte(c)
			p.i++
		}
	}
}

// ldapURLDNB validates the ldap:///<dn> shape of a quoted target or bind-rule
// value and parses the DN structurally. The DN text passes through config DN
// parsing, which applies its own RFC 4514 unescaping underneath the ACI
// escaping this parser already removed.
func (p *aciParserB) ldapURLDNB(raw, what string) (config.DN, error) {
	if !strings.HasPrefix(raw, aciLDAPPrefixB) {
		return config.DN{}, p.errf("%s must use the ldap:/// URL form", what)
	}
	d, err := config.ParseDN(raw[len(aciLDAPPrefixB):])
	if err != nil {
		return config.DN{}, p.errf("%s DN is not valid: %v", what, err)
	}
	return d, nil
}

func (p *aciParserB) parseTargetB() (config.DN, error) {
	p.skipWS()
	if err := p.expectByte('=', "equals after target"); err != nil {
		return config.DN{}, err
	}
	p.skipWS()
	raw, err := p.quoted("target")
	if err != nil {
		return config.DN{}, err
	}
	return p.ldapURLDNB(raw, "target")
}

// validACIAttrNameB mirrors the compiler's aciAttrRe (minus the wildcard,
// which is handled separately): a letter followed by letters, digits,
// hyphens, or semicolons (attribute options such as cn;lang-en).
func validACIAttrNameB(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		letter := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		if i == 0 {
			if !letter {
				return false
			}
			continue
		}
		if !letter && !(c >= '0' && c <= '9') && c != '-' && c != ';' {
			return false
		}
	}
	return s != ""
}

func (p *aciParserB) parseTargetAttrB() (ACIAttrsB, error) {
	p.skipWS()
	var except bool
	if strings.HasPrefix(p.s[p.i:], "!=") {
		except = true
		p.i += 2
	} else if err := p.expectByte('=', "equals or not-equals after targetattr"); err != nil {
		return ACIAttrsB{}, err
	}
	p.skipWS()
	raw, err := p.quoted("targetattr")
	if err != nil {
		return ACIAttrsB{}, err
	}
	parts := strings.Split(raw, "|")
	names := make([]string, 0, len(parts))
	wild := false
	for _, part := range parts {
		a := strings.TrimSpace(part)
		if a == "" {
			return ACIAttrsB{}, p.errf("empty attribute in targetattr list")
		}
		if a == "*" {
			wild = true
			continue
		}
		if !validACIAttrNameB(a) {
			return ACIAttrsB{}, p.errf("invalid attribute name in targetattr")
		}
		names = append(names, strings.ToLower(a))
	}
	if wild {
		if len(parts) != 1 {
			return ACIAttrsB{}, p.errf("wildcard * must be the only targetattr element")
		}
		if except {
			return ACIAttrsB{}, p.errf("wildcard * is not valid in targetattr!=")
		}
		return ACIAttrsB{All: true}, nil
	}
	return ACIAttrsB{Except: except, Names: names}, nil
}

func (p *aciParserB) parseBodyB(out *ParsedACIB) error {
	p.skipWS()
	if !p.keyword("3.0") {
		return p.errf("expected version 3.0")
	}
	p.skipWS()
	if err := p.expectByte(';', "semicolon after version"); err != nil {
		return err
	}
	p.skipWS()
	if !p.keyword("acl") {
		return p.errf("expected acl name clause")
	}
	p.skipWS()
	name, err := p.quoted("acl name")
	if err != nil {
		return err
	}
	if name == "" {
		return p.errf("acl name is empty")
	}
	p.skipWS()
	if err := p.expectByte(';', "semicolon after acl name"); err != nil {
		return err
	}
	p.skipWS()
	switch {
	case p.keyword("allow"):
		out.Deny = false
	case p.keyword("deny"):
		out.Deny = true
	default:
		return p.errf("expected allow or deny")
	}
	p.skipWS()
	if err := p.expectByte('(', "permission list"); err != nil {
		return err
	}
	perms, err := p.parsePermsB()
	if err != nil {
		return err
	}
	p.skipWS()
	subj, err := p.parseWhoB()
	if err != nil {
		return err
	}
	p.skipWS()
	if err := p.expectByte(';', "semicolon after bind rule"); err != nil {
		return err
	}
	out.ID = name
	out.Permissions = perms
	out.Subject = subj
	return nil
}

func (p *aciParserB) parsePermsB() ([]Permission, error) {
	var perms []Permission
	seen := map[Permission]struct{}{}
	for {
		p.skipWS()
		start := p.i
		for !p.atEnd() && (p.s[p.i] >= 'a' && p.s[p.i] <= 'z' || p.s[p.i] >= 'A' && p.s[p.i] <= 'Z') {
			p.i++
		}
		word := p.s[start:p.i]
		perm, ok := aciPermSetB[word]
		if !ok {
			if word == "" {
				return nil, p.errf("expected permission")
			}
			return nil, p.errf("unknown permission")
		}
		if _, dup := seen[perm]; dup {
			return nil, p.errf("duplicate permission")
		}
		seen[perm] = struct{}{}
		perms = append(perms, perm)
		p.skipWS()
		if p.atEnd() {
			return nil, p.errf("unterminated permission list")
		}
		switch p.s[p.i] {
		case ',':
			p.i++
		case ')':
			p.i++
			return perms, nil
		default:
			return nil, p.errf("expected comma or close of permission list")
		}
	}
}

func (p *aciParserB) parseWhoB() (ACISubjectB, error) {
	var group bool
	switch {
	case p.keyword("userdn"):
	case p.keyword("groupdn"):
		group = true
	default:
		return ACISubjectB{}, p.errf("expected userdn or groupdn bind rule")
	}
	p.skipWS()
	if err := p.expectByte('=', "equals after bind rule"); err != nil {
		return ACISubjectB{}, err
	}
	p.skipWS()
	raw, err := p.quoted("bind rule")
	if err != nil {
		return ACISubjectB{}, err
	}
	if !strings.HasPrefix(raw, aciLDAPPrefixB) {
		return ACISubjectB{}, p.errf("bind rule must use the ldap:/// URL form")
	}
	rest := raw[len(aciLDAPPrefixB):]
	if !group {
		switch rest {
		case "all":
			return ACISubjectB{Kind: ACISubjectAllB}, nil
		case "anyone":
			return ACISubjectB{Kind: ACISubjectAnyoneB}, nil
		case "self":
			return ACISubjectB{Kind: ACISubjectSelfB}, nil
		}
	}
	d, err := p.ldapURLDNB(raw, "bind rule")
	if err != nil {
		return ACISubjectB{}, err
	}
	if group {
		return ACISubjectB{Kind: ACISubjectGroupB, DN: d}, nil
	}
	return ACISubjectB{Kind: ACISubjectDNB, DN: d}, nil
}
