package ldapserver

// ACI parser for the LabLDAP compiler subset (T-138, parity contract C8).
//
// The grammar accepted here is exactly what internal/config/acl.go emits,
// plus the documented raw-ACI surface (directory.allowRawACI) that stays
// inside the same grammar:
//
//	(target="ldap:///<dn>")
//	(targetattr="<attr>[|<attr>...]" | "*" | targetattr!="<attr>[|<attr>...]")
//	(version 3.0; acl "<name>"; allow|deny (<perm>[,<perm>...]) <who>;)
//	<who> = userdn="ldap:///<dn>|all|anyone|self" | groupdn="ldap:///<dn>"
//
// Fail-closed rule (C8): any clause, keyword, permission, bind rule, or
// escape outside this grammar is a parse error, never silently ignored.
// Parsing is two-phase: a lexer produces a token stream (quoted strings are
// single tokens, so injection characters inside quotes are data), then a
// recursive-descent parser assembles the structured ParsedACI.

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// MaxACITextBytesA bounds the input ParseACITextA accepts. Compiler output
// is a few hundred bytes; the bound rejects absurd operator-supplied input
// before any allocation work happens.
const MaxACITextBytesA = 64 * 1024

// The grammar has three clause kinds, each appearing at most once, so the
// clause count is self-bounding; these caps bound the unbounded productions.
const (
	aciMaxPermsA = 16
	aciMaxAttrsA = 64
	aciMaxIDLenA = 128
)

// ErrACIParseA is the sentinel every ParseACITextA failure wraps, so callers
// can classify with errors.Is without matching message text.
var ErrACIParseA = errors.New("ldapserver: invalid ACI")

// ACIParseErrorA is a stable, secret-free parse failure: a byte offset into
// the input plus a fixed reason phrase. Quoted-string contents (DNs, attribute
// lists, ACL names) are never embedded in Reason; only short bare tokens such
// as clause keywords and permission names are quoted when actionable.
type ACIParseErrorA struct {
	Offset int
	Reason string
}

func (e *ACIParseErrorA) Error() string {
	return fmt.Sprintf("ldapserver: aci: byte %d: %s", e.Offset, e.Reason)
}

func (e *ACIParseErrorA) Unwrap() error { return ErrACIParseA }

func aciErrA(off int, format string, args ...any) *ACIParseErrorA {
	return &ACIParseErrorA{Offset: off, Reason: fmt.Sprintf(format, args...)}
}

// aciTruncA bounds bare-token text echoed into error reasons so a garbage
// word cannot make an error message (and any log line it lands in) huge.
func aciTruncA(s string) string {
	const max = 40
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// ACITargetAttrModeA is the targetattr disposition of a parsed ACI.
type ACITargetAttrModeA int

const (
	// ACITargetAttrAllA covers targetattr="*" and an omitted targetattr
	// clause (389 semantics: all attributes).
	ACITargetAttrAllA ACITargetAttrModeA = iota
	// ACITargetAttrAllowA covers targetattr="a|b": only Attrs are targeted.
	ACITargetAttrAllowA
	// ACITargetAttrDenyA covers targetattr!="a|b": every attribute except
	// Attrs is targeted.
	ACITargetAttrDenyA
)

func (m ACITargetAttrModeA) String() string {
	switch m {
	case ACITargetAttrAllA:
		return "all"
	case ACITargetAttrAllowA:
		return "allow-list"
	case ACITargetAttrDenyA:
		return "deny-list"
	}
	return "unknown"
}

// ACISubjectKindA identifies the bind-rule subject form.
type ACISubjectKindA int

const (
	// ACISubjectUserDNA is userdn="ldap:///<dn>": the bound entry itself.
	ACISubjectUserDNA ACISubjectKindA = iota
	// ACISubjectGroupDNA is groupdn="ldap:///<dn>": members of the group.
	ACISubjectGroupDNA
	// ACISubjectAnyoneA is userdn="ldap:///anyone": authenticated or not.
	ACISubjectAnyoneA
	// ACISubjectAllA is userdn="ldap:///all": any authenticated identity.
	ACISubjectAllA
	// ACISubjectSelfA is userdn="ldap:///self": bound DN equals target DN.
	ACISubjectSelfA
)

func (k ACISubjectKindA) String() string {
	switch k {
	case ACISubjectUserDNA:
		return "userdn"
	case ACISubjectGroupDNA:
		return "groupdn"
	case ACISubjectAnyoneA:
		return "anyone"
	case ACISubjectAllA:
		return "all"
	case ACISubjectSelfA:
		return "self"
	}
	return "unknown"
}

// ACISubjectA is the parsed bind rule. DN is set for ACISubjectUserDNA (the
// user DN) and ACISubjectGroupDNA (the group DN); it is the zero config.DN
// for the keyword subjects.
type ACISubjectA struct {
	Kind ACISubjectKindA
	DN   config.DN
}

// ParsedACI is one compiler-subset ACI in structured form, ready for the
// T-139 evaluator behind the ACIEngine seam.
type ParsedACI struct {
	// ID is the acl "<name>" value, e.g. "labldap:runtime-suffix-read".
	ID string
	// TargetDN is the target="ldap:///<dn>" value. Evaluation scope (the
	// entry itself or descendants, per C8) is the evaluator's concern.
	TargetDN config.DN
	// AttrMode and Attrs carry the targetattr clause. Attrs is nil when
	// AttrMode is ACITargetAttrAllA.
	AttrMode ACITargetAttrModeA
	Attrs    []string
	// Deny reports a deny (...) rule instead of allow (...). Deny-wins
	// ordering across ACIs is the evaluator's concern (C8).
	Deny bool
	// Permissions holds the allow/deny permission list in emission order.
	Permissions []Permission
	// Subject is the single bind rule. Boolean combinators (and/or) and
	// multiple bind rules are outside the compiler grammar and rejected.
	Subject ACISubjectA
}

// HasPerm reports whether perm is in the ACI's permission list.
func (p *ParsedACI) HasPerm(perm Permission) bool {
	for _, q := range p.Permissions {
		if q == perm {
			return true
		}
	}
	return false
}

// TargetsAttr reports whether the targetattr clause covers attr. Attribute
// comparison is case-insensitive per LDAP attribute-type equality.
func (p *ParsedACI) TargetsAttr(attr string) bool {
	switch p.AttrMode {
	case ACITargetAttrAllA:
		return true
	case ACITargetAttrAllowA:
		return aciAttrInA(p.Attrs, attr)
	case ACITargetAttrDenyA:
		return !aciAttrInA(p.Attrs, attr)
	}
	return false
}

func aciAttrInA(list []string, attr string) bool {
	for _, a := range list {
		if strings.EqualFold(a, attr) {
			return true
		}
	}
	return false
}

// aciPermsA maps the lowercase permission word to the shared Permission
// values from aci.go. Anything absent (proxy, all, ...) is rejected.
var aciPermsA = map[string]Permission{
	"read":    PermRead,
	"search":  PermSearch,
	"compare": PermCompare,
	"add":     PermAdd,
	"delete":  PermDelete,
	"write":   PermWrite,
}

// aciAttrNameReA mirrors the compiler's aciAttrRe so the parser accepts
// exactly the attribute tokens the emitter can produce (including ";" for
// attribute options such as userCertificate;binary).
var aciAttrNameReA = regexp.MustCompile(`^(\*|[A-Za-z][A-Za-z0-9-;]*)$`)

// aciTokKindA classifies lexer tokens.
type aciTokKindA int

const (
	aciTokEOF aciTokKindA = iota
	aciTokLParen
	aciTokRParen
	aciTokSemi
	aciTokComma
	aciTokEquals
	aciTokBang
	aciTokWord
	aciTokQString
)

type aciTokenA struct {
	kind aciTokKindA
	text string // word bytes, or the unescaped quoted-string value
	pos  int    // byte offset of the token start in the input
}

func aciTokDescA(t aciTokenA) string {
	switch t.kind {
	case aciTokEOF:
		return "end of input"
	case aciTokLParen:
		return "'('"
	case aciTokRParen:
		return "')'"
	case aciTokSemi:
		return "';'"
	case aciTokComma:
		return "','"
	case aciTokEquals:
		return "'='"
	case aciTokBang:
		return "'!'"
	case aciTokWord:
		return fmt.Sprintf("%q", aciTruncA(t.text))
	case aciTokQString:
		return "a quoted string"
	}
	return "a token"
}

func aciIsSpaceA(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}

func aciIsDelimA(c byte) bool {
	if aciIsSpaceA(c) {
		return true
	}
	switch c {
	case '(', ')', ';', ',', '=', '!', '"':
		return true
	}
	return false
}

func aciHexValA(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// aciLexQStringA scans the quoted string starting at text[start] (which must
// be '"') and returns the unescaped value plus the offset just past the
// closing quote. The compiler's aciEscape emits \\, \" and \HH hex, so those
// are the only escapes accepted; anything else is an error (fail-closed).
// NUL is rejected so unescaped values stay safe for downstream string use.
func aciLexQStringA(text string, start int) (string, int, error) {
	var b []byte
	i := start + 1
	for i < len(text) {
		c := text[i]
		switch c {
		case '"':
			if !utf8.Valid(b) {
				return "", 0, aciErrA(start, "quoted value is not valid UTF-8")
			}
			return string(b), i + 1, nil
		case '\\':
			if i+1 >= len(text) {
				return "", 0, aciErrA(i, "dangling escape at end of input")
			}
			n := text[i+1]
			switch {
			case n == '\\' || n == '"':
				b = append(b, n)
				i += 2
			default:
				hi, ok := aciHexValA(n)
				if !ok {
					return "", 0, aciErrA(i, "invalid escape sequence")
				}
				if i+2 >= len(text) {
					return "", 0, aciErrA(i, "truncated hex escape")
				}
				lo, ok := aciHexValA(text[i+2])
				if !ok {
					return "", 0, aciErrA(i, "truncated hex escape")
				}
				v := hi<<4 | lo
				if v == 0 {
					return "", 0, aciErrA(i, "NUL byte is not allowed in ACI values")
				}
				b = append(b, v)
				i += 3
			}
		default:
			b = append(b, c)
			i++
		}
	}
	return "", 0, aciErrA(start, "unterminated quoted string")
}

func aciLexA(text string) ([]aciTokenA, error) {
	toks := make([]aciTokenA, 0, 32)
	i := 0
	for i < len(text) {
		c := text[i]
		switch {
		case aciIsSpaceA(c):
			i++
		case c == '(':
			toks = append(toks, aciTokenA{kind: aciTokLParen, pos: i})
			i++
		case c == ')':
			toks = append(toks, aciTokenA{kind: aciTokRParen, pos: i})
			i++
		case c == ';':
			toks = append(toks, aciTokenA{kind: aciTokSemi, pos: i})
			i++
		case c == ',':
			toks = append(toks, aciTokenA{kind: aciTokComma, pos: i})
			i++
		case c == '=':
			toks = append(toks, aciTokenA{kind: aciTokEquals, pos: i})
			i++
		case c == '!':
			toks = append(toks, aciTokenA{kind: aciTokBang, pos: i})
			i++
		case c == '"':
			v, next, err := aciLexQStringA(text, i)
			if err != nil {
				return nil, err
			}
			toks = append(toks, aciTokenA{kind: aciTokQString, text: v, pos: i})
			i = next
		default:
			j := i
			for j < len(text) && !aciIsDelimA(text[j]) {
				j++
			}
			toks = append(toks, aciTokenA{kind: aciTokWord, text: text[i:j], pos: i})
			i = j
		}
	}
	toks = append(toks, aciTokenA{kind: aciTokEOF, pos: len(text)})
	return toks, nil
}

type aciParserA struct {
	toks []aciTokenA
	pos  int
}

func (p *aciParserA) peek() aciTokenA { return p.toks[p.pos] }

func (p *aciParserA) next() aciTokenA {
	t := p.toks[p.pos]
	if t.kind != aciTokEOF {
		p.pos++
	}
	return t
}

func (p *aciParserA) expect(kind aciTokKindA, what string) (aciTokenA, error) {
	t := p.next()
	if t.kind != kind {
		return t, aciErrA(t.pos, "expected %s, found %s", what, aciTokDescA(t))
	}
	return t, nil
}

// aciLDAPRestA strips the "ldap:///" prefix shared by target, userdn, and
// groupdn values. A host-bearing ldap://host/<dn> URL is outside the grammar
// and fails the prefix check.
func aciLDAPRestA(v string, pos int) (string, error) {
	const prefix = "ldap:///"
	if len(v) < len(prefix) || !strings.EqualFold(v[:len(prefix)], prefix) {
		return "", aciErrA(pos, `value must be an "ldap:///" URL`)
	}
	return v[len(prefix):], nil
}

// ParseACITextA parses one ACI string in the LabLDAP compiler subset into
// structured form. The input may be operator-supplied (allowRawACI): every
// malformed path returns an error wrapping ErrACIParseA and never panics.
func ParseACITextA(text string) (*ParsedACI, error) {
	if text == "" {
		return nil, aciErrA(0, "empty ACI text")
	}
	if len(text) > MaxACITextBytesA {
		return nil, aciErrA(MaxACITextBytesA, "ACI text exceeds %d bytes", MaxACITextBytesA)
	}
	toks, err := aciLexA(text)
	if err != nil {
		return nil, err
	}
	p := &aciParserA{toks: toks}
	out := &ParsedACI{}
	var seenTarget, seenAttr, seenBody bool
	for p.peek().kind != aciTokEOF {
		if seenTarget && seenAttr && seenBody {
			// The grammar defines three clause kinds and each may appear at
			// most once, so a fourth clause is always a duplicate or unknown.
			t := p.peek()
			return nil, aciErrA(t.pos, "too many clauses: an ACI has one target, one targetattr, and one bind rule")
		}
		if _, err := p.expect(aciTokLParen, "expected '(' starting an ACI clause"); err != nil {
			return nil, err
		}
		kw, err := p.expect(aciTokWord, "expected a clause keyword after '('")
		if err != nil {
			return nil, err
		}
		switch strings.ToLower(kw.text) {
		case "target":
			if seenTarget {
				return nil, aciErrA(kw.pos, "duplicate target clause")
			}
			seenTarget = true
			if err := p.parseTargetClauseA(out); err != nil {
				return nil, err
			}
		case "targetattr":
			if seenAttr {
				return nil, aciErrA(kw.pos, "duplicate targetattr clause")
			}
			seenAttr = true
			if err := p.parseTargetAttrClauseA(out); err != nil {
				return nil, err
			}
		case "version":
			if seenBody {
				return nil, aciErrA(kw.pos, "duplicate version/acl bind rule clause")
			}
			seenBody = true
			if err := p.parseBodyClauseA(out); err != nil {
				return nil, err
			}
		default:
			return nil, aciErrA(kw.pos, "unknown ACI clause %q", aciTruncA(kw.text))
		}
	}
	if !seenTarget {
		return nil, aciErrA(p.peek().pos, "missing target clause")
	}
	if !seenBody {
		return nil, aciErrA(p.peek().pos, "missing (version 3.0; acl ...; allow|deny ...) bind rule clause")
	}
	return out, nil
}

func (p *aciParserA) parseTargetClauseA(out *ParsedACI) error {
	if _, err := p.expect(aciTokEquals, "expected '=' after target"); err != nil {
		return err
	}
	v, err := p.expect(aciTokQString, `target value must be a quoted "ldap:///<dn>" string`)
	if err != nil {
		return err
	}
	rest, err := aciLDAPRestA(v.text, v.pos)
	if err != nil {
		return err
	}
	dn, err := config.ParseDN(rest)
	if err != nil {
		return aciErrA(v.pos, "target DN is invalid: %v", err)
	}
	out.TargetDN = dn
	_, err = p.expect(aciTokRParen, "expected ')' closing the target clause")
	return err
}

func (p *aciParserA) parseTargetAttrClauseA(out *ParsedACI) error {
	negate := false
	if p.peek().kind == aciTokBang {
		p.next()
		negate = true
	}
	if _, err := p.expect(aciTokEquals, "expected '=' or '!=' after targetattr"); err != nil {
		return err
	}
	v, err := p.expect(aciTokQString, "targetattr value must be a quoted attribute list")
	if err != nil {
		return err
	}
	parts := strings.Split(v.text, "|")
	if len(parts) > aciMaxAttrsA {
		return aciErrA(v.pos, "targetattr list exceeds %d attributes", aciMaxAttrsA)
	}
	star := false
	attrs := make([]string, 0, len(parts))
	for _, a := range parts {
		if a == "*" {
			star = true
			continue
		}
		if !aciAttrNameReA.MatchString(a) {
			return aciErrA(v.pos, "invalid attribute name %q in targetattr", aciTruncA(a))
		}
		attrs = append(attrs, a)
	}
	switch {
	case star && len(parts) != 1:
		return aciErrA(v.pos, `"*" cannot be combined with named attributes in targetattr`)
	case star && negate:
		return aciErrA(v.pos, `targetattr!= does not accept "*"`)
	case star:
		out.AttrMode = ACITargetAttrAllA
	case negate:
		out.AttrMode = ACITargetAttrDenyA
		out.Attrs = attrs
	default:
		out.AttrMode = ACITargetAttrAllowA
		out.Attrs = attrs
	}
	_, err = p.expect(aciTokRParen, "expected ')' closing the targetattr clause")
	return err
}

func (p *aciParserA) parseBodyClauseA(out *ParsedACI) error {
	ver, err := p.expect(aciTokWord, "expected the ACI version after 'version'")
	if err != nil {
		return err
	}
	if ver.text != "3.0" {
		return aciErrA(ver.pos, "unsupported ACI version %q (only 3.0)", aciTruncA(ver.text))
	}
	if _, err := p.expect(aciTokSemi, "expected ';' after the version"); err != nil {
		return err
	}
	kw, err := p.expect(aciTokWord, `expected the "acl" keyword`)
	if err != nil {
		return err
	}
	if !strings.EqualFold(kw.text, "acl") {
		return aciErrA(kw.pos, `expected "acl", found %q`, aciTruncA(kw.text))
	}
	id, err := p.expect(aciTokQString, "the acl name must be a quoted string")
	if err != nil {
		return err
	}
	if id.text == "" {
		return aciErrA(id.pos, "acl name is empty")
	}
	if len(id.text) > aciMaxIDLenA {
		return aciErrA(id.pos, "acl name exceeds %d bytes", aciMaxIDLenA)
	}
	for _, r := range id.text {
		if r < 0x20 || r == 0x7f {
			return aciErrA(id.pos, "acl name contains a control character")
		}
	}
	out.ID = id.text
	if _, err := p.expect(aciTokSemi, "expected ';' after the acl name"); err != nil {
		return err
	}
	if err := p.parsePermRuleA(out); err != nil {
		return err
	}
	if err := p.parseSubjectA(out); err != nil {
		return err
	}
	if _, err := p.expect(aciTokSemi, "expected ';' after the bind rule"); err != nil {
		return err
	}
	_, err = p.expect(aciTokRParen, "expected ')' closing the bind rule clause")
	return err
}

func (p *aciParserA) parsePermRuleA(out *ParsedACI) error {
	kw, err := p.expect(aciTokWord, "expected allow or deny")
	if err != nil {
		return err
	}
	switch strings.ToLower(kw.text) {
	case "allow":
		out.Deny = false
	case "deny":
		out.Deny = true
	default:
		return aciErrA(kw.pos, "unknown permission action %q (want allow or deny)", aciTruncA(kw.text))
	}
	if _, err := p.expect(aciTokLParen, "expected '(' before the permission list"); err != nil {
		return err
	}
	for {
		w, err := p.expect(aciTokWord, "expected a permission name")
		if err != nil {
			return err
		}
		perm, ok := aciPermsA[strings.ToLower(w.text)]
		if !ok {
			return aciErrA(w.pos, "unknown permission %q", aciTruncA(w.text))
		}
		out.Permissions = append(out.Permissions, perm)
		if len(out.Permissions) > aciMaxPermsA {
			return aciErrA(w.pos, "permission list exceeds %d entries", aciMaxPermsA)
		}
		if p.peek().kind == aciTokComma {
			p.next()
			continue
		}
		break
	}
	_, err = p.expect(aciTokRParen, "expected ')' after the permission list")
	return err
}

func (p *aciParserA) parseSubjectA(out *ParsedACI) error {
	kw, err := p.expect(aciTokWord, "expected a userdn or groupdn bind rule")
	if err != nil {
		return err
	}
	isGroup := false
	switch strings.ToLower(kw.text) {
	case "userdn":
	case "groupdn":
		isGroup = true
	default:
		return aciErrA(kw.pos, "unknown bind rule %q (only userdn and groupdn are in the compiler grammar)", aciTruncA(kw.text))
	}
	if _, err := p.expect(aciTokEquals, "expected '=' after the bind rule keyword"); err != nil {
		return err
	}
	v, err := p.expect(aciTokQString, "bind rule value must be a quoted ldap:/// URL")
	if err != nil {
		return err
	}
	rest, err := aciLDAPRestA(v.text, v.pos)
	if err != nil {
		return err
	}
	if isGroup {
		if rest == "" {
			return aciErrA(v.pos, "groupdn requires a group DN")
		}
		dn, err := config.ParseDN(rest)
		if err != nil {
			return aciErrA(v.pos, "groupdn DN is invalid: %v", err)
		}
		out.Subject = ACISubjectA{Kind: ACISubjectGroupDNA, DN: dn}
		return nil
	}
	switch strings.ToLower(rest) {
	case "all":
		out.Subject = ACISubjectA{Kind: ACISubjectAllA}
	case "anyone":
		out.Subject = ACISubjectA{Kind: ACISubjectAnyoneA}
	case "self":
		out.Subject = ACISubjectA{Kind: ACISubjectSelfA}
	default:
		if rest == "" {
			return aciErrA(v.pos, "userdn DN is empty (use ldap:///all, ldap:///anyone, or ldap:///self for the keyword forms)")
		}
		dn, err := config.ParseDN(rest)
		if err != nil {
			return aciErrA(v.pos, "userdn DN is invalid: %v", err)
		}
		out.Subject = ACISubjectA{Kind: ACISubjectUserDNA, DN: dn}
	}
	return nil
}
