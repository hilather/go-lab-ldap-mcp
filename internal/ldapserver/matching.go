package ldapserver

import (
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// Matcher is the consumer-owned seam between filter evaluation (T-127,
// filter_eval.go) and the RFC 4512/4517 matching-rule engine (T-131).
//
// Implementations must never panic on malformed values and must never log
// attribute values: stored values and assertions may be sensitive
// (AGENTS.md logging rules). A value that cannot be prepared under the
// rule — for example an unparseable DN assertion — is simply
// non-matching, the RFC 4511 "Undefined" filter result, never an error.
type Matcher interface {
	// Equal evaluates the attribute's equality rule: value is a stored
	// attribute value, assertion is the filter's assertion value.
	Equal(attr string, value, assertion []byte) bool
	// Substrings evaluates an RFC 4511 substring assertion under the
	// attribute's substring preparation: an optional initial run, ordered
	// any-runs, and an optional final run.
	Substrings(attr string, value, initial, final []byte, any [][]byte) bool
	// Compare orders value against assertion under the attribute's
	// ordering preparation: negative when value sorts before assertion,
	// zero when they are equal, positive when after.
	Compare(attr string, value, assertion []byte) int
}

// RuleMatcher is the built-in Matcher. Rule resolution is, in order:
//
//  1. The Schema's declared equality rule for the attribute, mapped
//     through rulesByName. A declared rule this engine does not implement
//     falls back to exact octets — a declared rule is authoritative and
//     its behavior is never guessed.
//  2. The Contract attribute registry (attributeRules), pinning the RFC
//     4512/4517 rules for the parity-contract C5 attribute set so search
//     behavior is stable before the T-132 schema registry lands.
//  3. Exact octets for unknown attributes, matching the T-127 stub.
type RuleMatcher struct {
	schema Schema
}

// NewRuleMatcher returns a Matcher that resolves rules through s. A nil
// Schema is permitted: resolution then uses the attribute registry alone.
func NewRuleMatcher(s Schema) *RuleMatcher { return &RuleMatcher{schema: s} }

// attrRules bundles the comparison behavior of one matching-rule family.
// Equality is normalized-string equality except for structuralDN rules,
// which compare internal/config DNs structurally.
type attrRules struct {
	name string
	// normalize prepares a value for equality, ordering, and substring
	// comparison. Identity normalization yields exact-octet behavior
	// (string conversion of arbitrary bytes is lossless).
	normalize func(v []byte) string
	// structuralDN selects distinguishedNameMatch semantics: both sides
	// parse as config DNs and compare with EqualFold.
	structuralDN bool
	// uniqueMember additionally tolerates the RFC 4519 '#' bit-string
	// suffix on uniqueMember values.
	uniqueMember bool
}

var (
	rulesCaseIgnore    = attrRules{name: "caseIgnoreMatch", normalize: normalizeCaseIgnore}
	rulesCaseIgnoreIA5 = attrRules{name: "caseIgnoreIA5Match", normalize: normalizeCaseIgnoreIA5}
	rulesCaseExact     = attrRules{name: "caseExactMatch", normalize: normalizeCaseExact}
	rulesCaseExactIA5  = attrRules{name: "caseExactIA5Match", normalize: normalizeCaseExact}
	rulesDN            = attrRules{name: "distinguishedNameMatch", normalize: normalizeDN, structuralDN: true}
	rulesUniqueMember  = attrRules{name: "uniqueMemberMatch", normalize: normalizeDN, structuralDN: true, uniqueMember: true}
	rulesObjectID      = attrRules{name: "objectIdentifierMatch", normalize: normalizeCaseIgnore}
	// rulesOctet covers octetStringMatch: identity normalization makes
	// equality, ordering, and substring comparisons byte-exact.
	rulesOctet = attrRules{name: "octetStringMatch", normalize: normalizeIdentity}
	// rulesGeneralizedTime compares stored canonical timestamps as exact
	// strings; semantic time comparison is not required by the Contract.
	rulesGeneralizedTime = attrRules{name: "generalizedTimeMatch", normalize: normalizeIdentity}
	// rulesExactOctets is the fallback for unknown attributes and for
	// schema-declared rules this engine does not implement.
	rulesExactOctets = attrRules{name: "exactOctetsFallback", normalize: normalizeIdentity}
)

// rulesByName maps a schema-declared equality rule (RFC 4517 names,
// lowercased) to its implementation. caseIgnoreListMatch (postalAddress)
// is approximated by caseIgnore preparation; booleanMatch folds case for
// the TRUE/FALSE tokens. Rules absent here (for example integerMatch) fall
// back to exact octets; the Contract attribute set does not require them.
var rulesByName = map[string]attrRules{
	"caseignorematch":        rulesCaseIgnore,
	"caseignoreia5match":     rulesCaseIgnoreIA5,
	"caseignorelistmatch":    rulesCaseIgnore,
	"caseexactmatch":         rulesCaseExact,
	"caseexactia5match":      rulesCaseExactIA5,
	"distinguishednamematch": rulesDN,
	"uniquemembermatch":      rulesUniqueMember,
	"objectidentifiermatch":  rulesObjectID,
	"octetstringmatch":       rulesOctet,
	"generalizedtimematch":   rulesGeneralizedTime,
	"booleanmatch":           rulesCaseIgnoreIA5,
}

// attributeRules is the Contract attribute registry (parity contract C5):
// the RFC 4512/4517 rules for the object classes LabLDAP manages, used
// when the Schema does not declare the attribute. Keys are lowercase
// attribute names.
var attributeRules = map[string]attrRules{
	"objectclass":          rulesObjectID,
	"uid":                  rulesCaseIgnore,
	"cn":                   rulesCaseIgnore,
	"sn":                   rulesCaseIgnore,
	"givenname":            rulesCaseIgnore,
	"displayname":          rulesCaseIgnore,
	"ou":                   rulesCaseIgnore,
	"o":                    rulesCaseIgnore,
	"l":                    rulesCaseIgnore,
	"st":                   rulesCaseIgnore,
	"street":               rulesCaseIgnore,
	"title":                rulesCaseIgnore,
	"description":          rulesCaseIgnore,
	"nsaccountlock":        rulesCaseIgnore,
	"entryuuid":            rulesCaseIgnore,
	"dc":                   rulesCaseIgnoreIA5,
	"mail":                 rulesCaseIgnoreIA5,
	"member":               rulesDN,
	"uniquemember":         rulesUniqueMember,
	"memberof":             rulesDN,
	"modifiersname":        rulesDN,
	"creatorsname":         rulesDN,
	"createtimestamp":      rulesGeneralizedTime,
	"modifytimestamp":      rulesGeneralizedTime,
	"pwdaccountlockedtime": rulesGeneralizedTime,
	"userpassword":         rulesOctet,
	// 389 declares no equality rule for aci (equality filters on it are
	// Undefined there); LabLDAP never filters on aci, and exact comparison
	// is the safest local behavior.
	"aci": rulesCaseExact,
}

// rulesFor resolves the matching rules for one attribute.
func (m *RuleMatcher) rulesFor(attr string) attrRules {
	if m != nil && m.schema != nil {
		if at, ok := m.schema.AttributeType(attr); ok && at.Equality != "" {
			if rs, ok := rulesByName[strings.ToLower(at.Equality)]; ok {
				return rs
			}
			return rulesExactOctets
		}
	}
	if rs, ok := attributeRules[strings.ToLower(attr)]; ok {
		return rs
	}
	return rulesExactOctets
}

// Equal implements Matcher.
func (m *RuleMatcher) Equal(attr string, value, assertion []byte) bool {
	rs := m.rulesFor(attr)
	if rs.structuralDN {
		dv, ok := dnFromValue(value, rs.uniqueMember)
		if !ok {
			return false
		}
		da, ok := dnFromValue(assertion, rs.uniqueMember)
		if !ok {
			return false
		}
		return dv.EqualFold(da)
	}
	return rs.normalize(value) == rs.normalize(assertion)
}

// Substrings implements Matcher: RFC 4511 section 4.5.1 evaluation over
// rule-normalized values. DN-valued attributes match against the folded
// canonical DN; 389 defines no substring rule for member (the assertion is
// Undefined there), so this is lenient by design — substring filters the
// product uses (search console names, mail) are string-ruled.
func (m *RuleMatcher) Substrings(attr string, value, initial, final []byte, any [][]byte) bool {
	norm := m.rulesFor(attr).normalize
	rest := norm(value)
	if len(initial) > 0 {
		prefix := norm(initial)
		if !strings.HasPrefix(rest, prefix) {
			return false
		}
		rest = rest[len(prefix):]
	}
	for _, a := range any {
		needle := norm(a)
		i := strings.Index(rest, needle)
		if i < 0 {
			return false
		}
		rest = rest[i+len(needle):]
	}
	if len(final) > 0 {
		return strings.HasSuffix(rest, norm(final))
	}
	return true
}

// Compare implements Matcher. Attributes without an ordering rule order by
// their equality-normalized form (caseIgnoreOrderingMatch behavior for
// string attributes, byte order for octets).
func (m *RuleMatcher) Compare(attr string, value, assertion []byte) int {
	rs := m.rulesFor(attr)
	return strings.Compare(rs.normalize(value), rs.normalize(assertion))
}

// dnFromValue parses a stored or asserted value as a DN. uniqueMember
// values may carry the RFC 4519 optional '#' bit-string suffix, stripped
// at the first unescaped '#'. Parse failure yields ok=false; the caller
// treats the comparison as Undefined (no match), never an error, so
// malformed assertions cannot panic or fail the enclosing search.
func dnFromValue(v []byte, uniqueMember bool) (config.DN, bool) {
	if uniqueMember {
		v = stripUniqueMemberSuffix(v)
	}
	d, err := config.ParseDN(string(v))
	if err != nil {
		return config.DN{}, false
	}
	return d, true
}

// stripUniqueMemberSuffix drops the optional '#' bit-string from a
// uniqueMember value. An escaped "\#" is DN data, not the separator.
func stripUniqueMemberSuffix(v []byte) []byte {
	s := string(v)
	esc := false
	for i := 0; i < len(s); i++ {
		if esc {
			esc = false
			continue
		}
		if s[i] == '\\' {
			esc = true
			continue
		}
		if s[i] == '#' {
			return []byte(s[:i])
		}
	}
	return v
}

// normalizeCaseIgnore is the RFC 4518 caseIgnoreStringPrepare subset used
// here: Unicode case fold plus insignificant-space handling. Full NFKC
// mapping and prohibited-character checks are deferred; a 389-observed
// divergence becomes a parity Delta in T-147.
func normalizeCaseIgnore(v []byte) string {
	return collapseSpaces(strings.ToLower(string(v)))
}

// normalizeCaseIgnoreIA5 folds ASCII case only: IA5 strings are ASCII by
// definition, and folding must not touch bytes outside the IA5 repertoire.
func normalizeCaseIgnoreIA5(v []byte) string {
	return collapseSpaces(foldASCII(string(v)))
}

// normalizeCaseExact applies insignificant-space handling without case
// folding (caseExactMatch / caseExactIA5Match).
func normalizeCaseExact(v []byte) string {
	return collapseSpaces(string(v))
}

// normalizeIdentity leaves the value untouched: exact-octet and
// generalized-time comparisons operate on the stored form.
func normalizeIdentity(v []byte) string { return string(v) }

// normalizeDN prepares a DN value for ordering and substring fallback:
// the folded canonical key when parseable, caseIgnore preparation
// otherwise.
func normalizeDN(v []byte) string {
	d, err := config.ParseDN(string(v))
	if err != nil {
		return normalizeCaseIgnore(v)
	}
	return d.FoldedKey()
}

// collapseSpaces applies RFC 4518 insignificant-space handling for U+0020:
// leading and trailing spaces are stripped and interior runs collapse to
// one space.
func collapseSpaces(s string) string {
	s = strings.Trim(s, " ")
	if !strings.Contains(s, "  ") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	pending := false
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			pending = true
			continue
		}
		if pending {
			b.WriteByte(' ')
			pending = false
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// foldASCII lowercases ASCII A-Z only.
func foldASCII(s string) string {
	upper := false
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			upper = true
			break
		}
	}
	if !upper {
		return s
	}
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
