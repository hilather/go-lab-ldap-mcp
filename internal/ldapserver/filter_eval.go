package ldapserver

import (
	"bytes"
	"strings"
)

// matchFilter evaluates one filter tree against an entry. Evaluation never
// panics and treats unknown nodes as non-matching (parity contract C6).
//
// Matching rules (T-131): equality, substring, and ordering assertions
// resolve through the Matcher seam (matching.go), which applies the
// attribute's RFC 4512/4517 rule — caseIgnoreMatch, caseIgnoreIA5Match,
// distinguishedNameMatch as structural canonical-DN comparison, or exact
// octets for attributes with no known rule. Approximate match folds to
// equality: 389 evaluates approx as equality for attributes without an
// approximate matching rule (observed); still folded, recorded as parity
// Delta candidate CAND-2 for the T-147 oracle.
func matchFilter(e *Entry, f Filter, s Schema) bool {
	return matchFilterM(e, f, NewRuleMatcher(s))
}

// matchFilterM is the rule-driven filter evaluator; tests exercise it
// directly against golden matching pairs. Attribute descriptions resolve
// against the matcher's own schema (attrdesc.go), so value selection and
// matching rules cannot disagree.
func matchFilterM(e *Entry, f Filter, m *RuleMatcher) bool {
	var s Schema
	if m != nil {
		s = m.schema
	}
	switch flt := f.(type) {
	case *FilterAnd:
		for _, child := range flt.Children {
			if !matchFilterM(e, child, m) {
				return false
			}
		}
		return true
	case *FilterOr:
		for _, child := range flt.Children {
			if matchFilterM(e, child, m) {
				return true
			}
		}
		return false
	case *FilterNot:
		return !matchFilterM(e, flt.Child, m)
	default:
		attr, ok := leafAttr(f)
		if !ok {
			return false
		}
		return matchLeaf(e, f, parseAttrDesc(s, attr), m)
	}
}

// leafAttr returns the attribute description of a leaf filter node.
func leafAttr(f Filter) (string, bool) {
	switch n := f.(type) {
	case *FilterEquality:
		return n.Attr, true
	case *FilterSubstrings:
		return n.Attr, true
	case *FilterPresent:
		return n.Attr, true
	case *FilterGreaterOrEqual:
		return n.Attr, true
	case *FilterLessOrEqual:
		return n.Attr, true
	case *FilterApproxMatch:
		return n.Attr, true
	}
	return "", false
}

// matchLeaf evaluates one leaf whose description the caller already parsed
// (matchSearchFilter parses once for both the ACI identity and the match).
func matchLeaf(e *Entry, f Filter, d attrDesc, m *RuleMatcher) bool {
	var s Schema
	if m != nil {
		s = m.schema
	}
	switch flt := f.(type) {
	case *FilterEquality:
		return matchEquality(e, d, flt.Value, m, s)
	case *FilterSubstrings:
		return matchSubstrings(e, d, flt, m, s)
	case *FilterPresent:
		return len(filterValues(e, d, s)) > 0
	case *FilterGreaterOrEqual:
		return matchOrdering(e, d, flt.Value, m, s, 1)
	case *FilterLessOrEqual:
		return matchOrdering(e, d, flt.Value, m, s, -1)
	case *FilterApproxMatch:
		return matchEquality(e, d, flt.Value, m, s)
	}
	return false
}

// foldCase reports whether the attribute's registered equality rule folds
// case. Unknown attributes fall back to exact octet comparison.
//
// T-128 write-path value matching (op_write.go) still uses this fold-only
// helper; T-131 replaced the search/filter side with the Matcher seam.
func foldCase(s Schema, attr string) bool {
	at, ok := s.AttributeType(attr)
	if !ok {
		return false
	}
	switch strings.ToLower(at.Equality) {
	case "caseignorematch", "caseignoreia5match", "caseignorelistmatch", "distinguishednamematch":
		return true
	default:
		return false
	}
}

func valueEqual(fold bool, a, b []byte) bool {
	if fold {
		return strings.EqualFold(string(a), string(b))
	}
	return bytes.Equal(a, b)
}

// matchEquality evaluates the attribute's equality rule through the
// Matcher; malformed assertions are Undefined (no match), never errors.
func matchEquality(e *Entry, d attrDesc, value []byte, m Matcher, s Schema) bool {
	for _, v := range filterValues(e, d, s) {
		if m.Equal(d.typ, v, value) {
			return true
		}
	}
	return false
}

// matchOrdering implements >= (dir 1) and <= (dir -1) over the attribute
// values under the attribute's ordering rule.
func matchOrdering(e *Entry, d attrDesc, value []byte, m Matcher, s Schema, dir int) bool {
	for _, v := range filterValues(e, d, s) {
		cmp := m.Compare(d.typ, v, value)
		if dir > 0 && cmp >= 0 {
			return true
		}
		if dir < 0 && cmp <= 0 {
			return true
		}
	}
	return false
}

// matchSubstrings evaluates an RFC 4511 substring assertion through the
// Matcher's substring rule.
func matchSubstrings(e *Entry, d attrDesc, f *FilterSubstrings, m Matcher, s Schema) bool {
	for _, v := range filterValues(e, d, s) {
		if m.Substrings(d.typ, v, f.Initial, f.Final, f.Any) {
			return true
		}
	}
	return false
}

// attrSelection is the parsed RFC 4511 attribute selection list.
type attrSelection struct {
	allUser        bool // empty list or "*": all user attributes
	allOperational bool // "+": all operational attributes
	none           bool // "1.1": no attributes
	names          map[string]struct{}
}

// parseAttrSelection parses the requested attribute list. An empty list
// selects all user attributes (RFC 4511 section 4.5.1).
func parseAttrSelection(requested []string) attrSelection {
	sel := attrSelection{}
	if len(requested) == 0 {
		sel.allUser = true
		return sel
	}
	for _, name := range requested {
		switch name {
		case "*":
			sel.allUser = true
		case "+":
			sel.allOperational = true
		case "1.1":
			sel.none = true
		default:
			if sel.names == nil {
				sel.names = map[string]struct{}{}
			}
			sel.names[strings.ToLower(name)] = struct{}{}
		}
	}
	return sel
}

// wants reports whether an attribute is selected. Operational attributes
// (per schema) require "+" or an explicit name; unknown attributes count
// as user attributes.
func (sel attrSelection) wants(s Schema, attr string) bool {
	if sel.none {
		return false
	}
	lower := strings.ToLower(attr)
	if _, ok := sel.names[lower]; ok {
		return true
	}
	operational := false
	if at, ok := s.AttributeType(attr); ok {
		operational = at.Operational
	}
	if operational {
		return sel.allOperational
	}
	return sel.allUser
}
