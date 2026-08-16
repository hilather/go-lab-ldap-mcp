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

// matchFilterM is the Matcher-driven filter evaluator; tests exercise it
// directly against golden matching pairs.
func matchFilterM(e *Entry, f Filter, m Matcher) bool {
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
	case *FilterEquality:
		return matchEquality(e, flt.Attr, flt.Value, m)
	case *FilterSubstrings:
		return matchSubstrings(e, flt, m)
	case *FilterPresent:
		return len(e.Values(flt.Attr)) > 0
	case *FilterGreaterOrEqual:
		return matchOrdering(e, flt.Attr, flt.Value, m, 1)
	case *FilterLessOrEqual:
		return matchOrdering(e, flt.Attr, flt.Value, m, -1)
	case *FilterApproxMatch:
		return matchEquality(e, flt.Attr, flt.Value, m)
	default:
		return false
	}
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
func matchEquality(e *Entry, attr string, value []byte, m Matcher) bool {
	for _, v := range e.Values(attr) {
		if m.Equal(attr, v, value) {
			return true
		}
	}
	return false
}

// matchOrdering implements >= (dir 1) and <= (dir -1) over the attribute
// values under the attribute's ordering rule.
func matchOrdering(e *Entry, attr string, value []byte, m Matcher, dir int) bool {
	for _, v := range e.Values(attr) {
		cmp := m.Compare(attr, v, value)
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
func matchSubstrings(e *Entry, f *FilterSubstrings, m Matcher) bool {
	for _, v := range e.Values(f.Attr) {
		if m.Substrings(f.Attr, v, f.Initial, f.Final, f.Any) {
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
