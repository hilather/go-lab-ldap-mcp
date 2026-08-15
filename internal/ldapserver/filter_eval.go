package ldapserver

import (
	"bytes"
	"strings"
)

// matchFilter evaluates one filter tree against an entry. Evaluation never
// panics and treats unknown nodes as non-matching (parity contract C6).
//
// Matching-rule stub (TASKS T-127 acceptance): until T-131 lands the real
// matching-rule engine, equality folds case only when the schema registers
// the attribute with a caseIgnore* / distinguishedName equality rule, and
// otherwise compares exact octets. Ordering comparisons use the same
// folding on the byte-lexicographic order. Approximate match folds to
// equality — 389 evaluates approx as equality for attributes without an
// approximate matching rule (observed); recorded as a parity Delta
// candidate for the T-147 oracle.
func matchFilter(e *Entry, f Filter, s Schema) bool {
	switch flt := f.(type) {
	case *FilterAnd:
		for _, child := range flt.Children {
			if !matchFilter(e, child, s) {
				return false
			}
		}
		return true
	case *FilterOr:
		for _, child := range flt.Children {
			if matchFilter(e, child, s) {
				return true
			}
		}
		return false
	case *FilterNot:
		return !matchFilter(e, flt.Child, s)
	case *FilterEquality:
		return matchEquality(e, flt.Attr, flt.Value, s)
	case *FilterSubstrings:
		return matchSubstrings(e, flt, s)
	case *FilterPresent:
		return len(e.Values(flt.Attr)) > 0
	case *FilterGreaterOrEqual:
		return matchOrdering(e, flt.Attr, flt.Value, s, 1)
	case *FilterLessOrEqual:
		return matchOrdering(e, flt.Attr, flt.Value, s, -1)
	case *FilterApproxMatch:
		return matchEquality(e, flt.Attr, flt.Value, s)
	default:
		return false
	}
}

// foldCase reports whether the attribute's registered equality rule folds
// case. Unknown attributes fall back to exact octet comparison.
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

func matchEquality(e *Entry, attr string, value []byte, s Schema) bool {
	fold := foldCase(s, attr)
	for _, v := range e.Values(attr) {
		if valueEqual(fold, v, value) {
			return true
		}
	}
	return false
}

// matchOrdering implements >= (dir 1) and <= (dir -1) over the attribute
// values, folded per the equality rule.
func matchOrdering(e *Entry, attr string, value []byte, s Schema, dir int) bool {
	fold := foldCase(s, attr)
	assertion := string(value)
	if fold {
		assertion = strings.ToLower(assertion)
	}
	for _, v := range e.Values(attr) {
		candidate := string(v)
		if fold {
			candidate = strings.ToLower(candidate)
		}
		cmp := strings.Compare(candidate, assertion)
		if dir > 0 && cmp >= 0 {
			return true
		}
		if dir < 0 && cmp <= 0 {
			return true
		}
	}
	return false
}

// matchSubstrings implements RFC 4511 section 4.5.1 substring evaluation:
// optional initial prefix, ordered any-runs, optional final suffix.
func matchSubstrings(e *Entry, f *FilterSubstrings, s Schema) bool {
	fold := foldCase(s, f.Attr)
	norm := func(b []byte) string {
		if fold {
			return strings.ToLower(string(b))
		}
		return string(b)
	}
	initial := norm(f.Initial)
	final := norm(f.Final)
	for _, v := range e.Values(f.Attr) {
		rest := norm(v)
		if initial != "" {
			if !strings.HasPrefix(rest, initial) {
				continue
			}
			rest = rest[len(initial):]
		}
		ok := true
		for _, any := range f.Any {
			needle := norm(any)
			i := strings.Index(rest, needle)
			if i < 0 {
				ok = false
				break
			}
			rest = rest[i+len(needle):]
		}
		if !ok {
			continue
		}
		if final != "" && !strings.HasSuffix(rest, final) {
			continue
		}
		return true
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
