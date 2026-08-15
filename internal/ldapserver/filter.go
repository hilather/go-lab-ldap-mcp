package ldapserver

// Filter is one node of a search filter tree. The codec (T-124) builds trees
// from the wire; matching-rule evaluation (T-131) consumes them. The tree is
// pure data: parsing must fail safely on malformed input and never panic
// (parity contract C6, fuzz targets in T-149).
type Filter interface {
	// filterNode keeps the set of filter nodes closed to this package's
	// definitions so evaluation can switch exhaustively.
	filterNode()
}

// FilterAnd matches when every child matches.
type FilterAnd struct {
	Children []Filter
}

// FilterOr matches when at least one child matches.
type FilterOr struct {
	Children []Filter
}

// FilterNot negates its child.
type FilterNot struct {
	Child Filter
}

// FilterEquality is an attribute value equality assertion. The matching rule
// (for example caseIgnoreMatch) comes from the attribute's schema entry, not
// from the filter (C6).
type FilterEquality struct {
	Attr  string
	Value []byte
}

// FilterSubstrings is an RFC 4511 substring assertion: an optional initial
// run, zero or more middle runs, and an optional final run.
type FilterSubstrings struct {
	Attr    string
	Initial []byte
	Any     [][]byte
	Final   []byte
}

// FilterPresent matches entries that carry the attribute at all ("attr=*").
type FilterPresent struct {
	Attr string
}

// FilterGreaterOrEqual is an ordering assertion.
type FilterGreaterOrEqual struct {
	Attr  string
	Value []byte
}

// FilterLessOrEqual is an ordering assertion.
type FilterLessOrEqual struct {
	Attr  string
	Value []byte
}

// FilterApproxMatch is an approximate-match assertion.
type FilterApproxMatch struct {
	Attr  string
	Value []byte
}

func (*FilterAnd) filterNode()            {}
func (*FilterOr) filterNode()             {}
func (*FilterNot) filterNode()            {}
func (*FilterEquality) filterNode()       {}
func (*FilterSubstrings) filterNode()     {}
func (*FilterPresent) filterNode()        {}
func (*FilterGreaterOrEqual) filterNode() {}
func (*FilterLessOrEqual) filterNode()    {}
func (*FilterApproxMatch) filterNode()    {}
