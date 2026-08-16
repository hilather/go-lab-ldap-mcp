package config

import (
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
)

// Filter is a parsed RFC 4515 subset used by later search work and T-023 fuzz.
type Filter struct {
	Raw string
}

func ParseFilter(s string, maxDepth, maxLen int) (Filter, error) {
	f, err := ParseFilterLimits(s, maxDepth, maxLen)
	if err != nil {
		return Filter{}, err
	}
	if IsOverBroad(s) {
		return Filter{}, apperr.New(apperr.CodeConfiguration, "search too broad").
			WithField(apperr.Field{Path: "filter", Code: "over_broad", Message: "filter is over-broad"})
	}
	return f, nil
}

// ParseFilterLimits validates syntax, depth, length, NUL, balance, and
// rejects approxMatch (`~=`). It does not apply the suffix+sub match-all
// over-broad conjunction (T-050).
func ParseFilterLimits(s string, maxDepth, maxLen int) (Filter, error) {
	if s == "" {
		return Filter{}, fieldErr("filter", "empty", "filter is empty")
	}
	if maxLen > 0 && len(s) > maxLen {
		return Filter{}, fieldErr("filter", "too_long", "filter exceeds maxFilterLength")
	}
	if strings.ContainsRune(s, 0) {
		return Filter{}, fieldErr("filter", "invalid", "filter contains NUL")
	}
	depth := 0
	max := 0
	for _, r := range s {
		switch r {
		case '(':
			depth++
			if depth > max {
				max = depth
			}
		case ')':
			depth--
		}
	}
	if maxDepth > 0 && max > maxDepth {
		return Filter{}, fieldErr("filter", "too_deep", "filter exceeds maxFilterDepth")
	}
	if depth != 0 {
		return Filter{}, fieldErr("filter", "unbalanced", "filter parentheses are unbalanced")
	}
	// Control plane rejects approxMatch (KD-14). Direct LDAP ~= stays D15.
	if ContainsApproxMatch(s) {
		return Filter{}, fieldErr("filter", "unsupported_filter", "approxMatch filters are not supported")
	}
	return Filter{Raw: s}, nil
}

// ContainsApproxMatch reports an RFC 4515 approxMatch operator (`~=`).
// Do not import ldapserver types here; a raw operator check is the contract.
func ContainsApproxMatch(s string) bool {
	return strings.Contains(s, "~=")
}

// IsOverBroad reports a match-all filter. T-050 rejects this only with suffix+sub.
func IsOverBroad(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "(objectclass=*)", "objectclass=*", "*", "(&(objectclass=*))":
		return true
	default:
		return false
	}
}
