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
	if isOverBroad(s) {
		return Filter{}, apperr.New(apperr.CodeConfiguration, "search too broad").
			WithField(apperr.Field{Path: "filter", Code: "over_broad", Message: "filter is over-broad"})
	}
	return Filter{Raw: s}, nil
}

func isOverBroad(s string) bool {
	t := strings.TrimSpace(s)
	return t == "(objectClass=*)" || t == "objectClass=*" || t == "*"
}
