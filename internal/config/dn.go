package config

import (
	"strings"
	"unicode/utf8"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
)

// DN is a parsed distinguished name. Comparison is structural, not a string suffix.
type DN struct {
	rdns []rdn
}

type rdn struct {
	attr  string
	value string
}

func ParseDN(s string) (DN, error) {
	if s == "" {
		return DN{}, fieldErr("dn", "invalid_dn", "DN is empty")
	}
	if strings.ContainsRune(s, 0) {
		return DN{}, fieldErr("dn", "invalid_dn", "DN contains NUL")
	}
	parts := splitUnescaped(s, ',')
	out := DN{rdns: make([]rdn, 0, len(parts))}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		eq := indexUnescaped(p, '=')
		if eq <= 0 {
			return DN{}, fieldErr("dn", "invalid_dn", "RDN is missing '='")
		}
		attr := strings.ToLower(strings.TrimSpace(p[:eq]))
		if attr == "" {
			return DN{}, fieldErr("dn", "invalid_dn", "RDN attribute is empty")
		}
		val, err := unescapeValue(p[eq+1:])
		if err != nil {
			return DN{}, err
		}
		out.rdns = append(out.rdns, rdn{attr: attr, value: val})
	}
	return out, nil
}

func EscapeAttributeValue(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	for i, r := range s {
		switch {
		case r == 0:
			b.WriteString(`\00`)
		case r == '\\' || r == ',' || r == '+' || r == '"' || r == ';' || r == '<' || r == '>':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == ' ' && (i == 0 || i+utf8.RuneLen(r) == len(s)):
			b.WriteString(`\ `)
		case r == '#' && i == 0:
			b.WriteString(`\#`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func BuildRDN(attr, value string) (string, error) {
	if attr == "" {
		return "", fieldErr("rdn", "invalid_rdn", "attribute is empty")
	}
	if strings.ContainsRune(value, 0) {
		return "", fieldErr("rdn", "invalid_rdn", "value contains NUL")
	}
	return strings.ToLower(attr) + "=" + EscapeAttributeValue(value), nil
}

func (d DN) String() string {
	parts := make([]string, len(d.rdns))
	for i, r := range d.rdns {
		parts[i] = r.attr + "=" + EscapeAttributeValue(r.value)
	}
	return strings.Join(parts, ",")
}

func (d DN) Equal(o DN) bool {
	if len(d.rdns) != len(o.rdns) {
		return false
	}
	for i := range d.rdns {
		if d.rdns[i].attr != o.rdns[i].attr || d.rdns[i].value != o.rdns[i].value {
			return false
		}
	}
	return true
}

// IsDescendantOf reports whether d is strictly under ancestor (RDN prefix from the root).
func (d DN) IsDescendantOf(ancestor DN) bool {
	if len(ancestor.rdns) == 0 || len(d.rdns) <= len(ancestor.rdns) {
		return false
	}
	// DNs are written leaf-first: uid=a,ou=people,dc=ex,dc=test
	off := len(d.rdns) - len(ancestor.rdns)
	for i := range ancestor.rdns {
		if d.rdns[off+i] != ancestor.rdns[i] {
			return false
		}
	}
	return true
}

func splitUnescaped(s string, sep rune) []string {
	var parts []string
	start := 0
	esc := false
	for i, r := range s {
		if esc {
			esc = false
			continue
		}
		if r == '\\' {
			esc = true
			continue
		}
		if r == sep {
			parts = append(parts, s[start:i])
			start = i + utf8.RuneLen(r)
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func indexUnescaped(s string, sep rune) int {
	esc := false
	for i, r := range s {
		if esc {
			esc = false
			continue
		}
		if r == '\\' {
			esc = true
			continue
		}
		if r == sep {
			return i
		}
	}
	return -1
}

func unescapeValue(s string) (string, error) {
	var b strings.Builder
	esc := false
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		if !esc {
			if r == '\\' {
				esc = true
				continue
			}
			b.WriteRune(r)
			continue
		}
		esc = false
		if r == '0' && i+1 < len(rs) && rs[i+1] == '0' {
			return "", apperr.New(apperr.CodeConfiguration, "invalid DN").
				WithField(apperr.Field{Path: "dn", Code: "invalid_dn", Message: "DN contains NUL"})
		}
		b.WriteRune(r)
	}
	if esc {
		return "", fieldErr("dn", "invalid_dn", "dangling escape")
	}
	return b.String(), nil
}
