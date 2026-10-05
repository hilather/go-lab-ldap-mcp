package config

import (
	"encoding/hex"
	"strings"
	"unicode/utf8"
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
		p = trimRDNWhitespace(p)
		eq := indexUnescaped(p, '=')
		if eq <= 0 {
			return DN{}, fieldErr("dn", "invalid_dn", "RDN is missing '='")
		}
		attr := strings.ToLower(strings.TrimSpace(p[:eq]))
		if !validDNAttribute(attr) {
			return DN{}, fieldErr("dn", "invalid_dn", "RDN attribute is invalid")
		}
		if indexUnescaped(p[eq+1:], '+') >= 0 {
			return DN{}, fieldErr("dn", "invalid_dn", "multi-valued RDN is not supported")
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
	if !validDNAttribute(attr) {
		return "", fieldErr("rdn", "invalid_rdn", "attribute is invalid")
	}
	if strings.ContainsRune(value, 0) {
		return "", fieldErr("rdn", "invalid_rdn", "value contains NUL")
	}
	return strings.ToLower(attr) + "=" + EscapeAttributeValue(value), nil
}

// Leaf returns the leftmost RDN (attribute and unescaped value).
func (d DN) Leaf() (attr, value string, ok bool) {
	if len(d.rdns) == 0 {
		return "", "", false
	}
	return d.rdns[0].attr, d.rdns[0].value, true
}

// Depth is the RDN count. Deeper DNs have a larger depth.
func (d DN) Depth() int { return len(d.rdns) }

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

// EqualFold compares RDN attributes and values case-insensitively.
func (d DN) EqualFold(o DN) bool {
	if len(d.rdns) != len(o.rdns) {
		return false
	}
	for i := range d.rdns {
		if d.rdns[i].attr != o.rdns[i].attr || !strings.EqualFold(d.rdns[i].value, o.rdns[i].value) {
			return false
		}
	}
	return true
}

// FoldedKey is a lowercase map key for protected-DN checks.
func (d DN) FoldedKey() string {
	parts := make([]string, len(d.rdns))
	for i, r := range d.rdns {
		parts[i] = r.attr + "=" + EscapeAttributeValue(strings.ToLower(r.value))
	}
	return strings.Join(parts, ",")
}

// Parent returns the DN after dropping the leaf RDN.
func (d DN) Parent() (DN, bool) {
	if len(d.rdns) < 2 {
		return DN{}, false
	}
	return DN{rdns: append([]rdn(nil), d.rdns[1:]...)}, true
}

// Rebase replaces from, an ancestor-or-self of d compared by FoldedKey,
// by to: the leading RDNs of d are kept as spelled and to's RDNs follow.
// ok is false when from is not d or an ancestor of d. Unlike a byte-length
// prefix swap it is safe for values whose lowercase form changes length.
func (d DN) Rebase(from, to DN) (DN, bool) {
	keep := len(d.rdns) - len(from.rdns)
	if len(from.rdns) == 0 || keep < 0 {
		return DN{}, false
	}
	if (DN{rdns: d.rdns[keep:]}).FoldedKey() != from.FoldedKey() {
		return DN{}, false
	}
	out := DN{rdns: make([]rdn, 0, keep+len(to.rdns))}
	out.rdns = append(out.rdns, d.rdns[:keep]...)
	out.rdns = append(out.rdns, to.rdns...)
	return out, true
}

// UnderAny reports whether d equals or is a descendant of any suffix.
func UnderAny(d DN, suffixes []DN) bool {
	for _, s := range suffixes {
		if d.Equal(s) || d.IsDescendantOf(s) {
			return true
		}
	}
	return false
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

func validDNAttribute(s string) bool {
	if s == "" {
		return false
	}
	if s[0] >= '0' && s[0] <= '9' {
		parts := strings.Split(s, ".")
		if len(parts) < 2 {
			return false
		}
		for _, part := range parts {
			if part == "" {
				return false
			}
			for _, c := range part {
				if c < '0' || c > '9' {
					return false
				}
			}
		}
		return true
	}
	for i, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			continue
		}
		if i > 0 && ((c >= '0' && c <= '9') || c == '-') {
			continue
		}
		return false
	}
	return true
}

func unescapeValue(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		i++
		if i >= len(s) {
			return "", fieldErr("dn", "invalid_dn", "dangling escape")
		}
		if i+1 < len(s) {
			var decoded [1]byte
			if _, err := hex.Decode(decoded[:], []byte(s[i:i+2])); err == nil {
				if decoded[0] == 0 {
					return "", fieldErr("dn", "invalid_dn", "DN contains NUL")
				}
				b.WriteByte(decoded[0])
				i++
				continue
			}
		}
		if !strings.ContainsRune(" ,+\"\\<>;=#", rune(s[i])) {
			return "", fieldErr("dn", "invalid_dn", "invalid DN escape")
		}
		b.WriteByte(s[i])
	}
	if !utf8.ValidString(b.String()) {
		return "", fieldErr("dn", "invalid_dn", "DN contains invalid UTF-8")
	}
	return b.String(), nil
}

func trimRDNWhitespace(s string) string {
	s = strings.TrimLeft(s, " \t")
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		escapes := 0
		for i := len(s) - 2; i >= 0 && s[i] == '\\'; i-- {
			escapes++
		}
		if escapes%2 == 1 {
			break
		}
		s = s[:len(s)-1]
	}
	return s
}
