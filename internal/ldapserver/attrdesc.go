package ldapserver

import (
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// Attribute descriptions in filters (parity contract C6).
//
// The pinned 389 oracle applies RFC 4512 section 2.5 subtype semantics to
// filter attribute descriptions (test/parity/testdata/
// filter-attr-oracle-probes.txt):
//
//   - A description without options names the attribute type: its primary
//     name, a second descriptor (userid, commonName) or its numeric OID, and
//     it matches the values of the type and of every subtype spelling stored
//     with options (uid;x-test).
//   - A description with options is resolved only when its base is the
//     type's primary name (uid;x-test). It matches stored values whose option
//     set contains every filter option (case-insensitive, order-free; no
//     RFC 3866 language ranges).
//   - A second descriptor or numeric OID WITH options (userid;x-test,
//     0.9.2342.19200300.100.1.1;x-test) is unresolved: it matches nothing,
//     and the search-permission check for that leaf uses the literal base.
//   - An empty option (cn;, cn;lang-en;) is kept as an option no stored
//     value carries, so the leaf matches nothing (oracle probe 20, sent as
//     raw BER because libldap rejects the filter client-side).
//
// ACI targetattr lists stay literal (aciAttrInA): 389 does not resolve
// aliases or OIDs inside them.

// attrDesc is a parsed filter attribute description.
type attrDesc struct {
	typ      string   // lowercase type key used for value selection and rules
	name     string   // ACI identity: registry casing when resolved, else the literal base
	opts     []string // lowercased options; "" marks an empty option (matches nothing)
	resolved bool
}

// parseAttrDesc resolves a filter attribute description against s. A nil s
// resolves second descriptors and protected OIDs only.
func parseAttrDesc(s Schema, desc string) attrDesc {
	base, rest, hasOpts := strings.Cut(strings.TrimSpace(desc), ";")
	base = strings.TrimSpace(base)
	opts := splitAttrOptions(rest)
	if hasOpts && hasEmptyAttrOption(rest) {
		opts = append(opts, "")
	}
	canon := config.CanonicalAttrType(base)
	name := canon
	regName := ""
	if s != nil {
		if at, ok := s.AttributeType(canon); ok {
			regName = at.Name
			name = at.Name
		}
	}
	if len(opts) > 0 {
		primary := !isNumericAttrOID(base) && canon == strings.ToLower(base) &&
			(regName == "" || strings.EqualFold(regName, base))
		if !primary {
			return attrDesc{typ: strings.ToLower(base), name: base, opts: opts}
		}
	}
	return attrDesc{typ: strings.ToLower(name), name: name, opts: opts, resolved: true}
}

// storedTypeKey resolves a stored attribute name to its lowercase type key
// and option set. Stored names resolve fully (second descriptors and OIDs
// even with options), because the native store keeps the spelling a direct
// LDAP write used.
func storedTypeKey(s Schema, name string) (string, []string) {
	base, rest, _ := strings.Cut(strings.TrimSpace(name), ";")
	typ := config.CanonicalAttrType(base)
	if s != nil {
		if at, ok := s.AttributeType(typ); ok {
			typ = at.Name
		}
	}
	return strings.ToLower(typ), splitAttrOptions(rest)
}

// AttrTypeKey is the lowercase attribute type a stored attribute name
// addresses (options stripped, second descriptors and OIDs resolved). The
// bbolt equality index keys postings by it.
func AttrTypeKey(s Schema, name string) string {
	typ, _ := storedTypeKey(s, name)
	return typ
}

// filterValues returns the values a filter description selects from e.
func filterValues(e *Entry, d attrDesc, s Schema) [][]byte {
	if e == nil || !d.resolved {
		return nil
	}
	var out [][]byte
	for _, a := range e.Attributes {
		typ, opts := storedTypeKey(s, a.Name)
		if typ != d.typ || !containsAllOptions(opts, d.opts) {
			continue
		}
		out = append(out, a.Values...)
	}
	return out
}

// hasEmptyAttrOption reports whether the option list after the first ';'
// has an empty entry ("", "lang-en;", "a;;b").
func hasEmptyAttrOption(rest string) bool {
	for _, o := range strings.Split(rest, ";") {
		if strings.TrimSpace(o) == "" {
			return true
		}
	}
	return false
}

func splitAttrOptions(rest string) []string {
	if rest == "" {
		return nil
	}
	var out []string
	for _, o := range strings.Split(rest, ";") {
		if o = strings.ToLower(strings.TrimSpace(o)); o != "" {
			out = append(out, o)
		}
	}
	return out
}

func containsAllOptions(have, want []string) bool {
	for _, w := range want {
		found := false
		for _, h := range have {
			if h == w {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func isNumericAttrOID(base string) bool {
	return base != "" && base[0] >= '0' && base[0] <= '9'
}
