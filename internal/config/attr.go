package config

import (
	"sort"
	"strings"
)

// Operational and managed attributes that operators may not set on users.
var operationalDeny = map[string]struct{}{
	"userpassword":           {},
	"authpassword":           {},
	"userpkcs12":             {},
	"memberof":               {},
	"modifiersname":          {},
	"modifytimestamp":        {},
	"entryuuid":              {},
	"nsuniqueid":             {},
	"createtimestamp":        {},
	"creatorsname":           {},
	"aci":                    {},
	"pwdaccountlockedtime":   {},
	"nsaccountlock":          {},
	"pwdreset":               {},
	"passwordexpirationtime": {},
	"accountunlocktime":      {},
	"passwordretrycount":     {},
	"entrydn":                {},
	"numsubordinates":        {},
}

// CanonicalAttr is the attribute-map and duplicate key: lowercase and trimmed,
// with attribute options preserved so cn and cn;lang-en stay distinct values.
// Policy decisions (deny lists, secret redaction) use CanonicalAttrType,
// which strips options and resolves protected OIDs.
func CanonicalAttr(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func ForbiddenUserAttr(name string) bool {
	base := CanonicalAttrType(name)
	// Operator writes use descriptors, not unknown engine-specific OIDs.
	if len(base) > 0 && base[0] >= '0' && base[0] <= '9' {
		return true
	}
	_, ok := operationalDeny[CanonicalAttrType(name)]
	return ok
}

// ForbiddenUserWriteAttr is the single write rule for user attributes from
// every source (REST, MCP, YAML bootstrap/reset, adapter): the protected set,
// every objectClass spelling (user object classes are fixed), and any
// non-bare spelling (option, OID, descriptor alias) of the planned names
// uid, cn and sn. Bare uid/cn/sn stay writable through their planned paths.
func ForbiddenUserWriteAttr(name string) bool {
	if ForbiddenUserAttr(name) {
		return true
	}
	t := CanonicalAttrType(name)
	switch t {
	case "objectclass":
		return true
	case "uid", "cn", "sn":
		return CanonicalAttr(name) != t
	}
	return false
}

func RequiredUserObjectClasses() []string {
	return []string{"top", "person", "organizationalPerson", "inetOrgPerson"}
}

// CanonicalAttrType resolves options and protected attribute OIDs for policy
// checks. CanonicalAttr still preserves descriptions for directory requests.
func CanonicalAttrType(name string) string {
	base, _, _ := strings.Cut(CanonicalAttr(name), ";")
	if resolved, ok := protectedAttributeOIDs[base]; ok {
		return resolved
	}
	if a, ok := attributeNameAliases[base]; ok {
		return a.typ
	}
	return base
}

// attrAlias is one second descriptor: the lowercase type it resolves to and
// the primary descriptor in schema casing, which writes send.
type attrAlias struct {
	typ     string
	primary string
}

// attributeNameAliases maps second descriptors to their attribute type
// (RFC 4519 / pinned 389 00core.ldif and cosine NAME lists:
// `NAME ( 'mail' 'rfc822mailbox' )`, `NAME ( 'givenName' 'gn' )`).
var attributeNameAliases = map[string]attrAlias{
	"userid":                 {"uid", "uid"},
	"commonname":             {"cn", "cn"},
	"surname":                {"sn", "sn"},
	"organizationalunitname": {"ou", "ou"},
	"domaincomponent":        {"dc", "dc"},
	"organizationname":       {"o", "o"},
	"rfc822mailbox":          {"mail", "mail"},
	"gn":                     {"givenname", "givenName"},
}

// AttrAliasType reports the attribute type when name's base (options
// stripped) is a second descriptor in the alias table. Protected OIDs are
// not aliases here.
func AttrAliasType(name string) (string, bool) {
	base, _, _ := strings.Cut(CanonicalAttr(name), ";")
	a, ok := attributeNameAliases[base]
	return a.typ, ok
}

// PrimaryAttrDescription rewrites a second descriptor in the alias table to
// the primary descriptor, keeping any options as written (rfc822Mailbox;x-a
// becomes mail;x-a, GN becomes givenName). Other names come back trimmed and
// unchanged. Writes send this spelling so both engines store the same name.
func PrimaryAttrDescription(name string) string {
	name = strings.TrimSpace(name)
	base, opts, hasOpts := strings.Cut(name, ";")
	a, ok := attributeNameAliases[strings.ToLower(strings.TrimSpace(base))]
	if !ok {
		return name
	}
	if !hasOpts {
		return a.primary
	}
	return a.primary + ";" + opts
}

// SortAttrNamesForDuplicates orders attribute names for duplicate detection:
// case-insensitive, with byte order as the tie-break, so the first name in
// that order wins (givenName before GN and gn; mail before rfc822Mailbox).
func SortAttrNamesForDuplicates(names []string) {
	sort.SliceStable(names, func(i, j int) bool {
		li, lj := strings.ToLower(names[i]), strings.ToLower(names[j])
		if li != lj {
			return li < lj
		}
		return names[i] < names[j]
	})
}

// AttrDuplicateKey identifies attribute names that address the same values:
// the resolved type (options stripped, OIDs and descriptor aliases resolved)
// plus the lowercased option list, so ou and organizationalUnitName collide
// while cn and cn;lang-en stay distinct.
func AttrDuplicateKey(name string) string {
	_, opts, ok := strings.Cut(CanonicalAttr(name), ";")
	if !ok {
		return CanonicalAttrType(name)
	}
	// Options are unordered (RFC 4512 section 2.5).
	list := strings.Split(opts, ";")
	sort.Strings(list)
	return CanonicalAttrType(name) + ";" + strings.Join(list, ";")
}

var protectedAttributeOIDs = map[string]string{
	"2.5.4.35":                   "userpassword",
	"1.3.6.1.4.1.4203.1.3.4":     "authpassword", // RFC 3112 section 2.2
	"2.16.840.1.113730.3.1.216":  "userpkcs12",   // pinned 389 schema
	"2.16.840.1.113730.3.1.542":  "nsuniqueid",
	"2.16.840.1.113730.3.1.93":   "passwordretrycount",
	"1.3.6.1.1.20":               "entrydn", // RFC 5020
	"2.16.840.1.113730.3.1.55":   "aci",
	"2.16.840.1.113730.3.1.610":  "nsaccountlock",
	"2.16.840.1.113730.3.1.612":  "memberof",
	"1.3.6.1.4.1.42.2.27.8.1.17": "pwdaccountlockedtime",
	"1.3.6.1.4.1.42.2.27.8.1.22": "pwdreset",
	"2.16.840.1.113730.3.1.598":  "passwordexpirationtime",
	"2.16.840.1.113730.3.1.95":   "accountunlocktime",
	"2.5.18.1":                   "createtimestamp",
	"2.5.18.2":                   "modifytimestamp",
	"2.5.18.3":                   "creatorsname",
	"2.5.18.4":                   "modifiersname",
	"1.3.6.1.1.16.4":             "entryuuid",
	"2.5.4.0":                    "objectclass",
}
