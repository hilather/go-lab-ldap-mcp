package config

import "strings"

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
	if resolved, ok := attributeNameAliases[base]; ok {
		return resolved
	}
	return base
}

// attributeNameAliases maps second descriptors of planned attributes to their
// primary names (RFC 4519 / pinned 389 00core.ldif NAME lists).
var attributeNameAliases = map[string]string{
	"userid":                 "uid",
	"commonname":             "cn",
	"surname":                "sn",
	"organizationalunitname": "ou",
	"domaincomponent":        "dc",
	"organizationname":       "o",
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
