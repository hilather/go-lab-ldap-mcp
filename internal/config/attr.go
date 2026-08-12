package config

import "strings"

// Operational and managed attributes that operators may not set on users.
var operationalDeny = map[string]struct{}{
	"userpassword":         {},
	"memberof":             {},
	"modifiersname":        {},
	"modifytimestamp":      {},
	"entryuuid":            {},
	"nsuniqueid":           {},
	"createtimestamp":      {},
	"creatorsname":         {},
	"aci":                  {},
	"pwdaccountlockedtime": {},
	"nsaccountlock":        {},
	"entrydn":              {},
	"numsubordinates":      {},
}

func CanonicalAttr(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func ForbiddenUserAttr(name string) bool {
	_, ok := operationalDeny[CanonicalAttr(name)]
	return ok
}

func RequiredUserObjectClasses() []string {
	return []string{"top", "person", "organizationalPerson", "inetOrgPerson"}
}
