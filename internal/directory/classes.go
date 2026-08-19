package directory

import (
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// NormalizeObjectClass maps an allowlisted request class to the stored
// structural class (ADR-0011). container → organizationalUnit;
// dcObject → domain.
func NormalizeObjectClass(name string) (string, bool) {
	switch config.CanonicalAttr(name) {
	case ClassDomain, ClassDCObject:
		return ClassDomain, true
	case ClassOrganizationalUnit, ClassContainer:
		return ClassOrganizationalUnit, true
	case ClassPerson, ClassInetOrgPerson:
		return ClassInetOrgPerson, true
	case ClassGroupOfNames:
		return ClassGroupOfNames, true
	default:
		return "", false
	}
}

// PrimaryStructuralClass picks the allowlisted structural class from a
// request list. Unknown classes fail.
func PrimaryStructuralClass(classes []string) (string, error) {
	var found string
	for _, raw := range classes {
		got, ok := NormalizeObjectClass(raw)
		if !ok {
			return "", Error("objectClasses", FieldForbidden, "object class is not allowlisted")
		}
		if found != "" && found != got {
			return "", Error("objectClasses", FieldConstraint, "conflicting structural object classes")
		}
		found = got
	}
	if found == "" {
		return "", Error("objectClasses", "required", "objectClasses is required")
	}
	return found, nil
}

// LeafAttrForClass is the required RDN attribute for a stored class.
func LeafAttrForClass(class string) string {
	switch class {
	case ClassDomain:
		return "dc"
	case ClassOrganizationalUnit:
		return "ou"
	case ClassGroupOfNames:
		return "cn"
	case ClassInetOrgPerson:
		return "" // uid or cn
	default:
		return ""
	}
}

// IsUserClass reports inetOrgPerson / person.
func IsUserClass(class string) bool {
	c, _ := NormalizeObjectClass(class)
	return c == ClassInetOrgPerson
}

// IsGroupClass reports groupOfNames.
func IsGroupClass(class string) bool {
	c, _ := NormalizeObjectClass(class)
	return c == ClassGroupOfNames
}

// HasObjectClass reports a case-insensitive objectClass value.
func HasObjectClass(classes []string, want string) bool {
	want = config.CanonicalAttr(want)
	for _, c := range classes {
		if config.CanonicalAttr(c) == want {
			return true
		}
	}
	return false
}

// StructuralClassFromEntry inspects stored objectClass values.
func StructuralClassFromEntry(classes []string) string {
	for _, name := range []string{ClassInetOrgPerson, ClassGroupOfNames, ClassOrganizationalUnit, ClassDomain, ClassPerson} {
		if HasObjectClass(classes, name) {
			if name == ClassPerson && HasObjectClass(classes, ClassInetOrgPerson) {
				return ClassInetOrgPerson
			}
			if name == ClassPerson {
				return ClassInetOrgPerson
			}
			return name
		}
	}
	return ""
}

// ForbiddenEntryAttr is true for operator-forbidden write attributes.
func ForbiddenEntryAttr(name string) bool {
	if config.ForbiddenUserAttr(name) {
		return true
	}
	switch config.CanonicalAttr(name) {
	case "userpassword", "aci", "memberof", "nsaccountlock":
		return true
	default:
		return strings.HasPrefix(config.CanonicalAttr(name), "nsslapd-")
	}
}
