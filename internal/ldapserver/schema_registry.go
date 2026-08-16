package ldapserver

import (
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// schema_registry.go is the T-132 implementation behind the pinned Schema
// interface (schema.go, T-122): the RFC 4512 subset registry for the
// parity-contract C5 object classes plus the 389-isms ADR-0009 decisions
// 18-21 require (nsAccountLock, nsmemberof, device), MUST/MAY and
// unknown-attribute enforcement on writes (D17), and subschema subentry
// publication (C10).

// Registry is a validated, immutable Schema implementation. Construction
// checks referential integrity (SUP chains and MUST/MAY attribute names
// resolve) so a bad table fails at startup with a wrapped error, never a
// panic and never a half-loaded registry.
type Registry struct {
	// ocs and ats index each definition twice: by lowercase name and by
	// OID, so lookups accept either form case-insensitively.
	ocs map[string]ObjectClassDef
	ats map[string]AttributeTypeDef
}

// Compile-time satisfaction of the pinned interface (T-122).
var _ Schema = (*Registry)(nil)

// NewRegistry indexes and validates the definitions. Names must be unique
// case-insensitively, OIDs unique, and every SUP / MUST / MAY reference
// must resolve within the same registry.
func NewRegistry(ocs []ObjectClassDef, ats []AttributeTypeDef) (*Registry, error) {
	r := &Registry{
		ocs: make(map[string]ObjectClassDef, 2*len(ocs)),
		ats: make(map[string]AttributeTypeDef, 2*len(ats)),
	}
	for _, oc := range ocs {
		if oc.Name == "" || oc.OID == "" {
			return nil, fmt.Errorf("ldapserver: schema: object class with name %q: name and OID are required", oc.Name)
		}
		for _, key := range []string{strings.ToLower(oc.Name), oc.OID} {
			if _, dup := r.ocs[key]; dup {
				return nil, fmt.Errorf("ldapserver: schema: duplicate object class name or OID %q", key)
			}
			r.ocs[key] = oc
		}
	}
	for _, at := range ats {
		if at.Name == "" || at.OID == "" {
			return nil, fmt.Errorf("ldapserver: schema: attribute type with name %q: name and OID are required", at.Name)
		}
		for _, key := range []string{strings.ToLower(at.Name), at.OID} {
			if _, dup := r.ats[key]; dup {
				return nil, fmt.Errorf("ldapserver: schema: duplicate attribute type name or OID %q", key)
			}
			r.ats[key] = at
		}
	}
	for _, oc := range ocs {
		for _, sup := range oc.Sup {
			if _, ok := r.ObjectClass(sup); !ok {
				return nil, fmt.Errorf("ldapserver: schema: object class %s: unknown SUP %q", oc.Name, sup)
			}
		}
		for _, attr := range slices.Concat(oc.Must, oc.May) {
			if _, ok := r.AttributeType(attr); !ok {
				return nil, fmt.Errorf("ldapserver: schema: object class %s: unknown attribute type %q", oc.Name, attr)
			}
		}
	}
	return r, nil
}

// ObjectClass resolves a name or OID, case-insensitively.
func (r *Registry) ObjectClass(name string) (ObjectClassDef, bool) {
	oc, ok := r.ocs[strings.ToLower(name)]
	return oc, ok
}

// AttributeType resolves a name or OID, case-insensitively.
func (r *Registry) AttributeType(name string) (AttributeTypeDef, bool) {
	at, ok := r.ats[strings.ToLower(name)]
	return at, ok
}

// ObjectClasses lists the registry without OID-alias duplicates, sorted by
// OID for deterministic subschema publication.
func (r *Registry) ObjectClasses() []ObjectClassDef {
	seen := map[string]struct{}{}
	var out []ObjectClassDef
	for _, oc := range r.ocs {
		if _, dup := seen[oc.OID]; dup {
			continue
		}
		seen[oc.OID] = struct{}{}
		out = append(out, oc)
	}
	slices.SortFunc(out, func(a, b ObjectClassDef) int { return strings.Compare(a.OID, b.OID) })
	return out
}

// AttributeTypes lists the registry without OID-alias duplicates, sorted
// by OID.
func (r *Registry) AttributeTypes() []AttributeTypeDef {
	seen := map[string]struct{}{}
	var out []AttributeTypeDef
	for _, at := range r.ats {
		if _, dup := seen[at.OID]; dup {
			continue
		}
		seen[at.OID] = struct{}{}
		out = append(out, at)
	}
	slices.SortFunc(out, func(a, b AttributeTypeDef) int { return strings.Compare(a.OID, b.OID) })
	return out
}

// LDAP attribute syntax OIDs used by the standard registry (RFC 4517).
const (
	syntaxDirectoryString  = "1.3.6.1.4.1.1466.115.121.1.15"
	syntaxPrintableString  = "1.3.6.1.4.1.1466.115.121.1.44"
	syntaxIA5String        = "1.3.6.1.4.1.1466.115.121.1.26"
	syntaxDN               = "1.3.6.1.4.1.1466.115.121.1.12"
	syntaxOID              = "1.3.6.1.4.1.1466.115.121.1.38"
	syntaxInteger          = "1.3.6.1.4.1.1466.115.121.1.27"
	syntaxOctetString      = "1.3.6.1.4.1.1466.115.121.1.40"
	syntaxGeneralizedTime  = "1.3.6.1.4.1.1466.115.121.1.24"
	syntaxTelephoneNumber  = "1.3.6.1.4.1.1466.115.121.1.50"
	syntaxJPEG             = "1.3.6.1.4.1.1466.115.121.1.28"
	syntaxAttrTypeDesc     = "1.3.6.1.4.1.1466.115.121.1.3"
	syntaxObjectClassDesc  = "1.3.6.1.4.1.1466.115.121.1.37"
	syntaxMatchingRuleDesc = "1.3.6.1.4.1.1466.115.121.1.30"
)

// standardObjectClasses is the RFC 4512 subset for the parity contract C5
// tree (suffix domain, organizational units, the RequiredUserObjectClasses
// chain, groups, the baseline marker) plus the 389-isms pinned by ADR-0009
// decisions 20-21 (nsmemberof, device) and the RFC 4512 subschema class.
//
// Equality rules are declared with their RFC 4517/389 names; the T-131
// RuleMatcher treats a declared rule as authoritative. aci and jpegPhoto
// deliberately declare no equality rule, matching 389's publication.
var standardObjectClasses = []ObjectClassDef{
	// aci is MAY on top: 389 allows it on any entry (person included).
	// CAND-16 adds a person that carries aci; treating it as a class-
	// specific MAY only on domain/ou/group would reject that write with 65.
	{OID: "2.5.6.0", Name: "top", Kind: ObjectClassAbstract, Must: []string{"objectClass"}, May: []string{"aci"}},
	{
		OID: "0.9.2342.19200300.100.4.13", Name: "domain", Kind: ObjectClassStructural, Sup: []string{"top"},
		Must: []string{"dc"},
		May:  []string{"description", "o", "l", "st", "street", "postalAddress", "telephoneNumber", "destinationIndicator", "seeAlso", "owner", "userPassword", "businessCategory", "aci"},
	},
	{
		OID: "2.5.6.5", Name: "organizationalUnit", Kind: ObjectClassStructural, Sup: []string{"top"},
		Must: []string{"ou"},
		May:  []string{"description", "o", "l", "st", "street", "postalAddress", "telephoneNumber", "destinationIndicator", "seeAlso", "owner", "userPassword", "businessCategory", "aci"},
	},
	{
		OID: "2.5.6.6", Name: "person", Kind: ObjectClassStructural, Sup: []string{"top"},
		Must: []string{"sn", "cn"},
		May:  []string{"userPassword", "telephoneNumber", "seeAlso", "description"},
	},
	{
		OID: "2.5.6.7", Name: "organizationalPerson", Kind: ObjectClassStructural, Sup: []string{"person"},
		May: []string{"title", "ou", "o", "l", "st", "street", "postalAddress", "destinationIndicator", "telephoneNumber", "seeAlso", "businessCategory"},
	},
	{
		OID: "2.16.840.1.113730.3.2.2", Name: "inetOrgPerson", Kind: ObjectClassStructural, Sup: []string{"organizationalPerson"},
		// nsAccountLock rides on user entries (ADR-0009 decision 18); the
		// seed writes it on inetOrgPerson, so it is published in MAY here.
		May: []string{"uid", "mail", "displayName", "givenName", "initials", "employeeNumber", "employeeType", "departmentNumber", "manager", "mobile", "homePhone", "pager", "roomNumber", "carLicense", "jpegPhoto", "nsAccountLock"},
	},
	{
		OID: "2.5.6.9", Name: "groupOfNames", Kind: ObjectClassStructural, Sup: []string{"top"},
		// member is MUST: empty groups are forbidden (OD-018).
		Must: []string{"member", "cn"},
		May:  []string{"description", "o", "ou", "owner", "seeAlso", "businessCategory", "aci"},
	},
	{
		OID: "2.5.6.17", Name: "groupOfUniqueNames", Kind: ObjectClassStructural, Sup: []string{"top"},
		Must: []string{"uniqueMember", "cn"},
		May:  []string{"description", "o", "ou", "owner", "seeAlso", "businessCategory", "aci"},
	},
	{
		OID: "0.9.2342.19200300.100.4.14", Name: "device", Kind: ObjectClassStructural, Sup: []string{"top"},
		Must: []string{"cn"},
		May:  []string{"serialNumber", "seeAlso", "owner", "ou", "o", "l", "description"},
	},
	{
		// ADR-0009 decision 20: the memberOf plugin auto-adds this class.
		OID: "2.16.840.1.113730.3.2.334", Name: "nsmemberof", Kind: ObjectClassAuxiliary, Sup: []string{"top"},
		May: []string{"memberOf"},
	},
	{
		// RFC 4512 section 4.2: the subschema subentry's class.
		OID: "2.5.17.0", Name: "subschema", Kind: ObjectClassAuxiliary, Sup: []string{"top"},
		May: []string{"attributeTypes", "objectClasses", "matchingRules"},
	},
}

// standardAttributeTypes covers every attribute the control plane, seed,
// marker, and plugins write, plus the Root DSE / subschema / operational
// attributes published by the engine (C10, D6).
var standardAttributeTypes = []AttributeTypeDef{
	// Core user attributes.
	{OID: "2.5.4.0", Name: "objectClass", Equality: "objectIdentifierMatch", Syntax: syntaxOID},
	{OID: "2.5.4.3", Name: "cn", Equality: "caseIgnoreMatch", Syntax: syntaxDirectoryString},
	{OID: "2.5.4.4", Name: "sn", Equality: "caseIgnoreMatch", Syntax: syntaxDirectoryString},
	{OID: "2.5.4.5", Name: "serialNumber", Equality: "caseIgnoreMatch", Syntax: syntaxPrintableString},
	{OID: "2.5.4.7", Name: "l", Equality: "caseIgnoreMatch", Syntax: syntaxDirectoryString},
	{OID: "2.5.4.8", Name: "st", Equality: "caseIgnoreMatch", Syntax: syntaxDirectoryString},
	{OID: "2.5.4.9", Name: "street", Equality: "caseIgnoreMatch", Syntax: syntaxDirectoryString},
	{OID: "2.5.4.10", Name: "o", Equality: "caseIgnoreMatch", Syntax: syntaxDirectoryString},
	{OID: "2.5.4.11", Name: "ou", Equality: "caseIgnoreMatch", Syntax: syntaxDirectoryString},
	{OID: "2.5.4.12", Name: "title", Equality: "caseIgnoreMatch", Syntax: syntaxDirectoryString},
	{OID: "2.5.4.13", Name: "description", Equality: "caseIgnoreMatch", Syntax: syntaxDirectoryString},
	{OID: "2.5.4.15", Name: "businessCategory", Equality: "caseIgnoreMatch", Syntax: syntaxDirectoryString},
	{OID: "2.5.4.16", Name: "postalAddress", Equality: "caseIgnoreListMatch", Syntax: syntaxDirectoryString},
	{OID: "2.5.4.20", Name: "telephoneNumber", Equality: "telephoneNumberMatch", Syntax: syntaxTelephoneNumber},
	{OID: "2.5.4.27", Name: "destinationIndicator", Equality: "caseIgnoreMatch", Syntax: syntaxPrintableString},
	{OID: "2.5.4.31", Name: "member", Equality: "distinguishedNameMatch", Syntax: syntaxDN},
	{OID: "2.5.4.32", Name: "owner", Equality: "distinguishedNameMatch", Syntax: syntaxDN},
	{OID: "2.5.4.34", Name: "seeAlso", Equality: "distinguishedNameMatch", Syntax: syntaxDN},
	{OID: "2.5.4.35", Name: "userPassword", Equality: "octetStringMatch", Syntax: syntaxOctetString},
	{OID: "2.5.4.42", Name: "givenName", Equality: "caseIgnoreMatch", Syntax: syntaxDirectoryString},
	{OID: "2.5.4.43", Name: "initials", Equality: "caseIgnoreMatch", Syntax: syntaxDirectoryString},
	{OID: "2.5.4.50", Name: "uniqueMember", Equality: "uniqueMemberMatch", Syntax: syntaxDN},
	{OID: "0.9.2342.19200300.100.1.1", Name: "uid", Equality: "caseIgnoreMatch", Syntax: syntaxDirectoryString},
	{OID: "0.9.2342.19200300.100.1.3", Name: "mail", Equality: "caseIgnoreIA5Match", Syntax: syntaxIA5String},
	{OID: "0.9.2342.19200300.100.1.6", Name: "roomNumber", Equality: "caseIgnoreMatch", Syntax: syntaxDirectoryString},
	{OID: "0.9.2342.19200300.100.1.10", Name: "manager", Equality: "distinguishedNameMatch", Syntax: syntaxDN},
	{OID: "0.9.2342.19200300.100.1.20", Name: "homePhone", Equality: "telephoneNumberMatch", Syntax: syntaxTelephoneNumber},
	{OID: "0.9.2342.19200300.100.1.25", Name: "dc", Equality: "caseIgnoreIA5Match", Syntax: syntaxIA5String, SingleValue: true},
	{OID: "0.9.2342.19200300.100.1.41", Name: "mobile", Equality: "telephoneNumberMatch", Syntax: syntaxTelephoneNumber},
	{OID: "0.9.2342.19200300.100.1.42", Name: "pager", Equality: "telephoneNumberMatch", Syntax: syntaxTelephoneNumber},
	{OID: "0.9.2342.19200300.100.1.60", Name: "jpegPhoto", Syntax: syntaxJPEG},
	{OID: "2.16.840.1.113730.3.1.1", Name: "carLicense", Equality: "caseIgnoreMatch", Syntax: syntaxDirectoryString},
	{OID: "2.16.840.1.113730.3.1.2", Name: "departmentNumber", Equality: "caseIgnoreMatch", Syntax: syntaxDirectoryString},
	{OID: "2.16.840.1.113730.3.1.3", Name: "employeeNumber", Equality: "caseIgnoreMatch", Syntax: syntaxDirectoryString, SingleValue: true},
	{OID: "2.16.840.1.113730.3.1.4", Name: "employeeType", Equality: "caseIgnoreMatch", Syntax: syntaxDirectoryString},
	{OID: "2.16.840.1.113730.3.1.241", Name: "displayName", Equality: "caseIgnoreMatch", Syntax: syntaxDirectoryString, SingleValue: true},
	// 389-isms (ADR-0009 decisions 18-21). nsAccountLock is a directory
	// string holding "true", matching 389's definition.
	{OID: "2.16.840.1.113730.3.1.610", Name: "nsAccountLock", Equality: "caseIgnoreMatch", Syntax: syntaxDirectoryString, SingleValue: true},
	{OID: "2.16.840.1.113730.3.1.612", Name: "memberOf", Equality: "distinguishedNameMatch", Syntax: syntaxDN, Operational: true},
	{OID: "1.3.6.1.4.1.42.2.27.8.1.16", Name: "pwdChangedTime", Equality: "generalizedTimeMatch", Syntax: syntaxGeneralizedTime, SingleValue: true, Operational: true},
	{OID: "1.3.6.1.4.1.42.2.27.8.1.17", Name: "pwdAccountLockedTime", Equality: "generalizedTimeMatch", Syntax: syntaxGeneralizedTime, SingleValue: true, Operational: true},
	{OID: "2.16.840.1.113730.3.1.101", Name: "passwordHistory", Equality: "octetStringMatch", Syntax: syntaxOctetString, Operational: true},
	// 389 publishes aci without an equality rule; kept that way here.
	{OID: "2.16.840.1.113730.3.1.55", Name: "aci", Syntax: syntaxIA5String},
	// Operational entry attributes (values are generated by T-137).
	{OID: "2.5.18.1", Name: "createTimestamp", Equality: "generalizedTimeMatch", Syntax: syntaxGeneralizedTime, SingleValue: true, Operational: true},
	{OID: "2.5.18.2", Name: "modifyTimestamp", Equality: "generalizedTimeMatch", Syntax: syntaxGeneralizedTime, SingleValue: true, Operational: true},
	{OID: "2.5.18.3", Name: "creatorsName", Equality: "distinguishedNameMatch", Syntax: syntaxDN, SingleValue: true, Operational: true},
	{OID: "2.5.18.4", Name: "modifiersName", Equality: "distinguishedNameMatch", Syntax: syntaxDN, SingleValue: true, Operational: true},
	{OID: "1.3.6.1.1.16.4", Name: "entryUUID", Equality: "caseIgnoreMatch", Syntax: syntaxDirectoryString, SingleValue: true, Operational: true},
	// Root DSE attributes (RFC 4512 section 5.1).
	{OID: "1.3.6.1.4.1.1466.101.120.5", Name: "namingContexts", Equality: "distinguishedNameMatch", Syntax: syntaxDN, Operational: true},
	{OID: "2.5.18.10", Name: "subschemaSubentry", Equality: "distinguishedNameMatch", Syntax: syntaxDN, SingleValue: true, Operational: true},
	{OID: "1.3.6.1.4.1.1466.101.120.13", Name: "supportedControl", Equality: "objectIdentifierMatch", Syntax: syntaxOID, Operational: true},
	{OID: "1.3.6.1.4.1.1466.101.120.7", Name: "supportedExtension", Equality: "objectIdentifierMatch", Syntax: syntaxOID, Operational: true},
	{OID: "1.3.6.1.4.1.1466.101.120.15", Name: "supportedLDAPVersion", Equality: "integerMatch", Syntax: syntaxInteger, Operational: true},
	{OID: "1.3.6.1.4.1.1466.101.120.111", Name: "vendorName", Equality: "caseIgnoreMatch", Syntax: syntaxDirectoryString, SingleValue: true, Operational: true},
	{OID: "1.3.6.1.4.1.1466.101.120.112", Name: "vendorVersion", Equality: "caseIgnoreMatch", Syntax: syntaxDirectoryString, SingleValue: true, Operational: true},
	// Subschema subentry attributes (RFC 4512 section 4.2).
	{OID: "2.5.21.5", Name: "attributeTypes", Syntax: syntaxAttrTypeDesc, Operational: true},
	{OID: "2.5.21.6", Name: "objectClasses", Syntax: syntaxObjectClassDesc, Operational: true},
	{OID: "2.5.21.4", Name: "matchingRules", Syntax: syntaxMatchingRuleDesc, Operational: true},
}

var standardSchemaOnce = sync.OnceValues(func() (*Registry, error) {
	return NewRegistry(standardObjectClasses, standardAttributeTypes)
})

// StandardSchema returns the shared, validated contract registry (C5 plus
// the ADR-0009 389-isms). The static table is validated once; a broken
// table surfaces as an error at daemon startup, never a panic.
func StandardSchema() (*Registry, error) { return standardSchemaOnce() }

// schemaViolation carries the client-facing reason for a failed schema
// check. It wraps errSchemaViolation so mapWriteError keeps returning
// objectClassViolation while surfacing which class or attribute failed.
type schemaViolation struct{ reason string }

func (e *schemaViolation) Error() string { return "ldapserver: schema violation: " + e.reason }
func (e *schemaViolation) Unwrap() error { return errSchemaViolation }

// checkEntrySchema enforces the write-path schema gate on the final
// attribute set of an Add or Modify (T-132, D17):
//
//   - A registry with no object classes (the FakeSchema default) permits
//     everything, preserving the pre-T-132 test seam.
//   - Otherwise the entry must carry objectClass, every value must
//     resolve, and every MUST attribute — including those inherited
//     through SUP chains — must be present with at least one value.
//   - Every user attribute must resolve in the registry and sit on the
//     inherited MUST/MAY allow-list. Unknown names and marker extras
//     (destinationIndicator on device) fail objectClassViolation, matching
//     389 (D17). The baseline marker stays description JSON (OD-012).
//   - Operational attributes the server itself writes (entryUUID,
//     timestamps, memberOf, …) remain allowed even when no class lists
//     them in MAY.
func checkEntrySchema(s Schema, e *Entry) error {
	if len(s.ObjectClasses()) == 0 {
		return nil
	}
	ocValues := entryValues(s, e, "objectClass")
	if len(ocValues) == 0 {
		return &schemaViolation{reason: "entry has no objectClass attribute"}
	}
	must := map[string]struct{}{}
	allowed := map[string]struct{}{}
	visited := map[string]struct{}{}
	for _, v := range ocValues {
		oc, ok := s.ObjectClass(string(v))
		if !ok {
			return &schemaViolation{reason: fmt.Sprintf("unknown object class %q", string(v))}
		}
		collectMustMay(s, oc, must, allowed, visited)
	}
	for _, attr := range sortedKeys(must) {
		if len(entryValues(s, e, attr)) == 0 {
			return &schemaViolation{reason: fmt.Sprintf("missing required attribute %q", attr)}
		}
	}
	for _, a := range e.Attributes {
		if len(a.Values) == 0 {
			continue
		}
		at, ok := s.AttributeType(a.Name)
		if !ok {
			return &schemaViolation{reason: fmt.Sprintf("unknown attribute %q", a.Name)}
		}
		if at.Operational {
			continue
		}
		if !attrAllowed(allowed, at) {
			return &schemaViolation{reason: fmt.Sprintf("attribute %q is not permitted by object class", a.Name)}
		}
	}
	return nil
}

// collectMustMay unions oc's MUST into must and MUST+MAY into allowed,
// walking SUP chains transitively. The visited set makes malformed
// diamond/cyclic chains terminate; NewRegistry already rejects
// unresolvable SUPs, and lookups through the interface simply skip a
// registry that cannot resolve one.
func collectMustMay(s Schema, oc ObjectClassDef, must, allowed, visited map[string]struct{}) {
	key := strings.ToLower(oc.Name)
	if _, seen := visited[key]; seen {
		return
	}
	visited[key] = struct{}{}
	for _, m := range oc.Must {
		must[strings.ToLower(m)] = struct{}{}
		markAttrKeys(s, m, allowed)
	}
	for _, m := range oc.May {
		markAttrKeys(s, m, allowed)
	}
	for _, sup := range oc.Sup {
		if supOC, ok := s.ObjectClass(sup); ok {
			collectMustMay(s, supOC, must, allowed, visited)
		}
	}
}

// markAttrKeys records the schema name and, when the type resolves, its
// canonical name and OID so a client AttributeDescription in either form
// matches the MUST/MAY allow-list (RFC 4512).
func markAttrKeys(s Schema, name string, dest map[string]struct{}) {
	dest[strings.ToLower(name)] = struct{}{}
	if at, ok := s.AttributeType(name); ok {
		dest[strings.ToLower(at.Name)] = struct{}{}
		if at.OID != "" {
			dest[at.OID] = struct{}{}
		}
	}
}

func attrAllowed(allowed map[string]struct{}, at AttributeTypeDef) bool {
	if _, ok := allowed[strings.ToLower(at.Name)]; ok {
		return true
	}
	if at.OID != "" {
		_, ok := allowed[at.OID]
		return ok
	}
	return false
}

// entryValues returns the named attribute, accepting the schema name or
// the type's OID so MUST presence is not name-only.
func entryValues(s Schema, e *Entry, name string) [][]byte {
	if v := e.Values(name); len(v) > 0 {
		return v
	}
	at, ok := s.AttributeType(name)
	if !ok {
		return nil
	}
	if !strings.EqualFold(at.Name, name) {
		if v := e.Values(at.Name); len(v) > 0 {
			return v
		}
	}
	if at.OID != "" && !strings.EqualFold(at.OID, name) {
		return e.Values(at.OID)
	}
	return nil
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// SubschemaDN is the advertised subschemaSubentry value (C10).
const SubschemaDN = "cn=subschema"

// subschemaDNs are the base DNs answered with the subschema subentry:
// SubschemaDN is advertised, and "cn=schema" is the 389-shaped alias the
// control plane's capability inspect reads (ds389 schemaHasAccountLock).
var subschemaDNs = func() []config.DN {
	var out []config.DN
	for _, s := range []string{SubschemaDN, "cn=schema"} {
		if d, err := config.ParseDN(s); err == nil {
			out = append(out, d)
		}
	}
	return out
}()

// isSubschemaDN reports whether dn addresses the subschema subentry.
func isSubschemaDN(dn config.DN) bool {
	for _, d := range subschemaDNs {
		if dn.EqualFold(d) {
			return true
		}
	}
	return false
}

// matchingRuleOIDs maps the RFC 4517 equality-rule names the registry
// declares to their OIDs for subschema matchingRules publication. A rule
// absent here is simply not published; an OID is never invented.
var matchingRuleOIDs = map[string]string{
	"objectidentifiermatch":  "2.5.13.0",
	"distinguishednamematch": "2.5.13.1",
	"caseignorematch":        "2.5.13.2",
	"caseignorelistmatch":    "2.5.13.4",
	"caseexactmatch":         "2.5.13.5",
	"booleanmatch":           "2.5.13.13",
	"integermatch":           "2.5.13.14",
	"octetstringmatch":       "2.5.13.17",
	"telephonenumbermatch":   "2.5.13.20",
	"uniquemembermatch":      "2.5.13.23",
	"generalizedtimematch":   "2.5.13.27",
	"caseignoreia5match":     "1.3.6.1.4.1.1466.109.114.2",
}

// subschemaEntry builds the cn=subschema subentry from the registry (RFC
// 4512 section 4.2, parity contract C10). requestedDN is echoed back as
// the entry DN so the cn=schema alias answers with the name the client
// addressed.
func subschemaEntry(s Schema, requestedDN string) *Entry {
	cn := "subschema"
	if d, err := config.ParseDN(requestedDN); err == nil {
		if attr, val, ok := d.Leaf(); ok && strings.EqualFold(attr, "cn") {
			cn = val
		}
	}
	attrs := []Attribute{
		StringAttribute("objectClass", "top", "subschema"),
		StringAttribute("cn", cn),
	}
	if vals := formatAttributeTypes(s.AttributeTypes()); len(vals) > 0 {
		attrs = append(attrs, Attribute{Name: "attributeTypes", Values: vals})
	}
	if vals := formatObjectClasses(s.ObjectClasses()); len(vals) > 0 {
		attrs = append(attrs, Attribute{Name: "objectClasses", Values: vals})
	}
	if vals := formatMatchingRules(s); len(vals) > 0 {
		attrs = append(attrs, Attribute{Name: "matchingRules", Values: vals})
	}
	return &Entry{DN: requestedDN, Attributes: attrs}
}

// formatObjectClasses renders definitions in RFC 4512
// ObjectClassDescription form for subschema publication.
func formatObjectClasses(ocs []ObjectClassDef) [][]byte {
	out := make([][]byte, 0, len(ocs))
	for _, oc := range ocs {
		out = append(out, []byte(formatObjectClass(oc)))
	}
	return out
}

// formatObjectClass renders one ObjectClassDescription, for example:
// ( 2.5.6.6 NAME 'person' SUP top STRUCTURAL MUST ( sn $ cn ) MAY ( userPassword $ telephoneNumber ) )
func formatObjectClass(oc ObjectClassDef) string {
	var b strings.Builder
	fmt.Fprintf(&b, "( %s NAME '%s'", oc.OID, oc.Name)
	switch len(oc.Sup) {
	case 0:
	case 1:
		fmt.Fprintf(&b, " SUP %s", oc.Sup[0])
	default:
		fmt.Fprintf(&b, " SUP ( %s )", strings.Join(oc.Sup, " $ "))
	}
	fmt.Fprintf(&b, " %s", oc.Kind.String())
	if len(oc.Must) > 0 {
		fmt.Fprintf(&b, " MUST ( %s )", strings.Join(oc.Must, " $ "))
	}
	if len(oc.May) > 0 {
		fmt.Fprintf(&b, " MAY ( %s )", strings.Join(oc.May, " $ "))
	}
	b.WriteString(" )")
	return b.String()
}

// formatAttributeTypes renders definitions in RFC 4512
// AttributeTypeDescription form for subschema publication.
func formatAttributeTypes(ats []AttributeTypeDef) [][]byte {
	out := make([][]byte, 0, len(ats))
	for _, at := range ats {
		out = append(out, []byte(formatAttributeType(at)))
	}
	return out
}

// formatAttributeType renders one AttributeTypeDescription, for example:
// ( 2.5.4.3 NAME 'cn' EQUALITY caseIgnoreMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )
func formatAttributeType(at AttributeTypeDef) string {
	var b strings.Builder
	fmt.Fprintf(&b, "( %s NAME '%s'", at.OID, at.Name)
	if at.Equality != "" {
		fmt.Fprintf(&b, " EQUALITY %s", at.Equality)
	}
	if at.Syntax != "" {
		fmt.Fprintf(&b, " SYNTAX %s", at.Syntax)
	}
	if at.SingleValue {
		b.WriteString(" SINGLE-VALUE")
	}
	if at.Operational {
		b.WriteString(" NO-USER-MODIFICATION USAGE directoryOperation")
	}
	b.WriteString(" )")
	return b.String()
}

// formatMatchingRules publishes the distinct equality rules the registry
// declares, in RFC 4512 MatchingRuleDescription form.
func formatMatchingRules(s Schema) [][]byte {
	seen := map[string]struct{}{}
	var out []string
	for _, at := range s.AttributeTypes() {
		if at.Equality == "" {
			continue
		}
		key := strings.ToLower(at.Equality)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		oid, ok := matchingRuleOIDs[key]
		if !ok {
			continue
		}
		out = append(out, fmt.Sprintf("( %s NAME '%s' )", oid, at.Equality))
	}
	slices.Sort(out)
	vals := make([][]byte, 0, len(out))
	for _, v := range out {
		vals = append(vals, []byte(v))
	}
	return vals
}
