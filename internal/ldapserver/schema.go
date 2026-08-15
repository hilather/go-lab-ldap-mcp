package ldapserver

// ObjectClassKind is the RFC 4512 object class kind.
type ObjectClassKind int

const (
	ObjectClassAbstract ObjectClassKind = iota
	ObjectClassStructural
	ObjectClassAuxiliary
)

// String returns the RFC 4512 keyword used in subschema publication.
func (k ObjectClassKind) String() string {
	switch k {
	case ObjectClassAbstract:
		return "ABSTRACT"
	case ObjectClassStructural:
		return "STRUCTURAL"
	case ObjectClassAuxiliary:
		return "AUXILIARY"
	default:
		return "UNKNOWN"
	}
}

// ObjectClassDef is the RFC 4512 subset the native engine enforces for the
// contract object classes (parity contract C5): SUP chains and MUST/MAY
// lists drive add/modify checks (T-132).
type ObjectClassDef struct {
	OID  string
	Name string
	Kind ObjectClassKind
	Sup  []string
	Must []string
	May  []string
}

// AttributeTypeDef is the RFC 4512 subset the engine enforces. Equality
// names the matching rule (for example caseIgnoreMatch) used by search and
// compare evaluation (T-131); Operational marks non-user attributes such as
// entryUUID and createTimestamp.
type AttributeTypeDef struct {
	OID         string
	Name        string
	Equality    string
	Syntax      string
	SingleValue bool
	Operational bool
}

// Schema is the object class and attribute type registry. It backs schema
// enforcement on writes and subschema/Root DSE publication (parity contract
// C5, C10). Implementations are pure registries loaded at startup, so
// lookups take no context.Context; the registry lands in T-132.
type Schema interface {
	// ObjectClass resolves a name or OID, case-insensitively.
	ObjectClass(name string) (ObjectClassDef, bool)
	// AttributeType resolves a name or OID, case-insensitively.
	AttributeType(name string) (AttributeTypeDef, bool)
	// ObjectClasses lists the registry for subschema publication.
	ObjectClasses() []ObjectClassDef
	// AttributeTypes lists the registry for subschema publication.
	AttributeTypes() []AttributeTypeDef
}
