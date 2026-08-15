package ldapserver

// Well-known OIDs advertised on the Root DSE and routed by dispatch
// (parity contract C1, C9).
const (
	OIDStartTLS           = "1.3.6.1.4.1.1466.20037"  // RFC 4511 extended op
	OIDWhoAmI             = "1.3.6.1.4.1.4203.1.11.3" // RFC 4532
	OIDSimplePagedResults = "1.2.840.113556.1.4.319"  // RFC 2696
	OIDAssertion          = "1.3.6.1.1.12"            // RFC 4528
	// OIDNoticeOfDisconnection is the RFC 4511 section 4.4.1 unsolicited
	// notice sent as an ExtendedResponse with message ID 0 when the server
	// closes a connection on its own initiative.
	OIDNoticeOfDisconnection = "1.3.6.1.4.1.1466.20036"
)

// OpCode is the RFC 4511 protocolOp tag (APPLICATION number).
type OpCode int

const (
	OpBindRequest       OpCode = 0
	OpBindResponse      OpCode = 1
	OpUnbindRequest     OpCode = 2
	OpSearchRequest     OpCode = 3
	OpSearchResultEntry OpCode = 4
	OpSearchResultDone  OpCode = 5
	OpModifyRequest     OpCode = 6
	OpModifyResponse    OpCode = 7
	OpAddRequest        OpCode = 8
	OpAddResponse       OpCode = 9
	OpDeleteRequest     OpCode = 10
	OpDeleteResponse    OpCode = 11
	OpModifyDNRequest   OpCode = 12
	OpModifyDNResponse  OpCode = 13
	OpCompareRequest    OpCode = 14
	OpCompareResponse   OpCode = 15
	OpAbandonRequest    OpCode = 16
	OpExtendedRequest   OpCode = 23
	OpExtendedResponse  OpCode = 24
)

// Operation is one decoded RFC 4511 protocolOp. The typed request and
// response structs in this package implement it; the codec (T-124) produces
// and consumes them.
type Operation interface {
	OpCode() OpCode
}

// Message is one LDAPMessage: a message ID, the protocol operation, and any
// attached controls. Message ID correlation across a connection is a
// dispatcher concern (T-125), not the codec's.
type Message struct {
	ID       int64
	Op       Operation
	Controls []Control
}

// Control is one decoded LDAP control. Unsupported critical controls are
// rejected by dispatch with unavailableCriticalExtension (C9).
type Control struct {
	OID      string
	Critical bool
	Value    []byte
}

// ResultCode is an RFC 4511 LDAPResult resultCode. Only the codes the
// control plane maps (parity contract C1) plus compare and RFC 4528
// assertion outcomes are named here.
type ResultCode int

const (
	ResultSuccess                      ResultCode = 0
	ResultOperationsError              ResultCode = 1
	ResultProtocolError                ResultCode = 2
	ResultTimeLimitExceeded            ResultCode = 3
	ResultSizeLimitExceeded            ResultCode = 4
	ResultCompareFalse                 ResultCode = 5
	ResultCompareTrue                  ResultCode = 6
	ResultAuthMethodNotSupported       ResultCode = 7
	ResultStrongAuthRequired           ResultCode = 8
	ResultAdminLimitExceeded           ResultCode = 11
	ResultUnavailableCriticalExtension ResultCode = 12
	ResultConfidentialityRequired      ResultCode = 13
	ResultNoSuchAttribute              ResultCode = 16
	ResultConstraintViolation          ResultCode = 19
	ResultAttributeOrValueExists       ResultCode = 20
	ResultNoSuchObject                 ResultCode = 32
	ResultAliasProblem                 ResultCode = 33 // unused by LabLDAP; reserved for parity
	ResultInvalidDNSyntax              ResultCode = 34
	ResultInappropriateAuthentication  ResultCode = 48
	ResultInvalidCredentials           ResultCode = 49
	ResultInsufficientAccessRights     ResultCode = 50
	ResultBusy                         ResultCode = 51
	ResultUnavailable                  ResultCode = 52
	ResultUnwillingToPerform           ResultCode = 53
	ResultNamingViolation              ResultCode = 64
	ResultObjectClassViolation         ResultCode = 65
	ResultNotAllowedOnNonLeaf          ResultCode = 66
	ResultEntryAlreadyExists           ResultCode = 68
	ResultAffectsMultipleDSAs          ResultCode = 71 // unused by LabLDAP; reserved for parity
	ResultAssertionFailed              ResultCode = 122
)

// String returns the RFC 4511 result name for logs and diagnostics.
func (c ResultCode) String() string {
	switch c {
	case ResultSuccess:
		return "success"
	case ResultOperationsError:
		return "operationsError"
	case ResultProtocolError:
		return "protocolError"
	case ResultTimeLimitExceeded:
		return "timeLimitExceeded"
	case ResultSizeLimitExceeded:
		return "sizeLimitExceeded"
	case ResultCompareFalse:
		return "compareFalse"
	case ResultCompareTrue:
		return "compareTrue"
	case ResultAuthMethodNotSupported:
		return "authMethodNotSupported"
	case ResultStrongAuthRequired:
		return "strongAuthRequired"
	case ResultAdminLimitExceeded:
		return "adminLimitExceeded"
	case ResultUnavailableCriticalExtension:
		return "unavailableCriticalExtension"
	case ResultConfidentialityRequired:
		return "confidentialityRequired"
	case ResultNoSuchAttribute:
		return "noSuchAttribute"
	case ResultConstraintViolation:
		return "constraintViolation"
	case ResultAttributeOrValueExists:
		return "attributeOrValueExists"
	case ResultNoSuchObject:
		return "noSuchObject"
	case ResultAliasProblem:
		return "aliasProblem"
	case ResultInvalidDNSyntax:
		return "invalidDNSyntax"
	case ResultInappropriateAuthentication:
		return "inappropriateAuthentication"
	case ResultInvalidCredentials:
		return "invalidCredentials"
	case ResultInsufficientAccessRights:
		return "insufficientAccessRights"
	case ResultBusy:
		return "busy"
	case ResultUnavailable:
		return "unavailable"
	case ResultUnwillingToPerform:
		return "unwillingToPerform"
	case ResultNamingViolation:
		return "namingViolation"
	case ResultObjectClassViolation:
		return "objectClassViolation"
	case ResultNotAllowedOnNonLeaf:
		return "notAllowedOnNonLeaf"
	case ResultEntryAlreadyExists:
		return "entryAlreadyExists"
	case ResultAffectsMultipleDSAs:
		return "affectsMultipleDSAs"
	case ResultAssertionFailed:
		return "assertionFailed"
	default:
		return "unknownResultCode"
	}
}

// Result is the LDAPResult payload shared by all response operations.
// DiagnosticMessage must never carry credentials or secret-file content.
type Result struct {
	Code              ResultCode
	MatchedDN         string
	DiagnosticMessage string
}

// Attribute is one attribute with its values. Values are raw octet strings
// because LDAP attribute syntaxes are binary-safe.
type Attribute struct {
	Name   string
	Values [][]byte
}

// Scope is an RFC 4511 search scope.
type Scope int

const (
	ScopeBaseObject   Scope = 0
	ScopeSingleLevel  Scope = 1
	ScopeWholeSubtree Scope = 2
	// ScopeChildren is only valid when advertised on the Root DSE (C1).
	ScopeChildren Scope = 3
)

// DerefPolicy is the RFC 4511 derefAliases choice. LabLDAP clients use
// DerefNever; the others exist so the codec can round-trip the wire shape.
type DerefPolicy int

const (
	DerefNever       DerefPolicy = 0
	DerefInSearching DerefPolicy = 1
	DerefFindingBase DerefPolicy = 2
	DerefAlways      DerefPolicy = 3
)

// ModifyOp is the RFC 4511 modify change operation. Increment (RFC 4525) is
// outside the parity contract and intentionally absent.
type ModifyOp int

const (
	ModifyAdd     ModifyOp = 0
	ModifyDelete  ModifyOp = 1
	ModifyReplace ModifyOp = 2
)

// ModifyChange is one modification sequence element. For ModifyDelete an
// empty Values list removes the whole attribute.
type ModifyChange struct {
	Op   ModifyOp
	Attr Attribute
}

// BindRequest is a simple bind (SASL is Excluded, parity contract E2).
// Password is sensitive: callers zero it after use where practical and never
// log it.
type BindRequest struct {
	Version  int
	Name     string
	Password []byte
}

func (*BindRequest) OpCode() OpCode { return OpBindRequest }

// BindResponse carries the bind LDAPResult.
type BindResponse struct {
	Result Result
}

func (*BindResponse) OpCode() OpCode { return OpBindResponse }

// UnbindRequest closes the connection; no response PDU is sent (RFC 4511).
type UnbindRequest struct{}

func (*UnbindRequest) OpCode() OpCode { return OpUnbindRequest }

// SearchRequest is an RFC 4511 search. Server size and time limits are
// always applied by dispatch regardless of the requested values (C6).
type SearchRequest struct {
	BaseDN     string
	Scope      Scope
	Deref      DerefPolicy
	SizeLimit  int
	TimeLimit  int // seconds
	TypesOnly  bool
	Filter     Filter
	Attributes []string
}

func (*SearchRequest) OpCode() OpCode { return OpSearchRequest }

// SearchResultEntry is one matching entry on the wire.
type SearchResultEntry struct {
	DN         string
	Attributes []Attribute
}

func (*SearchResultEntry) OpCode() OpCode { return OpSearchResultEntry }

// SearchResultDone terminates a search result stream.
type SearchResultDone struct {
	Result Result
}

func (*SearchResultDone) OpCode() OpCode { return OpSearchResultDone }

// ModifyRequest applies attribute changes to one entry.
type ModifyRequest struct {
	DN      string
	Changes []ModifyChange
}

func (*ModifyRequest) OpCode() OpCode { return OpModifyRequest }

// ModifyResponse carries the modify LDAPResult.
type ModifyResponse struct {
	Result Result
}

func (*ModifyResponse) OpCode() OpCode { return OpModifyResponse }

// AddRequest creates one leaf entry.
type AddRequest struct {
	DN         string
	Attributes []Attribute
}

func (*AddRequest) OpCode() OpCode { return OpAddRequest }

// AddResponse carries the add LDAPResult.
type AddResponse struct {
	Result Result
}

func (*AddResponse) OpCode() OpCode { return OpAddResponse }

// DeleteRequest removes one leaf entry.
type DeleteRequest struct {
	DN string
}

func (*DeleteRequest) OpCode() OpCode { return OpDeleteRequest }

// DeleteResponse carries the delete LDAPResult.
type DeleteResponse struct {
	Result Result
}

func (*DeleteResponse) OpCode() OpCode { return OpDeleteResponse }

// ModifyDNRequest renames an entry or moves it within the suffix.
// NewSuperior empty means the entry keeps its current parent.
type ModifyDNRequest struct {
	DN           string
	NewRDN       string
	DeleteOldRDN bool
	NewSuperior  string
}

func (*ModifyDNRequest) OpCode() OpCode { return OpModifyDNRequest }

// ModifyDNResponse carries the moddn LDAPResult.
type ModifyDNResponse struct {
	Result Result
}

func (*ModifyDNResponse) OpCode() OpCode { return OpModifyDNResponse }

// CompareRequest asserts one attribute value on one entry.
type CompareRequest struct {
	DN    string
	Attr  string
	Value []byte
}

func (*CompareRequest) OpCode() OpCode { return OpCompareRequest }

// CompareResponse carries compareTrue or compareFalse in its result code.
type CompareResponse struct {
	Result Result
}

func (*CompareResponse) OpCode() OpCode { return OpCompareResponse }

// AbandonRequest cancels an outstanding operation on the same connection.
type AbandonRequest struct {
	MessageID int64
}

func (*AbandonRequest) OpCode() OpCode { return OpAbandonRequest }

// ExtendedRequest is an RFC 4511 extended operation. In M9 only StartTLS
// (OIDStartTLS) and WhoAmI (OIDWhoAmI) are routed; RFC 3062 Password Modify
// is Excluded (E3).
type ExtendedRequest struct {
	Name  string
	Value []byte
}

func (*ExtendedRequest) OpCode() OpCode { return OpExtendedRequest }

// ExtendedResponse carries the extended-operation result.
type ExtendedResponse struct {
	Result Result
	Name   string
	Value  []byte
}

func (*ExtendedResponse) OpCode() OpCode { return OpExtendedResponse }
