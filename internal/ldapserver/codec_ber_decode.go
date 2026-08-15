package ldapserver

import (
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// This file interprets a decoded BER packet tree as an RFC 4511
// LDAPMessage. Every shape violation returns a wrapped ErrMalformedPDU (or
// ErrUnsupportedOp for well-formed operations outside the pinned model);
// no decode path panics and no error string carries wire content.

// Filter CHOICE tags (RFC 4511 §4.5.1), context class.
const (
	tagFilterAnd        = 0
	tagFilterOr         = 1
	tagFilterNot        = 2
	tagFilterEquality   = 3
	tagFilterSubstrings = 4
	tagFilterGE         = 5
	tagFilterLE         = 6
	tagFilterPresent    = 7
	tagFilterApprox     = 8
	tagFilterExtensible = 9
)

// Context tags inside BindRequest / ModifyDNRequest / Extended*.
const (
	tagBindSimple         = 0
	tagBindSASL           = 3
	tagModifyDNSuperior   = 0
	tagExtendedReqName    = 0
	tagExtendedReqValue   = 1
	tagResultReferral     = 3
	tagBindServerSaslCred = 7
	tagExtendedRespName   = 10
	tagExtendedRespValue  = 11
)

func malformed(what string) error {
	return fmt.Errorf("ldapserver: decode %s: %w", what, ErrMalformedPDU)
}

// shape asserts the packet's identifier.
func shape(p *ber.Packet, class ber.Class, typ ber.Type, tag ber.Tag, what string) error {
	if p.ClassType != class || p.TagType != typ || p.Tag != tag {
		return malformed(what)
	}
	return nil
}

// octetString reads a universal primitive OCTET STRING.
func octetString(p *ber.Packet, what string) (string, error) {
	if err := shape(p, ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, what); err != nil {
		return "", err
	}
	s, ok := p.Value.(string)
	if !ok {
		return "", malformed(what)
	}
	return s, nil
}

// octetBytes reads a universal primitive OCTET STRING as a copied byte
// slice (LDAP attribute values are binary-safe).
func octetBytes(p *ber.Packet, what string) ([]byte, error) {
	s, err := octetString(p, what)
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

// contextString reads a context-class primitive's raw content as a string.
func contextString(p *ber.Packet, tag ber.Tag, what string) (string, error) {
	if err := shape(p, ber.ClassContext, ber.TypePrimitive, tag, what); err != nil {
		return "", err
	}
	return string(p.Data.Bytes()), nil
}

// ldapBool reads a universal primitive BOOLEAN. BER mandates exactly one
// content octet; asn1-ber is lenient, so the length is enforced here.
func ldapBool(p *ber.Packet, what string) (bool, error) {
	if err := shape(p, ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, what); err != nil {
		return false, err
	}
	b := p.Data.Bytes()
	if len(b) != 1 {
		return false, malformed(what)
	}
	return b[0] != 0, nil
}

func decodeMessage(p *ber.Packet) (*Message, error) {
	if err := shape(p, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, "LDAPMessage"); err != nil {
		return nil, err
	}
	if len(p.Children) < 2 || len(p.Children) > 3 {
		return nil, malformed("LDAPMessage child count")
	}
	if err := shape(p.Children[0], ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, "message id"); err != nil {
		return nil, err
	}
	id, err := intInRange(p.Children[0], 0, maxInt32, "message id")
	if err != nil {
		return nil, err
	}
	opPkt := p.Children[1]
	if opPkt.ClassType != ber.ClassApplication {
		return nil, malformed("protocol op class")
	}
	op, err := decodeOp(opPkt)
	if err != nil {
		return nil, err
	}
	m := &Message{ID: id, Op: op}
	if len(p.Children) == 3 {
		controls, err := decodeControls(p.Children[2])
		if err != nil {
			return nil, err
		}
		m.Controls = controls
	}
	return m, nil
}

func decodeOp(p *ber.Packet) (Operation, error) {
	switch OpCode(p.Tag) {
	case OpBindRequest:
		return decodeBindRequest(p)
	case OpBindResponse:
		return decodeBindResponse(p)
	case OpUnbindRequest:
		return decodeUnbind(p)
	case OpSearchRequest:
		return decodeSearchRequest(p)
	case OpSearchResultEntry:
		return decodeSearchResultEntry(p)
	case OpSearchResultDone:
		return decodeResultOp(p, OpSearchResultDone, "search result done")
	case OpModifyRequest:
		return decodeModifyRequest(p)
	case OpModifyResponse:
		return decodeResultOp(p, OpModifyResponse, "modify response")
	case OpAddRequest:
		return decodeAddRequest(p)
	case OpAddResponse:
		return decodeResultOp(p, OpAddResponse, "add response")
	case OpDeleteRequest:
		return decodeDeleteRequest(p)
	case OpDeleteResponse:
		return decodeResultOp(p, OpDeleteResponse, "delete response")
	case OpModifyDNRequest:
		return decodeModifyDNRequest(p)
	case OpModifyDNResponse:
		return decodeResultOp(p, OpModifyDNResponse, "modifydn response")
	case OpCompareRequest:
		return decodeCompareRequest(p)
	case OpCompareResponse:
		return decodeResultOp(p, OpCompareResponse, "compare response")
	case OpAbandonRequest:
		return decodeAbandonRequest(p)
	case OpExtendedRequest:
		return decodeExtendedRequest(p)
	case OpExtendedResponse:
		return decodeExtendedResponse(p)
	default:
		return nil, fmt.Errorf("ldapserver: decode protocol op tag %d: %w", p.Tag, ErrUnsupportedOp)
	}
}

// decodeResultOp parses a response operation that is exactly an LDAPResult
// and wraps it in the typed response for code.
func decodeResultOp(p *ber.Packet, code OpCode, what string) (Operation, error) {
	if err := shape(p, ber.ClassApplication, ber.TypeConstructed, ber.Tag(code), what); err != nil {
		return nil, err
	}
	res, err := decodeDone(p, what)
	if err != nil {
		return nil, err
	}
	switch code {
	case OpSearchResultDone:
		return &SearchResultDone{Result: res}, nil
	case OpModifyResponse:
		return &ModifyResponse{Result: res}, nil
	case OpAddResponse:
		return &AddResponse{Result: res}, nil
	case OpDeleteResponse:
		return &DeleteResponse{Result: res}, nil
	case OpModifyDNResponse:
		return &ModifyDNResponse{Result: res}, nil
	case OpCompareResponse:
		return &CompareResponse{Result: res}, nil
	default:
		return nil, malformed(what)
	}
}

// decodeBindRequest parses [APPLICATION 0] SEQUENCE { version, name, auth }.
func decodeBindRequest(p *ber.Packet) (Operation, error) {
	if err := shape(p, ber.ClassApplication, ber.TypeConstructed, ber.Tag(OpBindRequest), "bind request"); err != nil {
		return nil, err
	}
	if len(p.Children) != 3 {
		return nil, malformed("bind request child count")
	}
	if err := shape(p.Children[0], ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, "bind version"); err != nil {
		return nil, err
	}
	version, err := intInRange(p.Children[0], 1, 127, "bind version")
	if err != nil {
		return nil, err
	}
	name, err := octetString(p.Children[1], "bind name")
	if err != nil {
		return nil, err
	}
	auth := p.Children[2]
	if auth.ClassType != ber.ClassContext {
		return nil, malformed("bind authentication class")
	}
	if auth.Tag == tagBindSASL {
		// SASL is Excluded (parity contract E2).
		return nil, fmt.Errorf("ldapserver: decode bind request: sasl: %w", ErrUnsupportedOp)
	}
	if err := shape(auth, ber.ClassContext, ber.TypePrimitive, tagBindSimple, "bind simple authentication"); err != nil {
		return nil, err
	}
	password := append([]byte(nil), auth.Data.Bytes()...)
	// Scrub the password copy held inside the BER tree.
	clear(auth.Data.Bytes())
	return &BindRequest{Version: int(version), Name: name, Password: password}, nil
}

// decodeBindResponse parses [APPLICATION 1] LDAPResult plus the optional
// serverSaslCreds, which the model drops (SASL is Excluded, E2).
func decodeBindResponse(p *ber.Packet) (Operation, error) {
	if err := shape(p, ber.ClassApplication, ber.TypeConstructed, ber.Tag(OpBindResponse), "bind response"); err != nil {
		return nil, err
	}
	res, rest, err := decodeResultFields(p, "bind response")
	if err != nil {
		return nil, err
	}
	for _, extra := range rest {
		if err := shape(extra, ber.ClassContext, ber.TypePrimitive, tagBindServerSaslCred, "bind response extra field"); err != nil {
			return nil, err
		}
	}
	return &BindResponse{Result: res}, nil
}

func decodeUnbind(p *ber.Packet) (Operation, error) {
	if err := shape(p, ber.ClassApplication, ber.TypePrimitive, ber.Tag(OpUnbindRequest), "unbind request"); err != nil {
		return nil, err
	}
	if p.Data.Len() != 0 {
		return nil, malformed("unbind request content")
	}
	return &UnbindRequest{}, nil
}

// decodeSearchRequest parses [APPLICATION 3]; see RFC 4511 §4.5.1.
func decodeSearchRequest(p *ber.Packet) (Operation, error) {
	if err := shape(p, ber.ClassApplication, ber.TypeConstructed, ber.Tag(OpSearchRequest), "search request"); err != nil {
		return nil, err
	}
	if len(p.Children) != 8 {
		return nil, malformed("search request child count")
	}
	c := p.Children
	base, err := octetString(c[0], "search baseObject")
	if err != nil {
		return nil, err
	}
	scope, err := decodeEnum(c[1], 0, int64(ScopeChildren), "search scope")
	if err != nil {
		return nil, err
	}
	deref, err := decodeEnum(c[2], 0, int64(DerefAlways), "search derefAliases")
	if err != nil {
		return nil, err
	}
	size, err := decodeIntField(c[3], 0, maxInt32, "search sizeLimit")
	if err != nil {
		return nil, err
	}
	tlim, err := decodeIntField(c[4], 0, maxInt32, "search timeLimit")
	if err != nil {
		return nil, err
	}
	typesOnly, err := ldapBool(c[5], "search typesOnly")
	if err != nil {
		return nil, err
	}
	filter, err := decodeFilter(c[6])
	if err != nil {
		return nil, err
	}
	if err := shape(c[7], ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, "search attributes"); err != nil {
		return nil, err
	}
	var attrs []string
	for _, a := range c[7].Children {
		name, err := octetString(a, "search attribute")
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, name)
	}
	return &SearchRequest{
		BaseDN:     base,
		Scope:      Scope(scope),
		Deref:      DerefPolicy(deref),
		SizeLimit:  int(size),
		TimeLimit:  int(tlim),
		TypesOnly:  typesOnly,
		Filter:     filter,
		Attributes: attrs,
	}, nil
}

func decodeEnum(p *ber.Packet, lo, hi int64, what string) (int64, error) {
	if err := shape(p, ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, what); err != nil {
		return 0, err
	}
	return intInRange(p, lo, hi, what)
}

func decodeIntField(p *ber.Packet, lo, hi int64, what string) (int64, error) {
	if err := shape(p, ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, what); err != nil {
		return 0, err
	}
	return intInRange(p, lo, hi, what)
}

// decodeFilter parses one Filter CHOICE element. Recursion depth is bounded
// by the framing pre-scan's TLV depth budget.
func decodeFilter(p *ber.Packet) (Filter, error) {
	if p.ClassType != ber.ClassContext {
		return nil, malformed("filter class")
	}
	tag := int(p.Tag)
	switch tag {
	case tagFilterAnd, tagFilterOr:
		if p.TagType != ber.TypeConstructed {
			return nil, malformed("filter and/or")
		}
		var children []Filter // nil when empty: decoder output is canonical
		for _, ch := range p.Children {
			f, err := decodeFilter(ch)
			if err != nil {
				return nil, err
			}
			children = append(children, f)
		}
		if tag == tagFilterAnd {
			return &FilterAnd{Children: children}, nil
		}
		return &FilterOr{Children: children}, nil
	case tagFilterNot:
		if p.TagType != ber.TypeConstructed || len(p.Children) != 1 {
			return nil, malformed("filter not")
		}
		child, err := decodeFilter(p.Children[0])
		if err != nil {
			return nil, err
		}
		return &FilterNot{Child: child}, nil
	case tagFilterEquality, tagFilterGE, tagFilterLE, tagFilterApprox:
		attr, value, err := decodeAVA(p, "filter assertion")
		if err != nil {
			return nil, err
		}
		switch tag {
		case tagFilterEquality:
			return &FilterEquality{Attr: attr, Value: value}, nil
		case tagFilterGE:
			return &FilterGreaterOrEqual{Attr: attr, Value: value}, nil
		case tagFilterLE:
			return &FilterLessOrEqual{Attr: attr, Value: value}, nil
		default:
			return &FilterApproxMatch{Attr: attr, Value: value}, nil
		}
	case tagFilterPresent:
		attr, err := contextString(p, tagFilterPresent, "filter present")
		if err != nil {
			return nil, err
		}
		if attr == "" {
			return nil, malformed("filter present attribute")
		}
		return &FilterPresent{Attr: attr}, nil
	case tagFilterSubstrings:
		return decodeSubstringFilter(p)
	case tagFilterExtensible:
		return nil, fmt.Errorf("ldapserver: decode filter: extensible match: %w", ErrUnsupportedOp)
	default:
		return nil, malformed("filter tag")
	}
}

// decodeAVA parses an AttributeValueAssertion-shaped constructed packet.
func decodeAVA(p *ber.Packet, what string) (attr string, value []byte, err error) {
	if p.TagType != ber.TypeConstructed || len(p.Children) != 2 {
		return "", nil, malformed(what)
	}
	attr, err = octetString(p.Children[0], what)
	if err != nil {
		return "", nil, err
	}
	if attr == "" {
		return "", nil, malformed(what)
	}
	value, err = octetBytes(p.Children[1], what)
	if err != nil {
		return "", nil, err
	}
	return attr, value, nil
}

// decodeSubstringFilter parses [4] { type, substrings SEQUENCE OF CHOICE {
// initial [0], any [1], final [2] } }. Wire order is preserved for `any`;
// duplicate initial or final runs are rejected.
func decodeSubstringFilter(p *ber.Packet) (Filter, error) {
	if p.TagType != ber.TypeConstructed || len(p.Children) != 2 {
		return nil, malformed("substring filter")
	}
	attr, err := octetString(p.Children[0], "substring filter type")
	if err != nil {
		return nil, err
	}
	if attr == "" {
		return nil, malformed("substring filter type")
	}
	seq := p.Children[1]
	if err := shape(seq, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, "substring filter choices"); err != nil {
		return nil, err
	}
	if len(seq.Children) == 0 {
		return nil, malformed("substring filter empty choices")
	}
	out := &FilterSubstrings{Attr: attr}
	seenInitial, seenFinal := false, false
	for _, ch := range seq.Children {
		if ch.ClassType != ber.ClassContext || ch.TagType != ber.TypePrimitive {
			return nil, malformed("substring filter choice")
		}
		// Preserve emptiness (non-nil zero-length): an empty run must
		// re-encode to the empty [n] choice it came from.
		data := append([]byte{}, ch.Data.Bytes()...)
		switch int(ch.Tag) {
		case 0:
			if seenInitial {
				return nil, malformed("substring filter duplicate initial")
			}
			seenInitial = true
			out.Initial = data
		case 1:
			out.Any = append(out.Any, data)
		case 2:
			if seenFinal {
				return nil, malformed("substring filter duplicate final")
			}
			seenFinal = true
			out.Final = data
		default:
			return nil, malformed("substring filter choice tag")
		}
	}
	return out, nil
}

// decodeSearchResultEntry parses [APPLICATION 4] { objectName, attributes }.
func decodeSearchResultEntry(p *ber.Packet) (Operation, error) {
	if err := shape(p, ber.ClassApplication, ber.TypeConstructed, ber.Tag(OpSearchResultEntry), "search result entry"); err != nil {
		return nil, err
	}
	if len(p.Children) != 2 {
		return nil, malformed("search result entry child count")
	}
	dn, err := octetString(p.Children[0], "search result entry dn")
	if err != nil {
		return nil, err
	}
	attrs, err := decodeAttributes(p.Children[1], "search result entry attributes", 0)
	if err != nil {
		return nil, err
	}
	return &SearchResultEntry{DN: dn, Attributes: attrs}, nil
}

// decodeAttributes parses a SEQUENCE OF SEQUENCE { type, SET OF values }.
// minCount enforces RFC SIZE bounds (1 for Add, 0 for search results).
func decodeAttributes(p *ber.Packet, what string, minCount int) ([]Attribute, error) {
	if err := shape(p, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, what); err != nil {
		return nil, err
	}
	if len(p.Children) < minCount {
		return nil, malformed(what)
	}
	var attrs []Attribute
	for _, ap := range p.Children {
		attr, err := decodeAttribute(ap, what)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, attr)
	}
	return attrs, nil
}

// decodeAttribute parses one SEQUENCE { type OCTET STRING, vals SET OF
// OCTET STRING }.
func decodeAttribute(ap *ber.Packet, what string) (Attribute, error) {
	if err := shape(ap, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, what); err != nil {
		return Attribute{}, err
	}
	if len(ap.Children) != 2 {
		return Attribute{}, malformed(what)
	}
	name, err := octetString(ap.Children[0], what)
	if err != nil {
		return Attribute{}, err
	}
	if name == "" {
		return Attribute{}, malformed(what)
	}
	if err := shape(ap.Children[1], ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, what); err != nil {
		return Attribute{}, err
	}
	attr := Attribute{Name: name}
	for _, vp := range ap.Children[1].Children {
		v, err := octetBytes(vp, what)
		if err != nil {
			return Attribute{}, err
		}
		attr.Values = append(attr.Values, v)
	}
	return attr, nil
}

// decodeResultFields parses the LDAPResult components (resultCode,
// matchedDN, diagnosticMessage) shared by all response operations and
// returns the remaining children with referrals ([3]) dropped.
func decodeResultFields(p *ber.Packet, what string) (Result, []*ber.Packet, error) {
	if p.TagType != ber.TypeConstructed {
		return Result{}, nil, malformed(what)
	}
	if len(p.Children) < 3 {
		return Result{}, nil, malformed(what + " result child count")
	}
	code, err := decodeEnum(p.Children[0], 0, maxInt32, what+" resultCode")
	if err != nil {
		return Result{}, nil, err
	}
	matched, err := octetString(p.Children[1], what+" matchedDN")
	if err != nil {
		return Result{}, nil, err
	}
	diag, err := octetString(p.Children[2], what+" diagnosticMessage")
	if err != nil {
		return Result{}, nil, err
	}
	res := Result{Code: ResultCode(code), MatchedDN: matched, DiagnosticMessage: diag}
	var rest []*ber.Packet
	for _, extra := range p.Children[3:] {
		if extra.ClassType == ber.ClassContext && extra.Tag == tagResultReferral {
			continue // referrals are outside the pinned model; dropped
		}
		rest = append(rest, extra)
	}
	return res, rest, nil
}

// decodeDone parses a response operation that is exactly an LDAPResult
// (SearchResultDone, ModifyResponse, AddResponse, DeleteResponse,
// ModifyDNResponse, CompareResponse).
func decodeDone(p *ber.Packet, what string) (Result, error) {
	res, rest, err := decodeResultFields(p, what)
	if err != nil {
		return Result{}, err
	}
	if len(rest) != 0 {
		return Result{}, malformed(what + " extra fields")
	}
	return res, nil
}

// decodeModifyRequest parses [APPLICATION 6] { object, changes }.
func decodeModifyRequest(p *ber.Packet) (Operation, error) {
	if err := shape(p, ber.ClassApplication, ber.TypeConstructed, ber.Tag(OpModifyRequest), "modify request"); err != nil {
		return nil, err
	}
	if len(p.Children) != 2 {
		return nil, malformed("modify request child count")
	}
	dn, err := octetString(p.Children[0], "modify request dn")
	if err != nil {
		return nil, err
	}
	seq := p.Children[1]
	if err := shape(seq, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, "modify changes"); err != nil {
		return nil, err
	}
	if len(seq.Children) == 0 {
		return nil, malformed("modify request empty changes")
	}
	var changes []ModifyChange
	for _, cp := range seq.Children {
		if err := shape(cp, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, "modify change"); err != nil {
			return nil, err
		}
		if len(cp.Children) != 2 {
			return nil, malformed("modify change child count")
		}
		op, err := decodeEnum(cp.Children[0], int64(ModifyAdd), int64(ModifyReplace), "modify change operation")
		if err != nil {
			return nil, err
		}
		attr, err := decodeAttribute(cp.Children[1], "modify change attribute")
		if err != nil {
			return nil, err
		}
		changes = append(changes, ModifyChange{Op: ModifyOp(op), Attr: attr})
	}
	return &ModifyRequest{DN: dn, Changes: changes}, nil
}

// decodeAddRequest parses [APPLICATION 8] { entry, attributes }.
func decodeAddRequest(p *ber.Packet) (Operation, error) {
	if err := shape(p, ber.ClassApplication, ber.TypeConstructed, ber.Tag(OpAddRequest), "add request"); err != nil {
		return nil, err
	}
	if len(p.Children) != 2 {
		return nil, malformed("add request child count")
	}
	dn, err := octetString(p.Children[0], "add request dn")
	if err != nil {
		return nil, err
	}
	attrs, err := decodeAttributes(p.Children[1], "add request attributes", 1)
	if err != nil {
		return nil, err
	}
	return &AddRequest{DN: dn, Attributes: attrs}, nil
}

// decodeDeleteRequest parses [APPLICATION 10] LDAPDN (primitive content).
func decodeDeleteRequest(p *ber.Packet) (Operation, error) {
	if err := shape(p, ber.ClassApplication, ber.TypePrimitive, ber.Tag(OpDeleteRequest), "delete request"); err != nil {
		return nil, err
	}
	return &DeleteRequest{DN: string(p.Data.Bytes())}, nil
}

// decodeModifyDNRequest parses [APPLICATION 12] { entry, newrdn,
// deleteoldrdn, newSuperior [0] OPTIONAL }.
func decodeModifyDNRequest(p *ber.Packet) (Operation, error) {
	if err := shape(p, ber.ClassApplication, ber.TypeConstructed, ber.Tag(OpModifyDNRequest), "modifydn request"); err != nil {
		return nil, err
	}
	if len(p.Children) != 3 && len(p.Children) != 4 {
		return nil, malformed("modifydn request child count")
	}
	dn, err := octetString(p.Children[0], "modifydn entry")
	if err != nil {
		return nil, err
	}
	rdn, err := octetString(p.Children[1], "modifydn newrdn")
	if err != nil {
		return nil, err
	}
	del, err := ldapBool(p.Children[2], "modifydn deleteoldrdn")
	if err != nil {
		return nil, err
	}
	req := &ModifyDNRequest{DN: dn, NewRDN: rdn, DeleteOldRDN: del}
	if len(p.Children) == 4 {
		sup, err := contextString(p.Children[3], tagModifyDNSuperior, "modifydn newSuperior")
		if err != nil {
			return nil, err
		}
		req.NewSuperior = sup
	}
	return req, nil
}

// decodeCompareRequest parses [APPLICATION 14] { entry, ava }.
func decodeCompareRequest(p *ber.Packet) (Operation, error) {
	if err := shape(p, ber.ClassApplication, ber.TypeConstructed, ber.Tag(OpCompareRequest), "compare request"); err != nil {
		return nil, err
	}
	if len(p.Children) != 2 {
		return nil, malformed("compare request child count")
	}
	dn, err := octetString(p.Children[0], "compare request dn")
	if err != nil {
		return nil, err
	}
	attr, value, err := decodeAVA(p.Children[1], "compare request ava")
	if err != nil {
		return nil, err
	}
	return &CompareRequest{DN: dn, Attr: attr, Value: value}, nil
}

// decodeAbandonRequest parses [APPLICATION 16] MessageID: primitive content
// holding the target message ID's INTEGER content octets (implicit tag).
func decodeAbandonRequest(p *ber.Packet) (Operation, error) {
	if err := shape(p, ber.ClassApplication, ber.TypePrimitive, ber.Tag(OpAbandonRequest), "abandon request"); err != nil {
		return nil, err
	}
	n := len(p.Data.Bytes())
	if n == 0 || n > 8 {
		return nil, malformed("abandon request message id")
	}
	id, err := ber.ParseInt64(p.Data.Bytes())
	if err != nil {
		return nil, malformed("abandon request message id")
	}
	if id < 0 || id > maxInt32 {
		return nil, malformed("abandon request message id range")
	}
	return &AbandonRequest{MessageID: id}, nil
}

// decodeExtendedRequest parses [APPLICATION 23] { requestName [0],
// requestValue [1] OPTIONAL }.
func decodeExtendedRequest(p *ber.Packet) (Operation, error) {
	if err := shape(p, ber.ClassApplication, ber.TypeConstructed, ber.Tag(OpExtendedRequest), "extended request"); err != nil {
		return nil, err
	}
	if len(p.Children) < 1 || len(p.Children) > 2 {
		return nil, malformed("extended request child count")
	}
	name, err := contextString(p.Children[0], tagExtendedReqName, "extended request name")
	if err != nil {
		return nil, err
	}
	req := &ExtendedRequest{Name: name}
	if len(p.Children) == 2 {
		if err := shape(p.Children[1], ber.ClassContext, ber.TypePrimitive, tagExtendedReqValue, "extended request value"); err != nil {
			return nil, err
		}
		req.Value = append([]byte(nil), p.Children[1].Data.Bytes()...)
	}
	return req, nil
}

// decodeExtendedResponse parses [APPLICATION 24] LDAPResult plus optional
// responseName [10] and responseValue [11].
func decodeExtendedResponse(p *ber.Packet) (Operation, error) {
	if err := shape(p, ber.ClassApplication, ber.TypeConstructed, ber.Tag(OpExtendedResponse), "extended response"); err != nil {
		return nil, err
	}
	res, rest, err := decodeResultFields(p, "extended response")
	if err != nil {
		return nil, err
	}
	resp := &ExtendedResponse{Result: res}
	for _, extra := range rest {
		switch int(extra.Tag) {
		case tagExtendedRespName:
			name, err := contextString(extra, tagExtendedRespName, "extended response name")
			if err != nil {
				return nil, err
			}
			resp.Name = name
		case tagExtendedRespValue:
			if err := shape(extra, ber.ClassContext, ber.TypePrimitive, tagExtendedRespValue, "extended response value"); err != nil {
				return nil, err
			}
			resp.Value = append([]byte(nil), extra.Data.Bytes()...)
		default:
			return nil, malformed("extended response extra field")
		}
	}
	return resp, nil
}

// decodeControls parses the LDAPMessage controls field: [0] SEQUENCE OF
// SEQUENCE { controlType OCTET STRING, criticality BOOLEAN DEFAULT FALSE,
// controlValue OCTET STRING OPTIONAL }. An absent or empty controlValue
// decodes to nil; an absent criticality decodes to false.
func decodeControls(p *ber.Packet) ([]Control, error) {
	if err := shape(p, ber.ClassContext, ber.TypeConstructed, 0, "controls"); err != nil {
		return nil, err
	}
	var controls []Control // nil when empty: decoder output is canonical
	for _, cp := range p.Children {
		if err := shape(cp, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, "control"); err != nil {
			return nil, err
		}
		if len(cp.Children) < 1 || len(cp.Children) > 3 {
			return nil, malformed("control child count")
		}
		oid, err := octetString(cp.Children[0], "control type")
		if err != nil {
			return nil, err
		}
		if oid == "" {
			return nil, malformed("control type")
		}
		ctrl := Control{OID: oid}
		for _, f := range cp.Children[1:] {
			switch {
			case f.ClassType == ber.ClassUniversal && f.Tag == ber.TagBoolean:
				v, err := ldapBool(f, "control criticality")
				if err != nil {
					return nil, err
				}
				ctrl.Critical = v
			case f.ClassType == ber.ClassUniversal && f.Tag == ber.TagOctetString:
				v, err := octetBytes(f, "control value")
				if err != nil {
					return nil, err
				}
				if len(v) > 0 {
					ctrl.Value = v
				}
			default:
				return nil, malformed("control field")
			}
		}
		controls = append(controls, ctrl)
	}
	return controls, nil
}
