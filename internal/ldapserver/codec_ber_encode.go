package ldapserver

import (
	"errors"
	"fmt"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// This file encodes the pinned message model into BER packet trees. The
// encoder emits the canonical form the decoder accepts (minimal-length
// integers and lengths, TRUE encoded as 0xFF per RFC 4511, DEFAULT fields
// omitted when unset), so decode->encode is byte-stable for canonical PDUs.
//
// asn1-ber helpers panic on unsupported value types (ber.NewInteger takes
// only ints); every value passed here is int64 or string, and model
// validation failures return errors instead.

// maxEncodeFilterDepth bounds encodeFilter recursion. Decoded filters are
// already bounded by the read-side TLV depth budget; this guard keeps a
// hand-built pathological filter tree from overflowing the stack on write.
const maxEncodeFilterDepth = 256

// encodeMessage encodes one LDAPMessage and returns its bytes. The packet
// tree is scrubbed after encoding: it may hold a copy of a bind password.
func encodeMessage(m *Message) ([]byte, error) {
	if m == nil || m.Op == nil {
		return nil, errors.New("ldapserver: encode message: nil message or operation")
	}
	if m.ID < 0 || m.ID > maxInt32 {
		return nil, errors.New("ldapserver: encode message: message id out of range")
	}
	op, err := encodeOp(m.Op)
	if err != nil {
		return nil, err
	}
	pkt := ber.NewSequence("LDAPMessage")
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, m.ID, "MessageID"))
	pkt.AppendChild(op)
	if len(m.Controls) > 0 {
		controls, err := encodeControls(m.Controls)
		if err != nil {
			return nil, err
		}
		pkt.AppendChild(controls)
	}
	out := pkt.Bytes()
	scrubPacket(pkt)
	return out, nil
}

// scrubPacket zeroes the content buffers of a packet tree (iteratively, so
// a deep tree cannot overflow the stack either).
func scrubPacket(p *ber.Packet) {
	stack := []*ber.Packet{p}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if n.Data != nil {
			clear(n.Data.Bytes())
		}
		stack = append(stack, n.Children...)
	}
}

func encodeOp(op Operation) (*ber.Packet, error) {
	switch o := op.(type) {
	case *BindRequest:
		return encodeBindRequest(o)
	case *BindResponse:
		return encodeResultOp(ber.Tag(OpBindResponse), o.Result, "BindResponse"), nil
	case *UnbindRequest:
		return ber.Encode(ber.ClassApplication, ber.TypePrimitive, ber.Tag(OpUnbindRequest), nil, "UnbindRequest"), nil
	case *SearchRequest:
		return encodeSearchRequest(o)
	case *SearchResultEntry:
		return encodeSearchResultEntry(o)
	case *SearchResultDone:
		return encodeResultOp(ber.Tag(OpSearchResultDone), o.Result, "SearchResultDone"), nil
	case *ModifyRequest:
		return encodeModifyRequest(o)
	case *ModifyResponse:
		return encodeResultOp(ber.Tag(OpModifyResponse), o.Result, "ModifyResponse"), nil
	case *AddRequest:
		return encodeAddRequest(o)
	case *AddResponse:
		return encodeResultOp(ber.Tag(OpAddResponse), o.Result, "AddResponse"), nil
	case *DeleteRequest:
		return ber.NewString(ber.ClassApplication, ber.TypePrimitive, ber.Tag(OpDeleteRequest), o.DN, "DeleteRequest"), nil
	case *DeleteResponse:
		return encodeResultOp(ber.Tag(OpDeleteResponse), o.Result, "DeleteResponse"), nil
	case *ModifyDNRequest:
		return encodeModifyDNRequest(o)
	case *ModifyDNResponse:
		return encodeResultOp(ber.Tag(OpModifyDNResponse), o.Result, "ModifyDNResponse"), nil
	case *CompareRequest:
		return encodeCompareRequest(o)
	case *CompareResponse:
		return encodeResultOp(ber.Tag(OpCompareResponse), o.Result, "CompareResponse"), nil
	case *AbandonRequest:
		if o.MessageID < 0 || o.MessageID > maxInt32 {
			return nil, errors.New("ldapserver: encode abandon request: message id out of range")
		}
		// [APPLICATION 16] MessageID is implicit-tagged: the primitive
		// content is the bare INTEGER content octets, not a full INTEGER TLV.
		ip := ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, o.MessageID, "MessageID")
		p := ber.Encode(ber.ClassApplication, ber.TypePrimitive, ber.Tag(OpAbandonRequest), nil, "AbandonRequest")
		p.Data.Write(ip.Data.Bytes())
		return p, nil
	case *ExtendedRequest:
		return encodeExtendedRequest(o)
	case *ExtendedResponse:
		return encodeExtendedResponse(o)
	default:
		return nil, fmt.Errorf("ldapserver: encode: unknown operation %T", op)
	}
}

func encodeBindRequest(r *BindRequest) (*ber.Packet, error) {
	if r.Version < 1 || r.Version > 127 {
		return nil, errors.New("ldapserver: encode bind request: version out of range")
	}
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(OpBindRequest), nil, "BindRequest")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(r.Version), "Version"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, r.Name, "Name"))
	// AuthenticationChoice simple: [0] OCTET STRING. string(password) copies
	// the bytes into the packet; the tree is scrubbed after encoding.
	p.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagBindSimple, string(r.Password), "Simple"))
	return p, nil
}

// encodeResultOp builds a constructed application packet holding an
// LDAPResult (resultCode ENUMERATED, matchedDN, diagnosticMessage).
func encodeResultOp(tag ber.Tag, res Result, desc string) *ber.Packet {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, desc)
	appendResult(p, res)
	return p
}

func appendResult(p *ber.Packet, res Result) {
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(res.Code), "ResultCode"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, res.MatchedDN, "MatchedDN"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, res.DiagnosticMessage, "DiagnosticMessage"))
}

func encodeSearchRequest(r *SearchRequest) (*ber.Packet, error) {
	if r.Scope < ScopeBaseObject || r.Scope > ScopeChildren {
		return nil, errors.New("ldapserver: encode search request: scope out of range")
	}
	if r.Deref < DerefNever || r.Deref > DerefAlways {
		return nil, errors.New("ldapserver: encode search request: derefAliases out of range")
	}
	if r.SizeLimit < 0 || int64(r.SizeLimit) > maxInt32 {
		return nil, errors.New("ldapserver: encode search request: sizeLimit out of range")
	}
	if r.TimeLimit < 0 || int64(r.TimeLimit) > maxInt32 {
		return nil, errors.New("ldapserver: encode search request: timeLimit out of range")
	}
	if r.Filter == nil {
		return nil, errors.New("ldapserver: encode search request: nil filter")
	}
	filter, err := encodeFilter(r.Filter, 0)
	if err != nil {
		return nil, err
	}
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(OpSearchRequest), nil, "SearchRequest")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, r.BaseDN, "BaseObject"))
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(r.Scope), "Scope"))
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(r.Deref), "DerefAliases"))
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(r.SizeLimit), "SizeLimit"))
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(r.TimeLimit), "TimeLimit"))
	p.AppendChild(ber.NewLDAPBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, r.TypesOnly, "TypesOnly"))
	p.AppendChild(filter)
	attrs := ber.NewSequence("Attributes")
	for _, a := range r.Attributes {
		attrs.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, a, "Attribute"))
	}
	p.AppendChild(attrs)
	return p, nil
}

// encodeFilter encodes one Filter node. depth is the current recursion
// depth, capped at maxEncodeFilterDepth.
func encodeFilter(f Filter, depth int) (*ber.Packet, error) {
	if depth > maxEncodeFilterDepth {
		return nil, errors.New("ldapserver: encode filter: depth limit exceeded")
	}
	switch v := f.(type) {
	case *FilterAnd:
		p := ber.Encode(ber.ClassContext, ber.TypeConstructed, tagFilterAnd, nil, "And")
		for _, child := range v.Children {
			cp, err := encodeFilter(child, depth+1)
			if err != nil {
				return nil, err
			}
			p.AppendChild(cp)
		}
		return p, nil
	case *FilterOr:
		p := ber.Encode(ber.ClassContext, ber.TypeConstructed, tagFilterOr, nil, "Or")
		for _, child := range v.Children {
			cp, err := encodeFilter(child, depth+1)
			if err != nil {
				return nil, err
			}
			p.AppendChild(cp)
		}
		return p, nil
	case *FilterNot:
		if v.Child == nil {
			return nil, errors.New("ldapserver: encode filter: not with nil child")
		}
		cp, err := encodeFilter(v.Child, depth+1)
		if err != nil {
			return nil, err
		}
		p := ber.Encode(ber.ClassContext, ber.TypeConstructed, tagFilterNot, nil, "Not")
		p.AppendChild(cp)
		return p, nil
	case *FilterEquality:
		return encodeAVA(v.Attr, v.Value, tagFilterEquality, "EqualityMatch"), nil
	case *FilterGreaterOrEqual:
		return encodeAVA(v.Attr, v.Value, tagFilterGE, "GreaterOrEqual"), nil
	case *FilterLessOrEqual:
		return encodeAVA(v.Attr, v.Value, tagFilterLE, "LessOrEqual"), nil
	case *FilterApproxMatch:
		return encodeAVA(v.Attr, v.Value, tagFilterApprox, "ApproxMatch"), nil
	case *FilterPresent:
		return ber.NewString(ber.ClassContext, ber.TypePrimitive, tagFilterPresent, v.Attr, "Present"), nil
	case *FilterSubstrings:
		return encodeSubstrings(v)
	default:
		return nil, fmt.Errorf("ldapserver: encode filter: unknown filter %T", f)
	}
}

func encodeAVA(attr string, value []byte, tag ber.Tag, desc string) *ber.Packet {
	p := ber.Encode(ber.ClassContext, ber.TypeConstructed, tag, nil, desc)
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, attr, "AttributeDesc"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(value), "AssertionValue"))
	return p
}

func encodeSubstrings(f *FilterSubstrings) (*ber.Packet, error) {
	if f.Initial == nil && len(f.Any) == 0 && f.Final == nil {
		return nil, errors.New("ldapserver: encode substring filter: no runs")
	}
	choices := ber.NewSequence("Substrings")
	if f.Initial != nil {
		choices.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, string(f.Initial), "Initial"))
	}
	for _, any := range f.Any {
		choices.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 1, string(any), "Any"))
	}
	if f.Final != nil {
		choices.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 2, string(f.Final), "Final"))
	}
	p := ber.Encode(ber.ClassContext, ber.TypeConstructed, tagFilterSubstrings, nil, "Substrings")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, f.Attr, "Type"))
	p.AppendChild(choices)
	return p, nil
}

// encodeAttributes builds a SEQUENCE OF SEQUENCE { type, SET OF values }.
func encodeAttributes(desc string, attrs []Attribute) (*ber.Packet, error) {
	list := ber.NewSequence(desc)
	for _, a := range attrs {
		pair, err := encodeAttribute(desc, a)
		if err != nil {
			return nil, err
		}
		list.AppendChild(pair)
	}
	return list, nil
}

// encodeAttribute builds one SEQUENCE { type OCTET STRING, vals SET OF
// OCTET STRING }.
func encodeAttribute(desc string, a Attribute) (*ber.Packet, error) {
	if a.Name == "" {
		return nil, fmt.Errorf("ldapserver: encode %s: empty attribute name", desc)
	}
	pair := ber.NewSequence(desc + " attribute")
	pair.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, a.Name, "Type"))
	vals := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "Vals")
	for _, v := range a.Values {
		vals.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(v), "Value"))
	}
	pair.AppendChild(vals)
	return pair, nil
}

func encodeSearchResultEntry(e *SearchResultEntry) (*ber.Packet, error) {
	attrs, err := encodeAttributes("search result entry", e.Attributes)
	if err != nil {
		return nil, err
	}
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(OpSearchResultEntry), nil, "SearchResultEntry")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.DN, "ObjectName"))
	p.AppendChild(attrs)
	return p, nil
}

func encodeModifyRequest(r *ModifyRequest) (*ber.Packet, error) {
	if len(r.Changes) == 0 {
		return nil, errors.New("ldapserver: encode modify request: no changes")
	}
	changes := ber.NewSequence("Changes")
	for _, ch := range r.Changes {
		if ch.Op < ModifyAdd || ch.Op > ModifyReplace {
			return nil, errors.New("ldapserver: encode modify request: change operation out of range")
		}
		attr, err := encodeAttribute("modify change", ch.Attr)
		if err != nil {
			return nil, err
		}
		change := ber.NewSequence("Change")
		change.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(ch.Op), "Operation"))
		change.AppendChild(attr)
		changes.AppendChild(change)
	}
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(OpModifyRequest), nil, "ModifyRequest")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, r.DN, "Object"))
	p.AppendChild(changes)
	return p, nil
}

func encodeAddRequest(r *AddRequest) (*ber.Packet, error) {
	if len(r.Attributes) == 0 {
		return nil, errors.New("ldapserver: encode add request: no attributes")
	}
	attrs, err := encodeAttributes("add request", r.Attributes)
	if err != nil {
		return nil, err
	}
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(OpAddRequest), nil, "AddRequest")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, r.DN, "Entry"))
	p.AppendChild(attrs)
	return p, nil
}

func encodeModifyDNRequest(r *ModifyDNRequest) (*ber.Packet, error) {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(OpModifyDNRequest), nil, "ModifyDNRequest")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, r.DN, "Entry"))
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, r.NewRDN, "NewRDN"))
	p.AppendChild(ber.NewLDAPBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, r.DeleteOldRDN, "DeleteOldRDN"))
	if r.NewSuperior != "" {
		p.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagModifyDNSuperior, r.NewSuperior, "NewSuperior"))
	}
	return p, nil
}

func encodeCompareRequest(r *CompareRequest) (*ber.Packet, error) {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(OpCompareRequest), nil, "CompareRequest")
	p.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, r.DN, "Entry"))
	p.AppendChild(encodeAVA(r.Attr, r.Value, ber.TagSequence, "AVA"))
	return p, nil
}

func encodeExtendedRequest(r *ExtendedRequest) (*ber.Packet, error) {
	if r.Name == "" {
		return nil, errors.New("ldapserver: encode extended request: empty name")
	}
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(OpExtendedRequest), nil, "ExtendedRequest")
	p.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagExtendedReqName, r.Name, "RequestName"))
	if len(r.Value) > 0 {
		p.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagExtendedReqValue, string(r.Value), "RequestValue"))
	}
	return p, nil
}

func encodeExtendedResponse(r *ExtendedResponse) (*ber.Packet, error) {
	p := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(OpExtendedResponse), nil, "ExtendedResponse")
	appendResult(p, r.Result)
	if r.Name != "" {
		p.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagExtendedRespName, r.Name, "ResponseName"))
	}
	if len(r.Value) > 0 {
		p.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, tagExtendedRespValue, string(r.Value), "ResponseValue"))
	}
	return p, nil
}

// encodeControls builds the [0] controls field. Criticality is omitted when
// false (DEFAULT FALSE) and controlValue when empty, matching the decoder's
// normalization.
func encodeControls(controls []Control) (*ber.Packet, error) {
	p := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
	for _, c := range controls {
		if c.OID == "" || !strings.Contains(c.OID, ".") {
			return nil, errors.New("ldapserver: encode control: invalid OID")
		}
		cp := ber.NewSequence("Control")
		cp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, c.OID, "ControlType"))
		if c.Critical {
			cp.AppendChild(ber.NewLDAPBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "Criticality"))
		}
		if len(c.Value) > 0 {
			cp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(c.Value), "ControlValue"))
		}
		p.AppendChild(cp)
	}
	return p, nil
}
