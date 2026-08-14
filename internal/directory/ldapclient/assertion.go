package ldapclient

import (
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

// ControlTypeAssertion is RFC 4528 LDAP assertion control.
const ControlTypeAssertion = directory.ControlAssertionOID

// ControlAssertion encodes a critical LDAP assertion (RFC 4528).
// go-ldap v3.4 does not ship this control.
type ControlAssertion struct {
	Filter      string
	Criticality bool
	packet      *ber.Packet
}

// NewControlAssertion compiles filter into a critical assertion control.
func NewControlAssertion(filter string) (*ControlAssertion, error) {
	pkt, err := ldap.CompileFilter(filter)
	if err != nil {
		return nil, fmt.Errorf("assertion filter: %w", err)
	}
	return &ControlAssertion{Filter: filter, Criticality: true, packet: pkt}, nil
}

func (c *ControlAssertion) GetControlType() string { return ControlTypeAssertion }

func (c *ControlAssertion) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ControlTypeAssertion, "Control Type"))
	if c == nil {
		return packet
	}
	if c.Criticality {
		packet.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, true, "Criticality"))
	}
	value := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value")
	if c.packet != nil {
		value.AppendChild(c.packet)
	}
	packet.AppendChild(value)
	return packet
}

func (c *ControlAssertion) String() string {
	if c == nil {
		return "Assertion Control"
	}
	return "Assertion Control filter=" + c.Filter
}
