// Package radius implements the subset of the RADIUS protocol needed by the
// ePDG to act as the EAP server behind strongSwan's eap-radius plugin:
// RADIUS packet encoding (RFC 2865/RFC 2866), the EAP-Message and
// Message-Authenticator attributes (RFC 3579) and the Microsoft vendor
// specific MS-MPPE key attributes (RFC 2548).
package radius

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Packet codes.
const (
	CodeAccessRequest      uint8 = 1
	CodeAccessAccept       uint8 = 2
	CodeAccessReject       uint8 = 3
	CodeAccountingRequest  uint8 = 4
	CodeAccountingResponse uint8 = 5
	CodeAccessChallenge    uint8 = 11
)

func CodeString(code uint8) string {
	switch code {
	case CodeAccessRequest:
		return "Access-Request"
	case CodeAccessAccept:
		return "Access-Accept"
	case CodeAccessReject:
		return "Access-Reject"
	case CodeAccountingRequest:
		return "Accounting-Request"
	case CodeAccountingResponse:
		return "Accounting-Response"
	case CodeAccessChallenge:
		return "Access-Challenge"
	default:
		return fmt.Sprintf("Code(%d)", code)
	}
}

// Attribute types used by the ePDG.
const (
	AttrUserName               uint8 = 1
	AttrUserPassword           uint8 = 2
	AttrNASIPAddress           uint8 = 4
	AttrNASPort                uint8 = 5
	AttrServiceType            uint8 = 6
	AttrFramedMTU              uint8 = 12
	AttrReplyMessage           uint8 = 18
	AttrState                  uint8 = 24
	AttrClass                  uint8 = 25
	AttrVendorSpecific         uint8 = 26
	AttrCalledStationID        uint8 = 30
	AttrCallingStationID       uint8 = 31
	AttrNASIdentifier          uint8 = 32
	AttrProxyState             uint8 = 33
	AttrAcctSessionID          uint8 = 44
	AttrNASPortType            uint8 = 61
	AttrEAPMessage             uint8 = 79
	AttrMessageAuthenticator   uint8 = 80
	AttrNASPortID              uint8 = 87
	AttrChargeableUserIdentity uint8 = 89
)

// Vendor specific attributes (RFC 2548).
const (
	VendorMicrosoft uint32 = 311
	MSMPPESendKey   uint8  = 16
	MSMPPERecvKey   uint8  = 17
	eapMessageChunk        = 253
)

// Attribute is a single RADIUS attribute.
type Attribute struct {
	Type  uint8
	Value []byte
}

// Packet is a decoded RADIUS packet.
type Packet struct {
	Code          uint8
	Identifier    uint8
	Authenticator [16]byte
	Attributes    []Attribute
}

// ErrShortPacket is returned when a datagram carries fewer than the 20 octets
// of the RADIUS header.
var ErrShortPacket = errors.New("radius: datagram shorter than the 20 octet header")

// Parse decodes a RADIUS datagram, validating the Length field and every
// attribute length (RFC 2865 section 3 and section 5).
func Parse(raw []byte) (*Packet, error) {
	if len(raw) < 20 {
		return nil, ErrShortPacket
	}
	length := int(binary.BigEndian.Uint16(raw[2:4]))
	if length < 20 {
		return nil, fmt.Errorf("radius: Length field %d is below the 20 octet minimum", length)
	}
	if length > len(raw) {
		return nil, fmt.Errorf("radius: Length field %d exceeds the %d octets received", length, len(raw))
	}
	p := &Packet{Code: raw[0], Identifier: raw[1]}
	copy(p.Authenticator[:], raw[4:20])
	attrs, err := parseAttributes(raw[20:length])
	if err != nil {
		return nil, err
	}
	p.Attributes = attrs
	return p, nil
}

func parseAttributes(raw []byte) ([]Attribute, error) {
	var attrs []Attribute
	for pos := 0; pos < len(raw); {
		if pos+2 > len(raw) {
			return nil, fmt.Errorf("radius: truncated attribute header at offset %d", pos)
		}
		typ := raw[pos]
		length := int(raw[pos+1])
		if length < 2 {
			return nil, fmt.Errorf("radius: attribute %d at offset %d has invalid length %d", typ, pos, length)
		}
		if pos+length > len(raw) {
			return nil, fmt.Errorf("radius: attribute %d at offset %d overruns the packet", typ, pos)
		}
		attrs = append(attrs, Attribute{Type: typ, Value: append([]byte{}, raw[pos+2:pos+length]...)})
		pos += length
	}
	return attrs, nil
}

// Marshal encodes the packet, filling in the Length field. The Authenticator
// field must already hold either the Request Authenticator derived value or
// the Response Authenticator.
func (p *Packet) Marshal() ([]byte, error) {
	attrs, err := marshalAttributes(p.Attributes)
	if err != nil {
		return nil, err
	}
	total := 20 + len(attrs)
	if total > 4096 {
		return nil, fmt.Errorf("radius: encoded packet is %d octets which exceeds the 4096 octet limit", total)
	}
	out := make([]byte, 20, total)
	out[0] = p.Code
	out[1] = p.Identifier
	binary.BigEndian.PutUint16(out[2:4], uint16(total))
	copy(out[4:20], p.Authenticator[:])
	out = append(out, attrs...)
	return out, nil
}

func marshalAttributes(attrs []Attribute) ([]byte, error) {
	out := make([]byte, 0, 64)
	for _, a := range attrs {
		if len(a.Value) > 253 {
			return nil, fmt.Errorf("radius: attribute %d value is %d octets which exceeds the 253 octet limit", a.Type, len(a.Value))
		}
		out = append(out, a.Type, byte(len(a.Value)+2))
		out = append(out, a.Value...)
	}
	return out, nil
}

// Get returns the value of the first attribute of the given type.
func (p *Packet) Get(typ uint8) ([]byte, bool) {
	for _, a := range p.Attributes {
		if a.Type == typ {
			return a.Value, true
		}
	}
	return nil, false
}

// GetAll returns every value for the given attribute type, in order.
func (p *Packet) GetAll(typ uint8) [][]byte {
	var out [][]byte
	for _, a := range p.Attributes {
		if a.Type == typ {
			out = append(out, a.Value)
		}
	}
	return out
}

// Add appends an attribute.
func (p *Packet) Add(typ uint8, value []byte) {
	p.Attributes = append(p.Attributes, Attribute{Type: typ, Value: value})
}

// Remove drops every attribute of the given type.
func (p *Packet) Remove(typ uint8) {
	kept := p.Attributes[:0]
	for _, a := range p.Attributes {
		if a.Type != typ {
			kept = append(kept, a)
		}
	}
	p.Attributes = kept
}

// EAPMessage reassembles the EAP payload from all EAP-Message attributes,
// which a RADIUS client may split across several attributes because a single
// attribute value is limited to 253 octets (RFC 2865 section 5.13).
func (p *Packet) EAPMessage() []byte {
	var out []byte
	for _, a := range p.Attributes {
		if a.Type == AttrEAPMessage {
			out = append(out, a.Value...)
		}
	}
	return out
}

// SetEAPMessage replaces any existing EAP-Message attributes with the given
// payload, splitting it as required by RFC 2865 section 5.13.
func (p *Packet) SetEAPMessage(eap []byte) {
	p.Remove(AttrEAPMessage)
	for len(eap) > eapMessageChunk {
		p.Add(AttrEAPMessage, eap[:eapMessageChunk])
		eap = eap[eapMessageChunk:]
	}
	p.Add(AttrEAPMessage, eap)
}

// UserName returns the User-Name attribute value as a string.
func (p *Packet) UserName() string {
	v, ok := p.Get(AttrUserName)
	if !ok {
		return ""
	}
	return string(v)
}

// VendorSpecific decodes all attributes of type 26 into their
// vendor/type/value triplets.
func (p *Packet) VendorSpecific() []VSA {
	var out []VSA
	for _, a := range p.Attributes {
		if a.Type != AttrVendorSpecific || len(a.Value) < 6 {
			continue
		}
		out = append(out, VSA{
			Vendor: binary.BigEndian.Uint32(a.Value[0:4]),
			Type:   a.Value[4],
			Value:  a.Value[6:],
		})
	}
	return out
}

// VSA is a decoded vendor specific attribute.
type VSA struct {
	Vendor uint32
	Type   uint8
	Value  []byte
}

// EncodeVSA encodes a vendor specific attribute into a RADIUS attribute.
func EncodeVSA(vendor uint32, typ uint8, value []byte) Attribute {
	val := make([]byte, 4+2+len(value))
	binary.BigEndian.PutUint32(val[0:4], vendor)
	val[4] = typ
	val[5] = byte(len(value) + 2)
	copy(val[6:], value)
	return Attribute{Type: AttrVendorSpecific, Value: val}
}
