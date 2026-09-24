// Package eap implements the Extensible Authentication Protocol packet format
// (RFC 3748) together with the EAP-AKA method (RFC 4187) used across the SWu
// reference point between the UE and the ePDG.
package eap

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Code is the EAP Code field (RFC 3748 section 4).
type Code uint8

const (
	CodeRequest  Code = 1
	CodeResponse Code = 2
	CodeSuccess  Code = 3
	CodeFailure  Code = 4
)

func (c Code) String() string {
	switch c {
	case CodeRequest:
		return "Request"
	case CodeResponse:
		return "Response"
	case CodeSuccess:
		return "Success"
	case CodeFailure:
		return "Failure"
	default:
		return fmt.Sprintf("Code(%d)", uint8(c))
	}
}

// EAP method types (IANA EAP Method Types, RFC 3748 section 5).
const (
	TypeIdentity     uint8 = 1
	TypeNotification uint8 = 2
	TypeNak          uint8 = 3
	TypeMD5Challenge uint8 = 4
	TypeAKA          uint8 = 23
	TypeAKAPrime     uint8 = 50
)

// headerLen is the size of the fixed EAP header.
const headerLen = 4

// Packet is a decoded EAP packet.
type Packet struct {
	Code       Code
	Identifier uint8
	// Type is only meaningful for Request and Response packets.
	Type uint8
	// Data is the method-specific payload that follows the Type octet.
	Data []byte
}

// Parse decodes and validates an EAP packet. The Length field must match the
// number of octets received (RFC 3748 section 4).
func Parse(raw []byte) (*Packet, error) {
	if len(raw) < headerLen {
		return nil, fmt.Errorf("eap: packet too short: %d octets", len(raw))
	}
	length := int(binary.BigEndian.Uint16(raw[2:4]))
	if length != len(raw) {
		return nil, fmt.Errorf("eap: Length field is %d but %d octets were received", length, len(raw))
	}
	p := &Packet{Code: Code(raw[0]), Identifier: raw[1]}
	switch p.Code {
	case CodeRequest, CodeResponse:
		if length < headerLen+1 {
			return nil, errors.New("eap: Request/Response without Type octet")
		}
		p.Type = raw[4]
		p.Data = append([]byte{}, raw[5:]...)
	default:
		if length != headerLen {
			return nil, fmt.Errorf("eap: %s must be %d octets, got %d", p.Code, headerLen, length)
		}
	}
	return p, nil
}

// Marshal encodes the packet, filling in the Length field.
func (p *Packet) Marshal() []byte {
	if p.Code == CodeRequest || p.Code == CodeResponse {
		raw := make([]byte, headerLen+1+len(p.Data))
		raw[0] = byte(p.Code)
		raw[1] = p.Identifier
		binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
		raw[4] = p.Type
		copy(raw[5:], p.Data)
		return raw
	}
	raw := make([]byte, headerLen)
	raw[0] = byte(p.Code)
	raw[1] = p.Identifier
	binary.BigEndian.PutUint16(raw[2:4], uint16(headerLen))
	return raw
}

// Identity returns the peer identity carried by an EAP-Response/Identity
// packet, or by the AT_IDENTITY attribute of an EAP-Response/AKA-Identity
// packet. It returns an empty string for any other packet.
func (p *Packet) Identity() string {
	switch p.Type {
	case TypeIdentity:
		return string(p.Data)
	case TypeAKA:
		if len(p.Data) < 3 || p.Data[0] != SubtypeIdentity {
			return ""
		}
		attrs, err := ParseAttributes(p.Data[3:])
		if err != nil {
			return ""
		}
		for _, a := range attrs {
			if a.Type == ATIdentity && len(a.Value) >= 2 {
				n := int(binary.BigEndian.Uint16(a.Value[0:2]))
				if n > len(a.Value)-2 {
					n = len(a.Value) - 2
				}
				return string(a.Value[2 : 2+n])
			}
		}
	}
	return ""
}

// Success builds an EAP-Success packet.
func Success(identifier uint8) []byte {
	return (&Packet{Code: CodeSuccess, Identifier: identifier}).Marshal()
}

// Failure builds an EAP-Failure packet.
func Failure(identifier uint8) []byte {
	return (&Packet{Code: CodeFailure, Identifier: identifier}).Marshal()
}

// IdentityRequest builds an EAP-Request/Identity packet.
func IdentityRequest(identifier uint8) []byte {
	return (&Packet{Code: CodeRequest, Identifier: identifier, Type: TypeIdentity}).Marshal()
}
