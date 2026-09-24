package eap

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
)

// EAP-AKA message subtypes (RFC 4187 section 11).
const (
	SubtypeChallenge              uint8 = 1
	SubtypeAuthenticationReject   uint8 = 2
	SubtypeSynchronizationFailure uint8 = 4
	SubtypeIdentity               uint8 = 5
	SubtypeNotification           uint8 = 12
	SubtypeReauthentication       uint8 = 13
	SubtypeClientError            uint8 = 14
)

// AT_* attribute types (RFC 4187 section 11).
const (
	ATRand            uint8 = 1
	ATAUTN            uint8 = 2
	ATRES             uint8 = 3
	ATAUTS            uint8 = 4
	ATPadding         uint8 = 6
	ATNonceMT         uint8 = 7
	ATPermanentIDReq  uint8 = 10
	ATMAC             uint8 = 11
	ATNotification    uint8 = 12
	ATAnyIDReq        uint8 = 13
	ATIdentity        uint8 = 14
	ATVersionList     uint8 = 15
	ATSelectedVersion uint8 = 16
	ATFullauthIDReq   uint8 = 17
	ATCounter         uint8 = 19
	ATCounterTooSmall uint8 = 20
	ATNonceS          uint8 = 21
	ATClientErrorCode uint8 = 22
)

// AT_NOTIFICATION codes (RFC 4187 section 10.19).
const (
	NotificationSuccess                  uint16 = 32768
	NotificationGeneralFailureAfterAuth  uint16 = 0
	NotificationGeneralFailureBeforeAuth uint16 = 16384
)

// akaHeaderLen is the size of the EAP-AKA Subtype + Reserved fields that
// precede the attribute list.
const akaHeaderLen = 3

// Attribute is a decoded AT_* attribute. Value excludes the Type and Length
// octets, so it still contains any reserved octets the attribute defines.
type Attribute struct {
	Type  uint8
	Value []byte
}

// Marshal encodes a single attribute. The value is zero padded so that the
// encoded length is a multiple of four octets as required by RFC 4187
// section 8.1.
func (a Attribute) Marshal() []byte {
	total := len(a.Value) + 2
	pad := (4 - total%4) % 4
	out := make([]byte, 2+len(a.Value)+pad)
	out[0] = a.Type
	out[1] = byte((2 + len(a.Value) + pad) / 4)
	copy(out[2:], a.Value)
	return out
}

// ParseAttributes decodes a sequence of AT_* attributes.
func ParseAttributes(raw []byte) ([]Attribute, error) {
	var attrs []Attribute
	for pos := 0; pos+2 <= len(raw); {
		typ := raw[pos]
		length := int(raw[pos+1]) * 4
		if length < 4 || pos+length > len(raw) {
			return nil, fmt.Errorf("eap-aka: malformed AT_%d at offset %d (encoded length %d)", typ, pos, length)
		}
		attrs = append(attrs, Attribute{Type: typ, Value: append([]byte{}, raw[pos+2:pos+length]...)})
		pos += length
	}
	return attrs, nil
}

// locateMAC returns the offset of the 16-octet MAC value inside the AT_MAC
// attribute of a marshalled EAP-AKA packet. The attribute list starts after
// the 4 octet EAP header, the Type octet and the 3 octet Subtype/Reserved
// header.
func locateMAC(raw []byte) (int, error) {
	pos := headerLen + 1 + akaHeaderLen
	for pos+2 <= len(raw) {
		typ := raw[pos]
		length := int(raw[pos+1]) * 4
		if length < 4 || pos+length > len(raw) {
			return 0, fmt.Errorf("eap-aka: malformed attribute at offset %d while locating AT_MAC", pos)
		}
		if typ == ATMAC {
			if length < 2+2+16 {
				return 0, errors.New("eap-aka: AT_MAC carries less than 16 octets")
			}
			return pos + 4, nil
		}
		pos += length
	}
	return 0, errors.New("eap-aka: AT_MAC attribute not present")
}

// hmacSHA1Trunc computes HMAC-SHA1-128, the MAC used by AT_MAC
// (RFC 4187 section 10.15).
func hmacSHA1Trunc(key, data []byte) []byte {
	mac := hmac.New(sha1.New, key)
	mac.Write(data)
	return mac.Sum(nil)[:16]
}

// BuildChallenge assembles an EAP-Request/AKA-Challenge (RFC 4187
// section 4.1.1) carrying AT_RAND, AT_AUTN and a freshly computed AT_MAC.
func BuildChallenge(identifier uint8, rand, autn, kAut []byte) ([]byte, error) {
	return BuildChallengeWithCheckcode(identifier, rand, autn, kAut, nil)
}

// BuildChallengeWithCheckcode behaves like BuildChallenge but additionally
// includes an AT_CHECKCODE attribute when checkcode is not nil. AT_CHECKCODE
// (RFC 4187 section 10.13) is used when EAP-AKA runs over a protocol such as
// IKEv2 that carries its own integrity protection.
func BuildChallengeWithCheckcode(identifier uint8, rand, autn, kAut, checkcode []byte) ([]byte, error) {
	if len(rand) != 16 || len(autn) != 16 {
		return nil, fmt.Errorf("eap-aka: RAND and AUTN must each be 16 octets (rand=%d autn=%d)", len(rand), len(autn))
	}
	if len(kAut) != 16 {
		return nil, fmt.Errorf("eap-aka: K_aut must be 16 octets, got %d", len(kAut))
	}

	body := []byte{SubtypeChallenge, 0, 0}
	body = append(body, Attribute{Type: ATRand, Value: append([]byte{0, 0}, rand...)}.Marshal()...)
	body = append(body, Attribute{Type: ATAUTN, Value: append([]byte{0, 0}, autn...)}.Marshal()...)
	if checkcode != nil {
		body = append(body, Attribute{Type: ATCheckcode, Value: append([]byte{0, 0}, checkcode...)}.Marshal()...)
	}
	body = append(body, Attribute{Type: ATMAC, Value: make([]byte, 18)}.Marshal()...)

	pkt := &Packet{Code: CodeRequest, Identifier: identifier, Type: TypeAKA, Data: body}
	raw := pkt.Marshal()

	off, err := locateMAC(raw)
	if err != nil {
		return nil, err
	}
	copy(raw[off:off+16], hmacSHA1Trunc(kAut, raw))
	return raw, nil
}

// AT_CHECKCODE is defined in RFC 4187 section 10.13.
const ATCheckcode uint8 = 134

// Response is a decoded EAP-Response carrying an EAP-AKA payload.
type Response struct {
	Subtype         uint8
	RES             []byte
	AUTS            []byte
	MAC             []byte
	Notification    *uint16
	ClientErrorCode *uint16
	Identity        string
}

// ParseResponse decodes an EAP-Response of method type AKA (or AKA').
func ParseResponse(raw []byte) (*Response, error) {
	pkt, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	if pkt.Code != CodeResponse {
		return nil, fmt.Errorf("eap-aka: expected a Response packet, got %s", pkt.Code)
	}
	if pkt.Type != TypeAKA && pkt.Type != TypeAKAPrime {
		return nil, fmt.Errorf("eap-aka: expected method type AKA(%d) or AKA'(%d), got %d", TypeAKA, TypeAKAPrime, pkt.Type)
	}
	if len(pkt.Data) < akaHeaderLen {
		return nil, errors.New("eap-aka: truncated Subtype/Reserved header")
	}
	resp := &Response{Subtype: pkt.Data[0]}
	attrs, err := ParseAttributes(pkt.Data[akaHeaderLen:])
	if err != nil {
		return nil, err
	}
	for _, a := range attrs {
		switch a.Type {
		case ATRES:
			if len(a.Value) < 2 {
				return nil, errors.New("eap-aka: AT_RES too short")
			}
			bits := int(binary.BigEndian.Uint16(a.Value[0:2]))
			n := (bits + 7) / 8
			if n <= 0 || n > len(a.Value)-2 {
				return nil, fmt.Errorf("eap-aka: AT_RES declares %d bits but carries %d octets", bits, len(a.Value)-2)
			}
			resp.RES = append([]byte{}, a.Value[2:2+n]...)
		case ATMAC:
			if len(a.Value) < 18 {
				return nil, errors.New("eap-aka: AT_MAC too short")
			}
			resp.MAC = append([]byte{}, a.Value[2:18]...)
		case ATAUTS:
			if len(a.Value) < 16 {
				return nil, errors.New("eap-aka: AT_AUTS too short")
			}
			resp.AUTS = append([]byte{}, a.Value[2:16]...)
		case ATNotification:
			if len(a.Value) < 2 {
				return nil, errors.New("eap-aka: AT_NOTIFICATION too short")
			}
			v := binary.BigEndian.Uint16(a.Value[0:2])
			resp.Notification = &v
		case ATClientErrorCode:
			if len(a.Value) < 2 {
				return nil, errors.New("eap-aka: AT_CLIENT_ERROR_CODE too short")
			}
			v := binary.BigEndian.Uint16(a.Value[0:2])
			resp.ClientErrorCode = &v
		case ATIdentity:
			if len(a.Value) >= 2 {
				n := int(binary.BigEndian.Uint16(a.Value[0:2]))
				if n > len(a.Value)-2 {
					n = len(a.Value) - 2
				}
				resp.Identity = string(a.Value[2 : 2+n])
			}
		}
	}
	return resp, nil
}

// SignMAC fills in the AT_MAC value of a marshalled EAP-AKA packet: HMAC-SHA1
// truncated to 128 bits, computed over the packet with the AT_MAC value zeroed
// (RFC 4187 section 10.15). A peer implementation uses this to sign its
// responses; the same computation is used by VerifyMAC on the server side.
func SignMAC(raw, kAut []byte) error {
	off, err := locateMAC(raw)
	if err != nil {
		return err
	}
	copy(raw[off:off+16], make([]byte, 16))
	copy(raw[off:off+16], hmacSHA1Trunc(kAut, raw))
	return nil
}

// VerifyMAC recomputes the AT_MAC integrity check of a marshalled EAP-AKA
// packet and reports whether it matches the value carried in the packet. The
// received MAC is always returned so callers can log it.
func VerifyMAC(raw, kAut []byte) (received, expected []byte, ok bool, err error) {
	zeroed := append([]byte{}, raw...)
	off, err := locateMAC(zeroed)
	if err != nil {
		return nil, nil, false, err
	}
	received = append([]byte{}, zeroed[off:off+16]...)
	copy(zeroed[off:off+16], make([]byte, 16))
	expected = hmacSHA1Trunc(kAut, zeroed)
	return received, expected, hmac.Equal(received, expected), nil
}

// Keys holds the EAP-AKA key hierarchy defined in RFC 4187 section 7.
type Keys struct {
	KEncr []byte
	KAut  []byte
	MSK   []byte
	EMSK  []byte
}

// DeriveKeys computes the EAP-AKA key hierarchy from the AKA IK/CK pair:
//
//	MK = SHA1(Identity | IK | CK)
//	K_encr | K_aut | MSK | EMSK = PRF(MK, 1280)
func DeriveKeys(identity string, ik, ck []byte) (*Keys, error) {
	if len(ik) != 16 || len(ck) != 16 {
		return nil, fmt.Errorf("eap-aka: IK and CK must be 16 octets each (ik=%d ck=%d)", len(ik), len(ck))
	}
	mk := deriveMK(identity, ik, ck)
	// 1280 bits of PRF output: 4 iterations of the 320-bit x_j.
	prf := fips186PRF(mk, 4)
	return &Keys{
		KEncr: prf[0:16],
		KAut:  prf[16:32],
		MSK:   prf[32:96],
		EMSK:  prf[96:160],
	}, nil
}
