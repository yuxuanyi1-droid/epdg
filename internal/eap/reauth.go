package eap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
)

// Additional AT_* attribute types (RFC 4187 sections 10.10-10.12). AT_COUNTER
// (19) and AT_NONCE_S (21) already live in aka.go.
const (
	ATIV            uint8 = 129
	ATEncrData      uint8 = 130
	ATNextPseudonym uint8 = 132
	ATNextReauthID  uint8 = 133
)

// BuildIdentityRequest assembles an EAP-Request/AKA-Identity (RFC 4187
// section 9.1) carrying exactly one of the three mutually exclusive identity
// requesting attributes. The message must not include AT_MAC, AT_IV or
// AT_ENCR_DATA because no keying material exists yet.
func BuildIdentityRequest(identifier uint8, reqAttr uint8) ([]byte, error) {
	switch reqAttr {
	case ATPermanentIDReq, ATAnyIDReq, ATFullauthIDReq:
	default:
		return nil, fmt.Errorf("eap-aka: %d is not an identity requesting attribute", reqAttr)
	}
	body := []byte{SubtypeIdentity, 0, 0}
	body = append(body, Attribute{Type: reqAttr, Value: make([]byte, 2)}.Marshal()...)
	pkt := &Packet{Code: CodeRequest, Identifier: identifier, Type: TypeAKA, Data: body}
	return pkt.Marshal(), nil
}

// ParseIdentityRequest decodes an EAP-Request/AKA-Identity and returns the
// identity requesting attribute it carries, or an error when the message
// carries none or more than one of them (they are mutually exclusive).
func ParseIdentityRequest(raw []byte) (uint8, error) {
	resp, err := parseAKAMessage(raw, SubtypeIdentity)
	if err != nil {
		return 0, err
	}
	found := uint8(0)
	for _, a := range resp.attrs {
		switch a.Type {
		case ATPermanentIDReq, ATAnyIDReq, ATFullauthIDReq:
			if found != 0 {
				return 0, errors.New("eap-aka: more than one identity requesting attribute")
			}
			found = a.Type
		case ATMAC, ATIV, ATEncrData:
			return 0, errors.New("eap-aka: EAP-Request/AKA-Identity must not carry AT_MAC, AT_IV or AT_ENCR_DATA")
		}
	}
	if found == 0 {
		return 0, errors.New("eap-aka: EAP-Request/AKA-Identity without an identity requesting attribute")
	}
	return found, nil
}

// ParseIdentityResponse decodes an EAP-Response/AKA-Identity (RFC 4187
// section 9.2) and returns the identity carried in AT_IDENTITY. The message
// must not carry AT_MAC, AT_IV or AT_ENCR_DATA.
func ParseIdentityResponse(raw []byte) (string, error) {
	resp, err := parseAKAMessage(raw, SubtypeIdentity)
	if err != nil {
		return "", err
	}
	for _, a := range resp.attrs {
		switch a.Type {
		case ATMAC, ATIV, ATEncrData:
			return "", errors.New("eap-aka: EAP-Response/AKA-Identity must not carry AT_MAC, AT_IV or AT_ENCR_DATA")
		case ATIdentity:
			// AT_IDENTITY carries a 2-byte actual identity length followed by
			// the identity (RFC 4187 section 10.5).
			if len(a.Value) < 2 {
				return "", errors.New("eap-aka: AT_IDENTITY too short")
			}
			n := int(binary.BigEndian.Uint16(a.Value[0:2]))
			if n > len(a.Value)-2 {
				n = len(a.Value) - 2
			}
			return string(a.Value[2 : 2+n]), nil
		}
	}
	return "", errors.New("eap-aka: EAP-Response/AKA-Identity without AT_IDENTITY")
}

// encryptedAttributes serialises the nested attribute list carried inside
// AT_ENCR_DATA.
type encryptedAttributes struct {
	attrs []Attribute
}

func (e *encryptedAttributes) add(a Attribute) { e.attrs = append(e.attrs, a) }

// plain pads the nested attributes with AT_PADDING (RFC 4187 section 10.12) so
// the total length becomes a multiple of 16 bytes. Every attribute is a
// multiple of four octets, so the remainder is 0, 4, 8 or 12 and the missing
// 16 - rem octets always fit a single AT_PADDING of 4, 8 or 12 bytes.
func (e *encryptedAttributes) plain() ([]byte, error) {
	raw := make([]byte, 0, 32)
	for _, a := range e.attrs {
		raw = append(raw, a.Marshal()...)
	}
	rem := len(raw) % 16
	if rem == 0 {
		return raw, nil
	}
	if rem%4 != 0 {
		return nil, fmt.Errorf("eap-aka: nested attributes leave a %d byte remainder, which AT_PADDING cannot fill", rem)
	}
	pad := 16 - rem
	return append(raw, Attribute{Type: ATPadding, Value: make([]byte, pad-2)}.Marshal()...), nil
}

// encrypt applies AES-128-CBC with the given K_encr and IV, as required by RFC
// 4187 section 10.12.
func (e *encryptedAttributes) encrypt(kEncr, iv []byte) (ciphertext []byte, err error) {
	plain, err := e.plain()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(kEncr)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plain)
	return out, nil
}

// decryptEncrData reverses encrypt: it decrypts the AT_ENCR_DATA value (which
// begins with two reserved octets) with AES-128-CBC and re-parses the nested
// attributes. Non-zero AT_PADDING bytes are rejected as required by RFC 4187
// section 10.12.
func decryptEncrData(kEncr, iv, value []byte) ([]Attribute, error) {
	if len(value) < 2 {
		return nil, errors.New("eap-aka: AT_ENCR_DATA too short")
	}
	ct := value[2:]
	if len(ct) == 0 || len(ct)%16 != 0 {
		return nil, errors.New("eap-aka: AT_ENCR_DATA ciphertext is not a multiple of 16 octets")
	}
	block, err := aes.NewCipher(kEncr)
	if err != nil {
		return nil, err
	}
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ct)
	attrs, err := ParseAttributes(plain)
	if err != nil {
		return nil, err
	}
	for _, a := range attrs {
		if a.Type != ATPadding {
			continue
		}
		for _, b := range a.Value {
			if b != 0 {
				return nil, errors.New("eap-aka: non-zero AT_PADDING byte")
			}
		}
	}
	return attrs, nil
}

// randomIV returns a fresh AT_IV value: two reserved octets followed by a
// random 16-byte initialisation vector (RFC 4187 section 10.12).
func randomIV() ([]byte, []byte, error) {
	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		return nil, nil, fmt.Errorf("eap-aka: cannot read an initialisation vector: %w", err)
	}
	return append([]byte{0, 0}, iv...), iv, nil
}

// ReauthRequest is a built EAP-Request/AKA-Reauthentication together with the
// values the server has to remember until the response arrives: the NONCE_S it
// chose (the response MAC covers it) and the counter it sent.
type ReauthRequest struct {
	// Raw is the marshalled EAP-Request/AKA-Reauthentication.
	Raw []byte
	// NonceS is the 16-byte random nonce the request carries inside
	// AT_ENCR_DATA. The AT_MAC of the peer's response is computed over the
	// response packet followed by this value (RFC 4187 section 9.8).
	NonceS []byte
	// Counter is the counter value the request carries inside AT_ENCR_DATA.
	Counter uint16
}

// BuildReauthenticationRequest assembles an EAP-Request/AKA-Reauthentication
// (RFC 4187 section 9.7): AT_IV and AT_ENCR_DATA carrying the encrypted
// AT_COUNTER, AT_NONCE_S and optionally AT_NEXT_REAUTH_ID, plus an AT_MAC with
// no message-specific data. The counter is the server's fresh counter value
// and nextReauthID, when not empty, is issued to the peer for the next fast
// re-authentication.
func BuildReauthenticationRequest(identifier uint8, keys *Keys, counter uint16, nextReauthID string) (*ReauthRequest, error) {
	if len(keys.KEncr) != 16 || len(keys.KAut) != 16 {
		return nil, errors.New("eap-aka: K_encr and K_aut must be 16 octets each")
	}
	if counter == 0 {
		return nil, errors.New("eap-aka: the re-authentication counter starts at one")
	}

	enc := &encryptedAttributes{}
	enc.add(Attribute{Type: ATCounter, Value: []byte{byte(counter >> 8), byte(counter)}})
	nonceS := make([]byte, 16)
	if _, err := rand.Read(nonceS); err != nil {
		return nil, fmt.Errorf("eap-aka: cannot read NONCE_S: %w", err)
	}
	enc.add(Attribute{Type: ATNonceS, Value: append([]byte{0, 0}, nonceS...)})
	if nextReauthID != "" {
		// AT_NEXT_REAUTH_ID carries a 2-byte actual length followed by the
		// identity, always encrypted (RFC 4187 section 10.11).
		id := []byte(nextReauthID)
		value := append([]byte{byte(len(id) >> 8), byte(len(id))}, id...)
		enc.add(Attribute{Type: ATNextReauthID, Value: value})
	}

	ivValue, iv, err := randomIV()
	if err != nil {
		return nil, err
	}
	ciphertext, err := enc.encrypt(keys.KEncr, iv)
	if err != nil {
		return nil, err
	}

	body := []byte{SubtypeReauthentication, 0, 0}
	body = append(body, Attribute{Type: ATIV, Value: ivValue}.Marshal()...)
	body = append(body, Attribute{Type: ATEncrData, Value: append([]byte{0, 0}, ciphertext...)}.Marshal()...)
	body = append(body, Attribute{Type: ATMAC, Value: make([]byte, 18)}.Marshal()...)

	pkt := &Packet{Code: CodeRequest, Identifier: identifier, Type: TypeAKA, Data: body}
	raw := pkt.Marshal()
	off, err := locateMAC(raw)
	if err != nil {
		return nil, err
	}
	copy(raw[off:off+16], hmacSHA1Trunc(keys.KAut, raw))
	return &ReauthRequest{Raw: raw, NonceS: nonceS, Counter: counter}, nil
}

// ReauthChallenge is a decoded EAP-Request/AKA-Reauthentication.
type ReauthChallenge struct {
	Counter      uint16
	NonceS       []byte
	NextReauthID string
}

// ParseReauthenticationRequest decodes an EAP-Request/AKA-Reauthentication:
// it verifies AT_MAC, decrypts AT_ENCR_DATA with K_encr and extracts the
// mandatory AT_COUNTER and AT_NONCE_S plus the optional AT_NEXT_REAUTH_ID.
func ParseReauthenticationRequest(raw []byte, keys *Keys) (*ReauthChallenge, error) {
	resp, err := parseAKAMessage(raw, SubtypeReauthentication)
	if err != nil {
		return nil, err
	}
	if len(keys.KEncr) != 16 || len(keys.KAut) != 16 {
		return nil, errors.New("eap-aka: K_encr and K_aut must be 16 octets each")
	}
	if _, _, ok, err := VerifyMAC(raw, keys.KAut); err != nil {
		return nil, err
	} else if !ok {
		return nil, errors.New("eap-aka: AT_MAC of the re-authentication request does not verify")
	}

	var (
		ivValue, encrValue []byte
		counter, nonceS    bool
		out                = &ReauthChallenge{}
	)
	for _, a := range resp.attrs {
		switch a.Type {
		case ATIV:
			if len(a.Value) != 18 {
				return nil, errors.New("eap-aka: AT_IV must carry two reserved octets and a 16-byte IV")
			}
			ivValue = a.Value
		case ATEncrData:
			encrValue = a.Value
		}
	}
	if ivValue == nil || encrValue == nil {
		return nil, errors.New("eap-aka: EAP-Request/AKA-Reauthentication must carry AT_IV and AT_ENCR_DATA")
	}
	nested, err := decryptEncrData(keys.KEncr, ivValue[2:], encrValue)
	if err != nil {
		return nil, err
	}
	for _, a := range nested {
		switch a.Type {
		case ATCounter:
			if len(a.Value) < 2 {
				return nil, errors.New("eap-aka: AT_COUNTER too short")
			}
			out.Counter = binary.BigEndian.Uint16(a.Value[0:2])
			counter = true
		case ATNonceS:
			if len(a.Value) < 18 {
				return nil, errors.New("eap-aka: AT_NONCE_S too short")
			}
			out.NonceS = append([]byte{}, a.Value[2:18]...)
			nonceS = true
		case ATNextReauthID:
			if len(a.Value) < 2 {
				return nil, errors.New("eap-aka: AT_NEXT_REAUTH_ID too short")
			}
			n := int(binary.BigEndian.Uint16(a.Value[0:2]))
			if n > len(a.Value)-2 {
				n = len(a.Value) - 2
			}
			out.NextReauthID = string(a.Value[2 : 2+n])
		}
	}
	if !counter || !nonceS {
		return nil, errors.New("eap-aka: EAP-Request/AKA-Reauthentication must carry AT_COUNTER and AT_NONCE_S")
	}
	return out, nil
}

// BuildReauthenticationResponse assembles an EAP-Response/AKA-Reauthentication
// (RFC 4187 section 9.8) answering a valid request: AT_IV and AT_ENCR_DATA
// carrying the same AT_COUNTER value the server sent, plus AT_MAC computed
// over the packet followed by the 16-byte NONCE_S of the request.
func BuildReauthenticationResponse(identifier uint8, keys *Keys, counter uint16, nonceS []byte) ([]byte, error) {
	return buildReauthResponse(identifier, keys, func(enc *encryptedAttributes) {
		enc.add(Attribute{Type: ATCounter, Value: []byte{byte(counter >> 8), byte(counter)}})
	}, nonceS)
}

// BuildReauthenticationCounterTooSmallResponse assembles the answer of a peer
// that rejected the counter of an EAP-Request/AKA-Reauthentication (RFC 4187
// section 5.5): AT_ENCR_DATA carries AT_COUNTER_TOO_SMALL in addition to the
// echoed AT_COUNTER, and AT_MAC covers the packet plus the NONCE_S of the
// request. The server answers this with a full authentication.
func BuildReauthenticationCounterTooSmallResponse(identifier uint8, keys *Keys, counter uint16, nonceS []byte) ([]byte, error) {
	raw, err := buildReauthResponse(identifier, keys, func(enc *encryptedAttributes) {
		enc.add(Attribute{Type: ATCounter, Value: []byte{byte(counter >> 8), byte(counter)}})
		enc.add(Attribute{Type: ATCounterTooSmall, Value: make([]byte, 2)})
	}, nonceS)
	return raw, err
}

// buildReauthResponse is the shared body of the two response builders.
func buildReauthResponse(identifier uint8, keys *Keys, nested func(*encryptedAttributes), nonceS []byte) ([]byte, error) {
	if len(keys.KEncr) != 16 || len(keys.KAut) != 16 {
		return nil, errors.New("eap-aka: K_encr and K_aut must be 16 octets each")
	}
	if len(nonceS) != 16 {
		return nil, errors.New("eap-aka: NONCE_S must be 16 octets")
	}

	enc := &encryptedAttributes{}
	nested(enc)
	ivValue, iv, err := randomIV()
	if err != nil {
		return nil, err
	}
	ciphertext, err := enc.encrypt(keys.KEncr, iv)
	if err != nil {
		return nil, err
	}

	body := []byte{SubtypeReauthentication, 0, 0}
	body = append(body, Attribute{Type: ATIV, Value: ivValue}.Marshal()...)
	body = append(body, Attribute{Type: ATEncrData, Value: append([]byte{0, 0}, ciphertext...)}.Marshal()...)
	body = append(body, Attribute{Type: ATMAC, Value: make([]byte, 18)}.Marshal()...)

	pkt := &Packet{Code: CodeResponse, Identifier: identifier, Type: TypeAKA, Data: body}
	raw := pkt.Marshal()
	off, err := locateMAC(raw)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha1.New, keys.KAut)
	mac.Write(raw)
	mac.Write(nonceS)
	copy(raw[off:off+16], mac.Sum(nil)[:16])
	return raw, nil
}

// VerifyReauthenticationResponse verifies the AT_MAC of an
// EAP-Response/AKA-Reauthentication, whose MAC covers the packet followed by
// the NONCE_S of the request (RFC 4187 section 9.8), decrypts the nested
// attributes and reports the counter value the peer echoed.
func VerifyReauthenticationResponse(raw []byte, keys *Keys, nonceS []byte) (counter uint16, counterTooSmall bool, err error) {
	resp, err := parseAKAMessage(raw, SubtypeReauthentication)
	if err != nil {
		return 0, false, err
	}
	if len(keys.KEncr) != 16 || len(keys.KAut) != 16 {
		return 0, false, errors.New("eap-aka: K_encr and K_aut must be 16 octets each")
	}
	// The MAC covers the packet with the AT_MAC value zeroed plus NONCE_S.
	zeroed := append([]byte{}, raw...)
	off, err := locateMAC(zeroed)
	if err != nil {
		return 0, false, err
	}
	received := append([]byte{}, zeroed[off:off+16]...)
	copy(zeroed[off:off+16], make([]byte, 16))
	mac := hmac.New(sha1.New, keys.KAut)
	mac.Write(zeroed)
	mac.Write(nonceS)
	if !hmac.Equal(received, mac.Sum(nil)[:16]) {
		return 0, false, errors.New("eap-aka: AT_MAC of the re-authentication response does not verify")
	}

	var (
		ivValue, encrValue []byte
		hasCounter         bool
	)
	for _, a := range resp.attrs {
		switch a.Type {
		case ATIV:
			if len(a.Value) != 18 {
				return 0, false, errors.New("eap-aka: AT_IV must carry two reserved octets and a 16-byte IV")
			}
			ivValue = a.Value
		case ATEncrData:
			encrValue = a.Value
		}
	}
	if ivValue == nil || encrValue == nil {
		return 0, false, errors.New("eap-aka: EAP-Response/AKA-Reauthentication must carry AT_IV and AT_ENCR_DATA")
	}
	nested, err := decryptEncrData(keys.KEncr, ivValue[2:], encrValue)
	if err != nil {
		return 0, false, err
	}
	for _, a := range nested {
		switch a.Type {
		case ATCounter:
			if len(a.Value) < 2 {
				return 0, false, errors.New("eap-aka: AT_COUNTER too short")
			}
			counter = binary.BigEndian.Uint16(a.Value[0:2])
			hasCounter = true
		case ATCounterTooSmall:
			counterTooSmall = true
		}
	}
	if !hasCounter {
		return 0, false, errors.New("eap-aka: EAP-Response/AKA-Reauthentication must carry AT_COUNTER")
	}
	return counter, counterTooSmall, nil
}

// DeriveReauthKeys computes the fast re-authentication key material (RFC 4187
// section 7): XKEY' = SHA1(Identity|counter|NONCE_S|MK) seeds the FIPS 186-2
// PRF, whose first 1280 bits are the new MSK and EMSK. K_encr and K_aut are
// not re-derived; the caller keeps using the keys of the preceding full
// authentication.
func DeriveReauthKeys(identity string, counter uint16, nonceS, mk []byte) (*Keys, error) {
	if len(nonceS) != 16 {
		return nil, errors.New("eap-aka: NONCE_S must be 16 octets")
	}
	if len(mk) != 20 {
		return nil, errors.New("eap-aka: MK must be 20 octets")
	}
	h := sha1.New()
	h.Write([]byte(identity))
	var counterBytes [2]byte
	binary.BigEndian.PutUint16(counterBytes[:], counter)
	h.Write(counterBytes[:])
	h.Write(nonceS)
	h.Write(mk)

	var xkey [20]byte
	copy(xkey[:], h.Sum(nil))
	stream := fips186PRF(xkey, 4)
	return &Keys{
		KEncr: nil,
		KAut:  nil,
		// On fast re-authentication the key stream starts at x_0, so MSK and
		// EMSK are the first 1280 bits instead of bits 256..1279.
		MSK:  stream[0:64],
		EMSK: stream[64:128],
	}, nil
}

// DeriveKeysWithMK behaves like DeriveKeys but also returns the MK so the
// caller can store it for later fast re-authentications.
func DeriveKeysWithMK(identity string, ik, ck []byte) (*Keys, []byte, error) {
	if len(ik) != 16 || len(ck) != 16 {
		return nil, nil, fmt.Errorf("eap-aka: IK and CK must be 16 octets each (ik=%d ck=%d)", len(ik), len(ck))
	}
	mk := deriveMK(identity, ik, ck)
	// 1280 bits of PRF output: 4 iterations of the 320-bit x_j.
	prf := fips186PRF(mk, 4)
	keys := &Keys{
		KEncr: prf[0:16],
		KAut:  prf[16:32],
		MSK:   prf[32:96],
		EMSK:  prf[96:160],
	}
	mkBytes := make([]byte, 20)
	copy(mkBytes, mk[:])
	return keys, mkBytes, nil
}

// akaMessage is the common decoded shape used by the message specific parsers
// above.
type akaMessage struct {
	attrs []Attribute
}

func parseAKAMessage(raw []byte, wantSubtype uint8) (*akaMessage, error) {
	pkt, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	if pkt.Code != CodeRequest && pkt.Code != CodeResponse {
		return nil, fmt.Errorf("eap-aka: unexpected code %s", pkt.Code)
	}
	if pkt.Type != TypeAKA && pkt.Type != TypeAKAPrime {
		return nil, fmt.Errorf("eap-aka: expected method type AKA(%d) or AKA'(%d), got %d", TypeAKA, TypeAKAPrime, pkt.Type)
	}
	if len(pkt.Data) < akaHeaderLen {
		return nil, errors.New("eap-aka: truncated Subtype/Reserved header")
	}
	if pkt.Data[0] != wantSubtype {
		return nil, fmt.Errorf("eap-aka: subtype %d, want %d", pkt.Data[0], wantSubtype)
	}
	attrs, err := ParseAttributes(pkt.Data[akaHeaderLen:])
	if err != nil {
		return nil, err
	}
	return &akaMessage{attrs: attrs}, nil
}
