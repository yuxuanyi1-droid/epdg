package radius

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"errors"
	"fmt"
)

func hmacMD5(key, data []byte) []byte {
	mac := hmac.New(md5.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func md5sum(parts ...[]byte) [16]byte {
	h := md5.New()
	for _, p := range parts {
		h.Write(p)
	}
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

// findAttribute returns the offset of the first attribute of the given type
// within a marshalled packet, and whether it was found.
func findAttribute(raw []byte, typ uint8) (int, bool) {
	if len(raw) < 20 {
		return 0, false
	}
	length := int(raw[2])<<8 | int(raw[3])
	if length > len(raw) {
		length = len(raw)
	}
	for pos := 20; pos+2 <= length; {
		alen := int(raw[pos+1])
		if alen < 2 || pos+alen > length {
			return 0, false
		}
		if raw[pos] == typ {
			return pos, true
		}
		pos += alen
	}
	return 0, false
}

// VerifyMessageAuthenticator validates the Message-Authenticator attribute of
// a received datagram as specified in RFC 3579 section 3.2: HMAC-MD5 computed
// over the packet with the Message-Authenticator value zeroed, keyed with the
// shared secret.
func VerifyMessageAuthenticator(raw, secret []byte) (bool, error) {
	off, ok := findAttribute(raw, AttrMessageAuthenticator)
	if !ok {
		return false, errors.New("radius: Message-Authenticator attribute is missing")
	}
	if off+18 > len(raw) {
		return false, errors.New("radius: truncated Message-Authenticator attribute")
	}
	received := append([]byte{}, raw[off+2:off+18]...)
	zeroed := append([]byte{}, raw...)
	copy(zeroed[off+2:off+18], make([]byte, 16))
	return hmac.Equal(received, hmacMD5(secret, zeroed)), nil
}

// SetMessageAuthenticator computes the Message-Authenticator attribute over
// the packet as currently encoded, assuming whatever value is already present
// in the Authenticator header field. For response packets the caller must have
// placed the Request Authenticator there first, matching the convention used
// by strongSwan and FreeRADIUS.
func (p *Packet) SetMessageAuthenticator(secret []byte) error {
	p.Remove(AttrMessageAuthenticator)
	p.Add(AttrMessageAuthenticator, make([]byte, 16))
	raw, err := p.Marshal()
	if err != nil {
		return err
	}
	ma := hmacMD5(secret, raw)
	setFirstAttribute(p, AttrMessageAuthenticator, ma)
	return nil
}

// FinalizeResponse fills in both the Message-Authenticator and the Response
// Authenticator of a reply. The Message-Authenticator is computed with the
// Request Authenticator in the header position and the Response Authenticator
// is then computed over the resulting packet as described in RFC 2865
// section 5.2 and RFC 3579 section 3.2.
func (p *Packet) FinalizeResponse(secret []byte, requestAuthenticator [16]byte) error {
	p.Remove(AttrMessageAuthenticator)
	p.Add(AttrMessageAuthenticator, make([]byte, 16))
	p.Authenticator = requestAuthenticator

	raw, err := p.Marshal()
	if err != nil {
		return err
	}
	setFirstAttribute(p, AttrMessageAuthenticator, hmacMD5(secret, raw))

	p.Authenticator = requestAuthenticator
	raw, err = p.Marshal()
	if err != nil {
		return err
	}
	p.Authenticator = md5sum(raw, secret)
	return nil
}

// VerifyResponseAuthenticator recomputes the Response Authenticator of a reply
// using the Request Authenticator of the matching request.
func VerifyResponseAuthenticator(raw, secret []byte, requestAuthenticator [16]byte) bool {
	if len(raw) < 20 {
		return false
	}
	received := append([]byte{}, raw[4:20]...)
	zeroed := append([]byte{}, raw...)
	copy(zeroed[4:20], requestAuthenticator[:])
	sum := md5sum(zeroed, secret)
	return hmac.Equal(received, sum[:])
}

func setFirstAttribute(p *Packet, typ uint8, value []byte) {
	for i := range p.Attributes {
		if p.Attributes[i].Type == typ {
			p.Attributes[i].Value = value
			return
		}
	}
	p.Add(typ, value)
}

// RandomAuthenticator returns a cryptographically random 16 octet value, used
// for the Request Authenticator of Access-Request packets or for the State
// attribute (RFC 2865 sections 3 and 5.24).
func RandomAuthenticator() ([16]byte, error) {
	var out [16]byte
	if _, err := rand.Read(out[:]); err != nil {
		return out, fmt.Errorf("radius: cannot read randomness: %w", err)
	}
	return out, nil
}

// RandomSalt returns a two octet salt whose most significant bit is set, as
// required by RFC 2548 section 2.4.2.
func RandomSalt() ([2]byte, error) {
	var out [2]byte
	if _, err := rand.Read(out[:]); err != nil {
		return out, fmt.Errorf("radius: cannot read randomness: %w", err)
	}
	// Force the MSB so the salt is always >= 0x8000 and keep the remaining
	// bits random; uniqueness is enforced by the caller.
	out[0] |= 0x80
	return out, nil
}

// EncryptMPPEKey encrypts a session key for inclusion in an
// MS-MPPE-Send-Key or MS-MPPE-Recv-Key vendor specific attribute using the
// algorithm of RFC 2548 section 2.4.2. The returned value is the Salt field
// followed by the ciphertext.
func EncryptMPPEKey(key, secret []byte, requestAuthenticator [16]byte, salt [2]byte) ([]byte, error) {
	if len(key) == 0 || len(key) > 255 {
		return nil, fmt.Errorf("radius: MPPE key length %d is out of range", len(key))
	}
	plain := make([]byte, 0, len(key)+16)
	plain = append(plain, byte(len(key)))
	plain = append(plain, key...)
	for len(plain)%16 != 0 {
		plain = append(plain, 0)
	}

	cipher := make([]byte, len(plain))
	b := md5sum(secret, requestAuthenticator[:], salt[:])
	for i := 0; i < len(plain); i += 16 {
		if i > 0 {
			b = md5sum(secret, cipher[i-16:i])
		}
		for j := 0; j < 16; j++ {
			cipher[i+j] = plain[i+j] ^ b[j]
		}
	}
	return append(salt[:], cipher...), nil
}

// DecryptMPPEKey reverses EncryptMPPEKey. It is used by the test suite to
// verify that strongSwan-compatible keying material is emitted.
func DecryptMPPEKey(encrypted, secret []byte, requestAuthenticator [16]byte) ([]byte, error) {
	if len(encrypted) < 2+16 {
		return nil, errors.New("radius: encrypted MPPE key too short")
	}
	salt := encrypted[:2]
	cipher := encrypted[2:]
	if len(cipher)%16 != 0 {
		return nil, errors.New("radius: encrypted MPPE key is not a multiple of 16 octets")
	}
	plain := make([]byte, len(cipher))
	b := md5sum(secret, requestAuthenticator[:], salt)
	for i := 0; i < len(cipher); i += 16 {
		if i > 0 {
			b = md5sum(secret, cipher[i-16:i])
		}
		for j := 0; j < 16; j++ {
			plain[i+j] = cipher[i+j] ^ b[j]
		}
	}
	n := int(plain[0])
	if n == 0 || n > len(plain)-1 {
		return nil, fmt.Errorf("radius: decrypted MPPE key length %d is out of range", n)
	}
	return plain[1 : 1+n], nil
}

// MPPEKeyAttributes builds the MS-MPPE-Recv-Key and MS-MPPE-Send-Key vendor
// specific attributes carrying the master session key. As in the reference
// implementation the first 32 octets of the MSK are carried in the Recv-Key
// attribute and the second 32 octets in the Send-Key attribute, which is the
// order strongSwan reassembles to recover the full MSK.
func MPPEKeyAttributes(msk, secret []byte, requestAuthenticator [16]byte) ([]Attribute, error) {
	if len(msk) != 64 {
		return nil, fmt.Errorf("radius: MSK must be 64 octets, got %d", len(msk))
	}
	recvSalt, err := RandomSalt()
	if err != nil {
		return nil, err
	}
	sendSalt, err := RandomSalt()
	if err != nil {
		return nil, err
	}
	for sendSalt == recvSalt {
		sendSalt, err = RandomSalt()
		if err != nil {
			return nil, err
		}
	}
	recv, err := EncryptMPPEKey(msk[:32], secret, requestAuthenticator, recvSalt)
	if err != nil {
		return nil, err
	}
	send, err := EncryptMPPEKey(msk[32:64], secret, requestAuthenticator, sendSalt)
	if err != nil {
		return nil, err
	}
	return []Attribute{
		EncodeVSA(VendorMicrosoft, MSMPPERecvKey, recv),
		EncodeVSA(VendorMicrosoft, MSMPPESendKey, send),
	}, nil
}
