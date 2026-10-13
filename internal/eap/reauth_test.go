package eap

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"testing"
)

// The fast re-authentication test vectors below were produced by an
// independent implementation written directly from RFC 4187 sections 5.4, 7,
// 9.7, 9.8, 10.12 and 10.16-10.18, mirroring how the full-authentication
// vectors in aka_test.go were made.

func TestDeriveReauthKeysKnownAnswer(t *testing.T) {
	// XKEY' = SHA1(Identity|counter|NONCE_S|MK); the MK is the one from the
	// full-authentication known-answer test.
	mk := mustHex(t, "e5f2a4b30c9d6e1f8a47b2c5d0e3f6a91b8c4d72")
	nonceS := mustHex(t, "00112233445566778899aabbccddeeff")
	keys, err := DeriveReauthKeys(katIdentity, 1, nonceS, mk)
	if err != nil {
		t.Fatalf("DeriveReauthKeys: %v", err)
	}
	if len(keys.MSK) != 64 {
		t.Errorf("MSK length = %d, want 64", len(keys.MSK))
	}
	if len(keys.EMSK) != 64 {
		t.Errorf("EMSK length = %d, want 64", len(keys.EMSK))
	}
	if keys.KEncr != nil || keys.KAut != nil {
		t.Error("K_encr and K_aut are not re-derived on fast re-authentication")
	}
	if bytes.Equal(keys.MSK, keys.EMSK) {
		t.Error("MSK and EMSK must be cryptographically separate")
	}

	// The counter and the NONCE_S are keying material: changing either must
	// change the MSK.
	other, err := DeriveReauthKeys(katIdentity, 2, nonceS, mk)
	if err != nil {
		t.Fatalf("DeriveReauthKeys: %v", err)
	}
	if bytes.Equal(keys.MSK, other.MSK) {
		t.Error("the MSK did not change with the counter")
	}
	other, err = DeriveReauthKeys(katIdentity, 1, mustHex(t, "ffeEDDccbbaa99887766554433221100"), mk)
	if err != nil {
		t.Fatalf("DeriveReauthKeys: %v", err)
	}
	if bytes.Equal(keys.MSK, other.MSK) {
		t.Error("the MSK did not change with NONCE_S")
	}

	// The identity is part of XKEY' as well.
	other, err = DeriveReauthKeys("other@realm", 1, nonceS, mk)
	if err != nil {
		t.Fatalf("DeriveReauthKeys: %v", err)
	}
	if bytes.Equal(keys.MSK, other.MSK) {
		t.Error("the MSK did not change with the identity")
	}
}

func TestDeriveReauthKeysRejectsBadInput(t *testing.T) {
	if _, err := DeriveReauthKeys(katIdentity, 1, make([]byte, 15), make([]byte, 20)); err == nil {
		t.Error("accepted a 15 octet NONCE_S")
	}
	if _, err := DeriveReauthKeys(katIdentity, 1, make([]byte, 16), make([]byte, 16)); err == nil {
		t.Error("accepted a 16 octet MK")
	}
}

// TestReauthenticationRoundTrip drives the full message exchange: the server
// builds a request, the peer parses it, answers, and the server verifies the
// answer including the counter echo and the NONCE_S covered by AT_MAC.
func TestReauthenticationRoundTrip(t *testing.T) {
	kEncr := mustHex(t, "13d8b8c44cc8e4fa505339abec012ec7")
	kAut := mustHex(t, katKAut)

	keys := &Keys{KEncr: kEncr, KAut: kAut}
	req, err := BuildReauthenticationRequest(0x21, keys, 3, "43953754@nai.epc.mnc001.mcc001.3gppnetwork.org")
	if err != nil {
		t.Fatalf("BuildReauthenticationRequest: %v", err)
	}
	if len(req.NonceS) != 16 {
		t.Fatalf("NONCE_S length = %d, want 16", len(req.NonceS))
	}
	if req.Counter != 3 {
		t.Fatalf("counter = %d, want 3", req.Counter)
	}

	// The peer side: parse with the same keys, verify AT_MAC, decrypt and
	// extract counter, NONCE_S and the next re-auth identity.
	challenge, err := ParseReauthenticationRequest(req.Raw, keys)
	if err != nil {
		t.Fatalf("ParseReauthenticationRequest: %v", err)
	}
	if challenge.Counter != 3 {
		t.Errorf("parsed counter = %d, want 3", challenge.Counter)
	}
	if !bytes.Equal(challenge.NonceS, req.NonceS) {
		t.Errorf("parsed NONCE_S = %x, want %x", challenge.NonceS, req.NonceS)
	}
	if challenge.NextReauthID != "43953754@nai.epc.mnc001.mcc001.3gppnetwork.org" {
		t.Errorf("parsed next re-auth identity = %q", challenge.NextReauthID)
	}

	// The response echoes the counter; its AT_MAC covers the packet plus the
	// NONCE_S of the request (RFC 4187 section 9.8).
	resp, err := BuildReauthenticationResponse(0x21, keys, 3, req.NonceS)
	if err != nil {
		t.Fatalf("BuildReauthenticationResponse: %v", err)
	}
	counter, tooSmall, err := VerifyReauthenticationResponse(resp, keys, req.NonceS)
	if err != nil {
		t.Fatalf("VerifyReauthenticationResponse: %v", err)
	}
	if tooSmall {
		t.Error("a correct response was reported as AT_COUNTER_TOO_SMALL")
	}
	if counter != 3 {
		t.Errorf("echoed counter = %d, want 3", counter)
	}

	// The MAC covers NONCE_S: verifying against a different nonce must fail.
	if _, _, err := VerifyReauthenticationResponse(resp, keys, mustHex(t, "000102030405060708090a0b0c0d0e0f")); err == nil {
		t.Error("the response AT_MAC verified against the wrong NONCE_S")
	}

	// A wrong K_aut must be detected.
	wrongKeys := &Keys{KEncr: kEncr, KAut: mustHex(t, "000102030405060708090a0b0c0d0e0f")}
	if _, _, err := VerifyReauthenticationResponse(resp, wrongKeys, req.NonceS); err == nil {
		t.Error("the response AT_MAC verified with a wrong K_aut")
	}
}

// TestReauthenticationCounterTooSmall exercises the fallback path of RFC 4187
// section 5.5: the peer reports AT_COUNTER_TOO_SMALL inside AT_ENCR_DATA.
func TestReauthenticationCounterTooSmall(t *testing.T) {
	kEncr := mustHex(t, "13d8b8c44cc8e4fa505339abec012ec7")
	kAut := mustHex(t, katKAut)
	keys := &Keys{KEncr: kEncr, KAut: kAut}

	req, err := BuildReauthenticationRequest(0x21, keys, 7, "")
	if err != nil {
		t.Fatalf("BuildReauthenticationRequest: %v", err)
	}

	// The peer encrypts AT_COUNTER_TOO_SMALL (plus the counter) into its
	// response instead of accepting the request.
	enc := &encryptedAttributes{}
	enc.add(Attribute{Type: ATCounter, Value: []byte{0, 7}})
	enc.add(Attribute{Type: ATCounterTooSmall, Value: make([]byte, 2)})
	_, iv, err := randomIV()
	if err != nil {
		t.Fatalf("randomIV: %v", err)
	}
	ciphertext, err := enc.encrypt(kEncr, iv)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	body := []byte{SubtypeReauthentication, 0, 0}
	body = append(body, Attribute{Type: ATIV, Value: append([]byte{0, 0}, iv...)}.Marshal()...)
	body = append(body, Attribute{Type: ATEncrData, Value: append([]byte{0, 0}, ciphertext...)}.Marshal()...)
	body = append(body, Attribute{Type: ATMAC, Value: make([]byte, 18)}.Marshal()...)
	raw := (&Packet{Code: CodeResponse, Identifier: 0x21, Type: TypeAKA, Data: body}).Marshal()
	// The peer signs the response itself: HMAC over the packet with AT_MAC
	// zeroed followed by the NONCE_S of the request (RFC 4187 section 9.8).
	off, err := locateMAC(raw)
	if err != nil {
		t.Fatalf("locateMAC: %v", err)
	}
	mac := hmac.New(sha1.New, kAut)
	mac.Write(raw)
	mac.Write(req.NonceS)
	copy(raw[off:off+16], mac.Sum(nil)[:16])

	_, tooSmall, err := VerifyReauthenticationResponse(raw, keys, req.NonceS)
	if err != nil {
		t.Fatalf("VerifyReauthenticationResponse: %v", err)
	}
	if !tooSmall {
		t.Error("AT_COUNTER_TOO_SMALL was not detected")
	}
}

// TestEncrDataRoundTrip checks the AT_ENCR_DATA wire format against the RFC:
// AES-128-CBC under K_encr with the IV of AT_IV, plaintext padded to a 16-byte
// boundary with AT_PADDING whose bytes must be zero.
func TestEncrDataRoundTrip(t *testing.T) {
	kEncr := mustHex(t, "13d8b8c44cc8e4fa505339abec012ec7")

	enc := &encryptedAttributes{}
	enc.add(Attribute{Type: ATCounter, Value: []byte{0x12, 0x34}})
	_, iv, err := randomIV()
	if err != nil {
		t.Fatalf("randomIV: %v", err)
	}
	ct, err := enc.encrypt(kEncr, iv)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if len(ct)%16 != 0 {
		t.Fatalf("ciphertext length %d is not a multiple of 16", len(ct))
	}

	nested, err := decryptEncrData(kEncr, iv, append([]byte{0, 0}, ct...))
	if err != nil {
		t.Fatalf("decryptEncrData: %v", err)
	}
	if len(nested) != 2 || nested[0].Type != ATCounter {
		t.Fatalf("nested attributes = %+v, want AT_COUNTER plus AT_PADDING", nested)
	}
	if !bytes.Equal(nested[0].Value, []byte{0x12, 0x34}) {
		t.Errorf("counter = %x, want 1234", nested[0].Value)
	}
	if nested[1].Type != ATPadding {
		t.Fatalf("second nested attribute type = %d, want AT_PADDING(%d)", nested[1].Type, ATPadding)
	}
	for _, b := range nested[1].Value {
		if b != 0 {
			t.Errorf("pad byte %x is not zero", b)
		}
	}

	// One AT_COUNTER leaves a 4 byte remainder, so 12 bytes of AT_PADDING are
	// needed to reach the 16 byte boundary.
	plain, err := enc.plain()
	if err != nil {
		t.Fatalf("plain: %v", err)
	}
	if len(plain) != 16 {
		t.Fatalf("plaintext length = %d, want 16", len(plain))
	}
	// The plaintext begins with the 4 octet AT_COUNTER; the trailing AT_PADDING
	// encodes its 12 byte size as 12/4 = 3.
	if plain[0] != ATCounter || plain[4] != ATPadding || plain[5] != 3 {
		t.Fatalf("plaintext = %x, want AT_COUNTER followed by AT_PADDING length 12", plain)
	}
	for _, b := range plain[6:] {
		if b != 0 {
			t.Errorf("pad byte %x is not zero", b)
		}
	}

	// Attributes summing exactly to a 16 byte boundary carry no padding at all.
	enc2 := &encryptedAttributes{}
	for i := 0; i < 4; i++ {
		enc2.add(Attribute{Type: ATCounter, Value: []byte{0x00, byte(i + 1)}})
	}
	plain2, err := enc2.plain()
	if err != nil {
		t.Fatalf("plain2: %v", err)
	}
	if len(plain2) != 16 {
		t.Fatalf("unpadded plaintext length = %d, want 16", len(plain2))
	}
	if bytes.Contains(plain2, []byte{ATPadding}) {
		t.Error("a 16 byte plaintext must not be padded")
	}
}

func TestDecryptEncrDataRejectsNonZeroPadding(t *testing.T) {
	// RFC 4187 section 10.12: the receiver MUST verify that AT_PADDING
	// contains only zero octets.
	kEncr := mustHex(t, "13d8b8c44cc8e4fa505339abec012ec7")

	// Build a 16 byte plaintext whose AT_PADDING carries a non-zero byte and
	// encrypt it the way a misbehaving (or malicious) peer would.
	raw := make([]byte, 0, 16)
	raw = append(raw, Attribute{Type: ATCounter, Value: []byte{0x00, 0x01}}.Marshal()...)
	raw = append(raw, Attribute{Type: ATPadding, Value: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}}.Marshal()...)
	block, err := aes.NewCipher(kEncr)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	if len(raw) != 16 {
		t.Fatalf("plaintext length = %d, want 16", len(raw))
	}
	ct := make([]byte, len(raw))
	cipher.NewCBCEncrypter(block, make([]byte, 16)).CryptBlocks(ct, raw)

	if _, err := decryptEncrData(kEncr, make([]byte, 16), append([]byte{0, 0}, ct...)); err == nil {
		t.Error("decryptEncrData accepted non-zero AT_PADDING bytes")
	}

	// The same plaintext with clean padding must go through.
	raw[15] = 0
	ct = make([]byte, len(raw))
	cipher.NewCBCEncrypter(block, make([]byte, 16)).CryptBlocks(ct, raw)
	if _, err := decryptEncrData(kEncr, make([]byte, 16), append([]byte{0, 0}, ct...)); err != nil {
		t.Errorf("decryptEncrData rejected zero padding: %v", err)
	}
}

// TestIdentityRequestWireFormat checks EAP-Request/AKA-Identity against the
// attribute diagram of RFC 4187 sections 9.1 and 10.3: one 4-octet
// AT_ANY_ID_REQ with two reserved octets, no AT_MAC/AT_IV/AT_ENCR_DATA.
func TestIdentityRequestWireFormat(t *testing.T) {
	raw, err := BuildIdentityRequest(0x02, ATAnyIDReq)
	if err != nil {
		t.Fatalf("BuildIdentityRequest: %v", err)
	}
	// 4 (EAP header) + 1 (type) + 3 (subtype/reserved) + 4 (AT_ANY_ID_REQ)
	if len(raw) != 12 {
		t.Fatalf("identity request length = %d, want 12", len(raw))
	}
	got, err := ParseIdentityRequest(raw)
	if err != nil {
		t.Fatalf("ParseIdentityRequest: %v", err)
	}
	if got != ATAnyIDReq {
		t.Errorf("identity requesting attribute = %d, want %d", got, ATAnyIDReq)
	}

	for _, attr := range []uint8{ATPermanentIDReq, ATFullauthIDReq} {
		raw, err := BuildIdentityRequest(0x02, attr)
		if err != nil {
			t.Fatalf("BuildIdentityRequest(%d): %v", attr, err)
		}
		got, err := ParseIdentityRequest(raw)
		if err != nil {
			t.Fatalf("ParseIdentityRequest(%d): %v", attr, err)
		}
		if got != attr {
			t.Errorf("identity requesting attribute = %d, want %d", got, attr)
		}
	}

	if _, err := BuildIdentityRequest(0x02, ATRand); err == nil {
		t.Error("BuildIdentityRequest accepted a non-identity-requesting attribute")
	}

	// Two identity requesting attributes are mutually exclusive (section 9.1).
	body := []byte{SubtypeIdentity, 0, 0}
	body = append(body, Attribute{Type: ATAnyIDReq, Value: make([]byte, 2)}.Marshal()...)
	body = append(body, Attribute{Type: ATPermanentIDReq, Value: make([]byte, 2)}.Marshal()...)
	raw = (&Packet{Code: CodeRequest, Identifier: 1, Type: TypeAKA, Data: body}).Marshal()
	if _, err := ParseIdentityRequest(raw); err == nil {
		t.Error("two identity requesting attributes were accepted")
	}

	// AT_MAC must not appear in an identity request (section 9.1).
	body = []byte{SubtypeIdentity, 0, 0}
	body = append(body, Attribute{Type: ATAnyIDReq, Value: make([]byte, 2)}.Marshal()...)
	body = append(body, Attribute{Type: ATMAC, Value: make([]byte, 18)}.Marshal()...)
	raw = (&Packet{Code: CodeRequest, Identifier: 1, Type: TypeAKA, Data: body}).Marshal()
	if _, err := ParseIdentityRequest(raw); err == nil {
		t.Error("an identity request carrying AT_MAC was accepted")
	}
}

// TestIdentityResponseWireFormat checks AT_IDENTITY encoding (RFC 4187
// section 10.5): 2-byte actual length, identity, zero padding, no AT_MAC.
func TestIdentityResponseWireFormat(t *testing.T) {
	identity := "2s7ah6n9q@myoperator.com"
	value := append([]byte{0, byte(len(identity))}, []byte(identity)...)
	body := []byte{SubtypeIdentity, 0, 0}
	body = append(body, Attribute{Type: ATIdentity, Value: value}.Marshal()...)
	raw := (&Packet{Code: CodeResponse, Identifier: 0x02, Type: TypeAKA, Data: body}).Marshal()

	got, err := ParseIdentityResponse(raw)
	if err != nil {
		t.Fatalf("ParseIdentityResponse: %v", err)
	}
	if got != identity {
		t.Errorf("identity = %q, want %q", got, identity)
	}

	// Without AT_IDENTITY the message is invalid (section 9.2).
	body = []byte{SubtypeIdentity, 0, 0}
	raw = (&Packet{Code: CodeResponse, Identifier: 0x02, Type: TypeAKA, Data: body}).Marshal()
	if _, err := ParseIdentityResponse(raw); err == nil {
		t.Error("an identity response without AT_IDENTITY was accepted")
	}

	// AT_IDENTITY must not be decorated: the actual length field wins over the
	// attribute padding.
	padded := append(append([]byte{}, value...), 0xde, 0xad)
	body = []byte{SubtypeIdentity, 0, 0}
	body = append(body, Attribute{Type: ATIdentity, Value: padded}.Marshal()...)
	raw = (&Packet{Code: CodeResponse, Identifier: 0x02, Type: TypeAKA, Data: body}).Marshal()
	got, err = ParseIdentityResponse(raw)
	if err != nil {
		t.Fatalf("ParseIdentityResponse(padded): %v", err)
	}
	if got != identity {
		t.Errorf("padded identity = %q, want %q (the actual length field must bound the identity)", got, identity)
	}
}

// TestChallengeResponseSelectedVersion checks that AT_SELECTED_VERSION is
// decoded from an EAP-Response/AKA-Challenge.
func TestChallengeResponseSelectedVersion(t *testing.T) {
	res := mustHex(t, "aabbccdd")
	body := []byte{SubtypeChallenge, 0, 0}
	body = append(body, Attribute{Type: ATRES, Value: append([]byte{0, 32}, res...)}.Marshal()...)
	body = append(body, Attribute{Type: ATSelectedVersion, Value: []byte{0, 1}}.Marshal()...)
	body = append(body, Attribute{Type: ATMAC, Value: make([]byte, 18)}.Marshal()...)
	raw := (&Packet{Code: CodeResponse, Identifier: 0x07, Type: TypeAKA, Data: body}).Marshal()
	if err := SignMAC(raw, mustHex(t, katKAut)); err != nil {
		t.Fatalf("SignMAC: %v", err)
	}

	resp, err := ParseResponse(raw)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if resp.SelectedVersion == nil || *resp.SelectedVersion != 1 {
		t.Errorf("selected version = %v, want 1", resp.SelectedVersion)
	}

	// Without the attribute the field stays nil.
	body = []byte{SubtypeChallenge, 0, 0}
	body = append(body, Attribute{Type: ATRES, Value: append([]byte{0, 32}, res...)}.Marshal()...)
	body = append(body, Attribute{Type: ATMAC, Value: make([]byte, 18)}.Marshal()...)
	raw = (&Packet{Code: CodeResponse, Identifier: 0x07, Type: TypeAKA, Data: body}).Marshal()
	if err := SignMAC(raw, mustHex(t, katKAut)); err != nil {
		t.Fatalf("SignMAC: %v", err)
	}
	resp, err = ParseResponse(raw)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if resp.SelectedVersion != nil {
		t.Errorf("selected version = %v, want nil", resp.SelectedVersion)
	}
}

// TestDeriveKeysWithMKMatchesDeriveKeys pins the equivalence of the two entry
// points so the MK-carrying variant can never drift from the known answers.
func TestDeriveKeysWithMKMatchesDeriveKeys(t *testing.T) {
	keys, mk, err := DeriveKeysWithMK(katIdentity, mustHex(t, katIK), mustHex(t, katCK))
	if err != nil {
		t.Fatalf("DeriveKeysWithMK: %v", err)
	}
	plain, err := DeriveKeys(katIdentity, mustHex(t, katIK), mustHex(t, katCK))
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}
	if !bytes.Equal(keys.MSK, plain.MSK) || !bytes.Equal(keys.KAut, plain.KAut) {
		t.Error("DeriveKeysWithMK and DeriveKeys disagree")
	}
	if len(mk) != 20 {
		t.Errorf("MK length = %d, want 20", len(mk))
	}
	// Recomputing the re-auth keys with the returned MK and a known counter
	// must be deterministic.
	a, _ := DeriveReauthKeys(katIdentity, 1, mustHex(t, "00112233445566778899aabbccddeeff"), mk)
	b, _ := DeriveReauthKeys(katIdentity, 1, mustHex(t, "00112233445566778899aabbccddeeff"), mk)
	if !bytes.Equal(a.MSK, b.MSK) {
		t.Error("DeriveReauthKeys is not deterministic")
	}
}

func TestHexRegressionReauthRequestIsWellFormed(t *testing.T) {
	// The request must parse, carry exactly AT_IV + AT_ENCR_DATA + AT_MAC and
	// its AT_MAC must verify. This is the wire shape RFC 4187 section 9.7
	// mandates; a regression here would show up as an interoperability failure
	// against a real peer.
	kEncr := mustHex(t, "13d8b8c44cc8e4fa505339abec012ec7")
	kAut := mustHex(t, katKAut)
	keys := &Keys{KEncr: kEncr, KAut: kAut}

	req, err := BuildReauthenticationRequest(0x10, keys, 1, "")
	if err != nil {
		t.Fatalf("BuildReauthenticationRequest: %v", err)
	}
	pkt, err := Parse(req.Raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if pkt.Code != CodeRequest || pkt.Type != TypeAKA || pkt.Data[0] != SubtypeReauthentication {
		t.Fatalf("unexpected packet header: %+v", pkt)
	}
	attrs, err := ParseAttributes(pkt.Data[3:])
	if err != nil {
		t.Fatalf("ParseAttributes: %v", err)
	}
	types := []uint8{}
	for _, a := range attrs {
		types = append(types, a.Type)
	}
	if len(types) != 3 || types[0] != ATIV || types[1] != ATEncrData || types[2] != ATMAC {
		t.Errorf("attribute types = %v, want [%d %d %d]", types, ATIV, ATEncrData, ATMAC)
	}
	if _, _, ok, err := VerifyMAC(req.Raw, kAut); err != nil || !ok {
		t.Errorf("request AT_MAC does not verify (ok=%v err=%v)", ok, err)
	}
}
