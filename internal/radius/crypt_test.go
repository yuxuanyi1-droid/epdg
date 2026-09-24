package radius

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("cannot decode hex %q: %v", s, err)
	}
	return b
}

func mustAuth(t *testing.T, s string) [16]byte {
	t.Helper()
	var out [16]byte
	copy(out[:], mustHex(t, s))
	return out
}

const (
	katSecret = "pyhss-radius-secret"
	// EAP-Request/AKA-Challenge with a zeroed AT_MAC, 68 octets.
	katEAPChallenge = "01070044170100000105000000112233445566778899aabbccddeeff" +
		"0205000011223344556677889900aabbccddeeff" +
		"0b050000" + "00000000000000000000000000000000"
)

// TestFinalizeResponseKnownAnswer checks the Access-Challenge encoding byte for
// byte against the output of pyrad, an independent RADIUS implementation, with
// an identical attribute order (RFC 2865 section 5.2 and RFC 3579 section 3.2).
func TestFinalizeResponseKnownAnswer(t *testing.T) {
	// Expected octets produced by pyrad for the same attributes in the same
	// order: EAP-Message, Reply-Message, Message-Authenticator.
	const want = "0b2a007b061a1677cfe38160be1c83e49236723f" +
		"4f46" + katEAPChallenge +
		"120f616b61206368616c6c656e6765" +
		"501283bc8e98045b9e50dbc6c9eba8095be1"

	reqAuth := mustAuth(t, "00112233445566778899aabbccddeeff")
	p := &Packet{Code: CodeAccessChallenge, Identifier: 0x2a}
	p.Add(AttrEAPMessage, mustHex(t, katEAPChallenge))
	p.Add(AttrReplyMessage, []byte("aka challenge"))
	if err := p.FinalizeResponse([]byte(katSecret), reqAuth); err != nil {
		t.Fatalf("FinalizeResponse: %v", err)
	}
	raw, err := p.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if got := hex.EncodeToString(raw); got != want {
		t.Fatalf("Access-Challenge encoding mismatch\n got %s\nwant %s", got, want)
	}

	// The same bytes must be accepted by our own decoder.
	back, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse of our own reply failed: %v", err)
	}
	if back.Code != CodeAccessChallenge || back.Identifier != 0x2a {
		t.Fatalf("round trip changed the header: %+v", back)
	}
	if !bytes.Equal(back.EAPMessage(), mustHex(t, katEAPChallenge)) {
		t.Error("round trip changed the EAP-Message payload")
	}
	if got, _ := back.Get(AttrReplyMessage); string(got) != "aka challenge" {
		t.Errorf("round trip changed Reply-Message to %q", got)
	}
	if back.Authenticator != reqAuth {
		// The transmitted Authenticator is the Response Authenticator, which
		// must differ from the Request Authenticator.
		if back.Authenticator == reqAuth {
			t.Error("Response Authenticator equals the Request Authenticator")
		}
	}
	if !VerifyResponseAuthenticator(raw, []byte(katSecret), reqAuth) {
		t.Error("Response Authenticator does not verify")
	}
}

// TestMessageAuthenticatorUsesRequestAuthenticator verifies the convention
// that strongSwan uses (src/libradius/radius_message.c): the
// Message-Authenticator of a reply is computed with the Request Authenticator
// in the Authenticator header field, not with the Response Authenticator.
func TestMessageAuthenticatorUsesRequestAuthenticator(t *testing.T) {
	reqAuth := mustAuth(t, "00112233445566778899aabbccddeeff")
	p := &Packet{Code: CodeAccessChallenge, Identifier: 0x2a}
	p.Add(AttrEAPMessage, mustHex(t, katEAPChallenge))
	if err := p.FinalizeResponse([]byte(katSecret), reqAuth); err != nil {
		t.Fatalf("FinalizeResponse: %v", err)
	}
	raw, err := p.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// The reply carries the Response Authenticator in the header, so a naive
	// verification using that value must fail.
	if ok, err := VerifyMessageAuthenticator(raw, []byte(katSecret)); err != nil || ok {
		t.Errorf("Message-Authenticator verified against the Response Authenticator (ok=%v err=%v)", ok, err)
	}

	// Substituting the Request Authenticator must make it verify.
	substituted := append([]byte{}, raw...)
	copy(substituted[4:20], reqAuth[:])
	ok, err := VerifyMessageAuthenticator(substituted, []byte(katSecret))
	if err != nil {
		t.Fatalf("VerifyMessageAuthenticator: %v", err)
	}
	if !ok {
		t.Error("Message-Authenticator did not verify with the Request Authenticator")
	}
}

func TestVerifyMessageAuthenticatorRejectsWrongSecret(t *testing.T) {
	reqAuth := mustAuth(t, "00112233445566778899aabbccddeeff")
	p := &Packet{Code: CodeAccessChallenge, Identifier: 1}
	p.Add(AttrEAPMessage, mustHex(t, katEAPChallenge))
	if err := p.FinalizeResponse([]byte(katSecret), reqAuth); err != nil {
		t.Fatalf("FinalizeResponse: %v", err)
	}
	raw, _ := p.Marshal()
	substituted := append([]byte{}, raw...)
	copy(substituted[4:20], reqAuth[:])
	if ok, _ := VerifyMessageAuthenticator(substituted, []byte("wrong-secret")); ok {
		t.Error("Message-Authenticator verified with the wrong shared secret")
	}
}

// TestEncryptMPPEKeyKnownAnswer checks RFC 2548 section 2.4.2 encryption
// against a known answer produced by an independent implementation using a
// fixed salt.
func TestEncryptMPPEKeyKnownAnswer(t *testing.T) {
	reqAuth := mustAuth(t, "00112233445566778899aabbccddeeff")
	salt := [2]byte{0x9a, 0xbc}

	recvKey := mustHex(t, "561b01f5ce435134075a4c4958f9fabf6706a7a632f4f1577b0a1d4766624899")
	sendKey := mustHex(t, "925e7fd033a735cec216d9af8c5d74c5910d174b62597d43225a47d719d61636")

	cases := []struct {
		name string
		key  []byte
		want string
	}{
		{"recv", recvKey, "9abcd637948693b46e7dbc554d9c2f31ceefefe519fe796cc84a1b3fd85a8756296c2e52ba8c0c435d399682f5faf6c6f975"},
		{"send", sendKey, "9abcd6f3d1f8b6498a1946900109c9e56a61c49350698f89de604c44b813d8643fd38cedc2501800eb1285d8aadb1aed86a5"},
	}
	for _, tc := range cases {
		got, err := EncryptMPPEKey(tc.key, []byte(katSecret), reqAuth, salt)
		if err != nil {
			t.Fatalf("%s: EncryptMPPEKey: %v", tc.name, err)
		}
		if hex.EncodeToString(got) != tc.want {
			t.Errorf("%s ciphertext = %s\nwant               %s", tc.name, hex.EncodeToString(got), tc.want)
		}
		plain, err := DecryptMPPEKey(got, []byte(katSecret), reqAuth)
		if err != nil {
			t.Fatalf("%s: DecryptMPPEKey: %v", tc.name, err)
		}
		if !bytes.Equal(plain, tc.key) {
			t.Errorf("%s round trip mismatch: %x != %x", tc.name, plain, tc.key)
		}
	}
}

// TestMPPEKeyAttributesReassembleMSK mirrors the logic in strongSwan's
// radius_socket.c decrypt_msk(): MSK = MS-MPPE-Recv-Key || MS-MPPE-Send-Key.
func TestMPPEKeyAttributesReassembleMSK(t *testing.T) {
	msk := mustHex(t, "561b01f5ce435134075a4c4958f9fabf6706a7a632f4f1577b0a1d4766624899"+
		"925e7fd033a735cec216d9af8c5d74c5910d174b62597d43225a47d719d61636")
	reqAuth := mustAuth(t, "00112233445566778899aabbccddeeff")

	attrs, err := MPPEKeyAttributes(msk, []byte(katSecret), reqAuth)
	if err != nil {
		t.Fatalf("MPPEKeyAttributes: %v", err)
	}
	if len(attrs) != 2 {
		t.Fatalf("expected two vendor attributes, got %d", len(attrs))
	}

	p := &Packet{Code: CodeAccessAccept, Identifier: 9, Attributes: attrs}
	raw, err := p.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	var recv, send []byte
	for _, vsa := range back.VendorSpecific() {
		if vsa.Vendor != VendorMicrosoft {
			continue
		}
		key, err := DecryptMPPEKey(vsa.Value, []byte(katSecret), reqAuth)
		if err != nil {
			t.Fatalf("DecryptMPPEKey: %v", err)
		}
		switch vsa.Type {
		case MSMPPERecvKey:
			recv = key
		case MSMPPESendKey:
			send = key
		default:
			t.Fatalf("unexpected vendor type %d", vsa.Type)
		}
	}
	if recv == nil || send == nil {
		t.Fatal("both MS-MPPE-Recv-Key and MS-MPPE-Send-Key must be present")
	}
	if got := append(append([]byte{}, recv...), send...); !bytes.Equal(got, msk) {
		t.Errorf("reassembled MSK = %x, want %x", got, msk)
	}
}

func TestMPPEKeyAttributesRejectsBadMSK(t *testing.T) {
	if _, err := MPPEKeyAttributes(make([]byte, 32), []byte(katSecret), [16]byte{}); err == nil {
		t.Error("MPPEKeyAttributes accepted a 32 octet MSK")
	}
}

func TestParseRejectsMalformedPackets(t *testing.T) {
	cases := map[string][]byte{
		"short header":     make([]byte, 19),
		"length too small": {1, 1, 0x00, 0x04},
		"length too long":  {1, 1, 0x00, 0x40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		"attribute length": {1, 1, 0x00, 0x16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80, 0x01},
	}
	for name, raw := range cases {
		if _, err := Parse(raw); err == nil {
			t.Errorf("%s: Parse accepted a malformed packet", name)
		}
	}
}

func TestSetEAPMessageFragmentation(t *testing.T) {
	// An EAP payload larger than 253 octets must be split across attributes
	// (RFC 2865 section 5.13) and reassembled losslessly.
	payload := make([]byte, 600)
	for i := range payload {
		payload[i] = byte(i)
	}
	p := &Packet{Code: CodeAccessChallenge, Identifier: 3}
	p.SetEAPMessage(payload)
	if len(p.GetAll(AttrEAPMessage)) != 3 {
		t.Fatalf("expected 3 EAP-Message fragments, got %d", len(p.GetAll(AttrEAPMessage)))
	}
	raw, err := p.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	back, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !bytes.Equal(back.EAPMessage(), payload) {
		t.Error("EAP-Message fragmentation round trip is lossy")
	}
}
