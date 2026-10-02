package aaa

import (
	"bytes"
	"context"
	"encoding/hex"
	"log/slog"
	"net"
	"testing"
	"time"

	"epdg/internal/eap"
	"epdg/internal/hss"
	"epdg/internal/radius"
)

const (
	testSecret = "pyhss-radius-secret"
	testNAI    = "0001010000000001@nai.epc.mnc001.mcc001.3gppnetwork.org"
)

// recordedVector is a quintuplet previously issued by PyHSS for the subscriber
// in database/pyhss/hss.db. Using real HSS output keeps the test honest about
// the shape of the data the server has to consume.
var recordedVector = &hss.Vector{
	RAND: mustHex("6ee3b978d4578d6cdf715140a7e401cc"),
	AUTN: mustHex("7ead788ce31480006633fb7027dd4ffd"),
	XRES: mustHex("652d50ccec3e84a0"),
	CK:   mustHex("30449c76c49427423336a1157ead0b6d"),
	IK:   mustHex("9df3be5b1cef88535c8e05c92119ca37"),
}

type recordedSource struct {
	vector   *hss.Vector
	onResync func(imsi string, auts, rand []byte) error
}

func (r recordedSource) Vector(context.Context, string) (*hss.Vector, error) {
	return r.vector, nil
}

func (r recordedSource) Resync(_ context.Context, imsi string, auts, rand []byte) error {
	if r.onResync != nil {
		return r.onResync(imsi, auts, rand)
	}
	return nil
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	return NewServer(ServerConfig{
		Listen:                      "127.0.0.1:0",
		Secret:                      testSecret,
		RequireMessageAuthenticator: true,
		SessionTTL:                  time.Minute,
	}, recordedSource{vector: recordedVector}, discardLogger())
}

// buildRequest assembles an Access-Request the way strongSwan's eap-radius
// plugin does: a random authenticator, User-Name, and the EAP payload spread
// over EAP-Message attributes with a Message-Authenticator.
func buildRequest(t *testing.T, identifier uint8, eapPayload []byte) ([]byte, *radius.Packet) {
	t.Helper()
	request := &radius.Packet{Code: radius.CodeAccessRequest, Identifier: identifier}
	auth, err := radius.RandomAuthenticator()
	if err != nil {
		t.Fatalf("RandomAuthenticator: %v", err)
	}
	request.Authenticator = auth
	request.Add(radius.AttrUserName, []byte(testNAI))
	request.Add(radius.AttrNASIdentifier, []byte("epdg.local"))
	request.SetEAPMessage(eapPayload)
	if err := request.SetMessageAuthenticator([]byte(testSecret)); err != nil {
		t.Fatalf("SetMessageAuthenticator: %v", err)
	}
	raw, err := request.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return raw, request
}

func peerAddr() *net.UDPAddr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40000}
}

// TestEAPAKAExchange drives the whole three step exchange. The AT_MAC and AT_RES
// of the response are computed from the same keys a UE would derive, so a
// successful Access-Accept proves the server parsed the challenge correctly,
// verified AT_MAC and compared RES against XRES.
func TestEAPAKAExchange(t *testing.T) {
	server := newTestServer(t)
	ctx := context.Background()

	identity := (&eap.Packet{Code: eap.CodeResponse, Identifier: 0x01, Type: eap.TypeIdentity, Data: []byte(testNAI)}).Marshal()
	raw, request := buildRequest(t, 0x2a, identity)

	challengeRaw := server.Handle(ctx, raw, peerAddr())
	if challengeRaw == nil {
		t.Fatal("the server dropped the Access-Request")
	}
	challenge, err := radius.Parse(challengeRaw)
	if err != nil {
		t.Fatalf("Parse(Access-Challenge): %v", err)
	}
	if challenge.Code != radius.CodeAccessChallenge {
		t.Fatalf("reply code = %s, want Access-Challenge", radius.CodeString(challenge.Code))
	}
	if !radius.VerifyResponseAuthenticator(challengeRaw, []byte(testSecret), request.Authenticator) {
		t.Error("Access-Challenge Response Authenticator does not verify")
	}
	state, ok := challenge.Get(radius.AttrState)
	if !ok || len(state) == 0 {
		t.Fatal("Access-Challenge is missing the State attribute")
	}
	// RFC 3579 section 2.6.5: Reply-Message MUST NOT appear in a packet that
	// carries an EAP-Message.
	if _, ok := challenge.Get(radius.AttrReplyMessage); ok {
		t.Error("Access-Challenge must not carry Reply-Message alongside EAP-Message")
	}

	// Act as the UE: derive the keys and answer with AT_RES plus a correct
	// AT_MAC over the received challenge.
	keys, err := eap.DeriveKeys(testNAI, recordedVector.IK, recordedVector.CK)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}
	challengeEAP := challenge.EAPMessage()
	_, _, ok, err = eap.VerifyMAC(challengeEAP, keys.KAut)
	if err != nil {
		t.Fatalf("VerifyMAC: %v", err)
	}
	if !ok {
		t.Fatal("the challenge AT_MAC does not verify with the keys derived from the recorded vector")
	}

	responseEAP := buildResponse(t, challengeEAP[1], recordedVector.XRES, keys.KAut)
	raw2, _ := buildRequest(t, 0x2b, responseEAP)
	// Carry the State attribute the server handed out.
	req2, err := radius.Parse(raw2)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	req2.Add(radius.AttrState, state)
	req2Auth := req2.Authenticator
	if err := req2.SetMessageAuthenticator([]byte(testSecret)); err != nil {
		t.Fatalf("SetMessageAuthenticator: %v", err)
	}
	raw2, err = req2.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	acceptRaw := server.Handle(ctx, raw2, peerAddr())
	if acceptRaw == nil {
		t.Fatal("the server dropped the AKA response")
	}
	accept, err := radius.Parse(acceptRaw)
	if err != nil {
		t.Fatalf("Parse(Access-Accept): %v", err)
	}
	if accept.Code != radius.CodeAccessAccept {
		t.Fatalf("reply code = %s, want Access-Accept", radius.CodeString(accept.Code))
	}
	if _, ok := accept.Get(radius.AttrReplyMessage); ok {
		t.Error("Access-Accept must not carry Reply-Message alongside EAP-Message")
	}
	// RFC 3579 section 3: if the Access-Request carried User-Name, the
	// Access-Accept must echo it for EAP-unaware proxies.
	if un, ok := accept.Get(radius.AttrUserName); !ok || string(un) != testNAI {
		t.Errorf("Access-Accept must echo User-Name %q, got %q", testNAI, un)
	}

	// The MSK must be handed back as MS-MPPE-Recv-Key || MS-MPPE-Send-Key, which
	// is how strongSwan reassembles it (src/libradius/radius_socket.c).
	var recv, send []byte
	for _, vsa := range accept.VendorSpecific() {
		if vsa.Vendor != radius.VendorMicrosoft {
			continue
		}
		key, err := radius.DecryptMPPEKey(vsa.Value, []byte(testSecret), req2Auth)
		if err != nil {
			t.Fatalf("DecryptMPPEKey: %v", err)
		}
		switch vsa.Type {
		case radius.MSMPPERecvKey:
			recv = key
		case radius.MSMPPESendKey:
			send = key
		}
	}
	if !equalBytes(append(append([]byte{}, recv...), send...), keys.MSK) {
		t.Error("the MSK delivered to the NAS does not match the UE's MSK")
	}
}

// TestAKASynchronizationFailureResync checks that an EAP-Response/
// AKA-Synchronization-Failure is reported to the vector source with the AUTS
// and the RAND of the rejected challenge, and that the server then answers with
// a fresh AKA challenge (RFC 4187 sections 9.6 and 10.6).
func TestAKASynchronizationFailureResync(t *testing.T) {
	var gotIMSI string
	var gotAUTS, gotRAND []byte
	source := recordedSource{
		vector: recordedVector,
		onResync: func(imsi string, auts, rand []byte) error {
			gotIMSI, gotAUTS, gotRAND = imsi, auts, rand
			return nil
		},
	}
	server := NewServer(ServerConfig{
		Secret:                      testSecret,
		RequireMessageAuthenticator: true,
		SessionTTL:                  time.Minute,
	}, source, discardLogger())
	ctx := context.Background()

	identity := (&eap.Packet{Code: eap.CodeResponse, Identifier: 0x01, Type: eap.TypeIdentity, Data: []byte(testNAI)}).Marshal()
	raw, _ := buildRequest(t, 0x2a, identity)
	challengeRaw := server.Handle(ctx, raw, peerAddr())
	challenge, err := radius.Parse(challengeRaw)
	if err != nil {
		t.Fatalf("Parse(Access-Challenge): %v", err)
	}
	state, _ := challenge.Get(radius.AttrState)

	// The peer reports a stale SQN: EAP-Response/AKA-Synchronization-Failure
	// carries AT_AUTS and, per RFC 4187 section 9.6, no AT_MAC.
	// AT_AUTS has no reserved octets: its value is the 14-octet AUTS
	// (RFC 4187 section 10.9).
	auts := mustHex("00112233445566778899aabbccdd")
	body := []byte{eap.SubtypeSynchronizationFailure, 0, 0}
	body = append(body, eap.Attribute{Type: eap.ATAUTS, Value: auts}.Marshal()...)
	syncEAP := (&eap.Packet{Code: eap.CodeResponse, Identifier: challenge.EAPMessage()[1], Type: eap.TypeAKA, Data: body}).Marshal()

	raw2, _ := buildRequest(t, 0x2b, syncEAP)
	req2, err := radius.Parse(raw2)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	req2.Add(radius.AttrState, state)
	if err := req2.SetMessageAuthenticator([]byte(testSecret)); err != nil {
		t.Fatalf("SetMessageAuthenticator: %v", err)
	}
	raw2, err = req2.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	replyRaw := server.Handle(ctx, raw2, peerAddr())
	reply, err := radius.Parse(replyRaw)
	if err != nil {
		t.Fatalf("Parse(Access-Challenge): %v", err)
	}
	if reply.Code != radius.CodeAccessChallenge {
		t.Fatalf("reply code = %s, want Access-Challenge", radius.CodeString(reply.Code))
	}
	if gotIMSI != "001010000000001" {
		t.Errorf("resync IMSI = %q, want 001010000000001", gotIMSI)
	}
	if !bytes.Equal(gotAUTS, auts) {
		t.Errorf("resync AUTS = %x, want %x", gotAUTS, auts)
	}
	if !bytes.Equal(gotRAND, recordedVector.RAND) {
		t.Errorf("resync RAND = %x, want the challenge RAND %x", gotRAND, recordedVector.RAND)
	}
}

func TestAccessRejectOnWrongRES(t *testing.T) {
	server := newTestServer(t)
	ctx := context.Background()

	identity := (&eap.Packet{Code: eap.CodeResponse, Identifier: 0x01, Type: eap.TypeIdentity, Data: []byte(testNAI)}).Marshal()
	raw, request := buildRequest(t, 0x01, identity)
	challengeRaw := server.Handle(ctx, raw, peerAddr())
	challenge, err := radius.Parse(challengeRaw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	state, _ := challenge.Get(radius.AttrState)

	keys, err := eap.DeriveKeys(testNAI, recordedVector.IK, recordedVector.CK)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}
	wrongRES := append([]byte{}, recordedVector.XRES...)
	wrongRES[0] ^= 0xff

	responseEAP := buildResponse(t, challenge.EAPMessage()[1], wrongRES, keys.KAut)
	raw2, _ := buildRequest(t, 0x02, responseEAP)
	req2, err := radius.Parse(raw2)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	req2.Add(radius.AttrState, state)
	if err := req2.SetMessageAuthenticator([]byte(testSecret)); err != nil {
		t.Fatalf("SetMessageAuthenticator: %v", err)
	}
	raw2, err = req2.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	replyRaw := server.Handle(ctx, raw2, peerAddr())
	reply, err := radius.Parse(replyRaw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if reply.Code != radius.CodeAccessReject {
		t.Fatalf("reply code = %s, want Access-Reject", radius.CodeString(reply.Code))
	}
	// RFC 3579 sections 2.2 and 3.3: a fatal error must be reported with an
	// Access-Reject carrying an EAP-Failure, and never with Reply-Message.
	if fm := reply.EAPMessage(); len(fm) < 4 || fm[0] != byte(eap.CodeFailure) {
		t.Errorf("Access-Reject must carry an EAP-Failure, got %x", fm)
	}
	if _, ok := reply.Get(radius.AttrReplyMessage); ok {
		t.Error("Access-Reject must not carry Reply-Message alongside EAP-Message")
	}
	_ = request
}

// TestSilentlyDiscardsWithoutMessageAuthenticator verifies RFC 3579 section 3.1:
// an Access-Request carrying an EAP-Message but no Message-Authenticator is
// silently discarded, so the server returns no reply at all.
func TestSilentlyDiscardsWithoutMessageAuthenticator(t *testing.T) {
	server := newTestServer(t)
	identity := (&eap.Packet{Code: eap.CodeResponse, Identifier: 1, Type: eap.TypeIdentity, Data: []byte(testNAI)}).Marshal()
	request := &radius.Packet{Code: radius.CodeAccessRequest, Identifier: 1}
	auth, _ := radius.RandomAuthenticator()
	request.Authenticator = auth
	request.Add(radius.AttrUserName, []byte(testNAI))
	request.SetEAPMessage(identity)
	raw, err := request.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if reply := server.Handle(context.Background(), raw, peerAddr()); reply != nil {
		t.Errorf("server answered a request without a Message-Authenticator: %x", reply)
	}
}

// TestSilentlyDiscardsBadMessageAuthenticator verifies the MUST in RFC 3579
// section 3.1: a request whose Message-Authenticator does not verify is
// silently discarded.
func TestSilentlyDiscardsBadMessageAuthenticator(t *testing.T) {
	server := newTestServer(t)
	identity := (&eap.Packet{Code: eap.CodeResponse, Identifier: 1, Type: eap.TypeIdentity, Data: []byte(testNAI)}).Marshal()
	request := &radius.Packet{Code: radius.CodeAccessRequest, Identifier: 1}
	auth, _ := radius.RandomAuthenticator()
	request.Authenticator = auth
	request.Add(radius.AttrUserName, []byte(testNAI))
	request.SetEAPMessage(identity)
	if err := request.SetMessageAuthenticator([]byte("wrong-secret")); err != nil {
		t.Fatalf("SetMessageAuthenticator: %v", err)
	}
	raw, err := request.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if reply := server.Handle(context.Background(), raw, peerAddr()); reply != nil {
		t.Errorf("server answered a request with an invalid Message-Authenticator: %x", reply)
	}
}

func TestAccessRejectForUnknownState(t *testing.T) {
	server := newTestServer(t)
	keys, err := eap.DeriveKeys(testNAI, recordedVector.IK, recordedVector.CK)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}
	responseEAP := buildResponse(t, 0x01, recordedVector.XRES, keys.KAut)
	raw, _ := buildRequest(t, 1, responseEAP)
	reply, err := radius.Parse(server.Handle(context.Background(), raw, peerAddr()))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if reply.Code != radius.CodeAccessReject {
		t.Errorf("reply code = %s, want Access-Reject", radius.CodeString(reply.Code))
	}
}

func TestIMSIFromIdentity(t *testing.T) {
	cases := map[string]string{
		"0001010000000001@nai.epc.mnc001.mcc001.3gppnetwork.org": "001010000000001",
		"001010000000001@nai.epc.mnc001.mcc001.3gppnetwork.org":  "001010000000001",
		"001010000000001": "001010000000001",
	}
	for identity, want := range cases {
		got, err := imsiFromIdentity(identity)
		if err != nil {
			t.Errorf("%s: %v", identity, err)
			continue
		}
		if got != want {
			t.Errorf("%s: imsi = %q, want %q", identity, got, want)
		}
	}
	for _, bad := range []string{"", "user@example.com", "001010000000@nai.epc"} {
		if _, err := imsiFromIdentity(bad); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

// buildResponse plays the UE role: it answers the AKA challenge with AT_RES and
// an AT_MAC computed over the response packet (RFC 4187 section 4.1.2).
func buildResponse(t *testing.T, identifier uint8, res, kAut []byte) []byte {
	t.Helper()
	body := []byte{eap.SubtypeChallenge, 0, 0}
	body = append(body, eap.Attribute{Type: eap.ATRES, Value: append([]byte{0, byte(len(res) * 8)}, res...)}.Marshal()...)
	body = append(body, eap.Attribute{Type: eap.ATMAC, Value: make([]byte, 18)}.Marshal()...)
	raw := (&eap.Packet{Code: eap.CodeResponse, Identifier: identifier, Type: eap.TypeAKA, Data: body}).Marshal()
	if err := eap.SignMAC(raw, kAut); err != nil {
		t.Fatalf("SignMAC: %v", err)
	}
	return raw
}

// discardLogger returns a logger that drops everything, keeping test output
// clean while the server under test still logs normally in production.
func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func mustGet(p *radius.Packet, typ uint8) []byte {
	v, _ := p.Get(typ)
	return v
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
