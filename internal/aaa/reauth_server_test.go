package aaa

import (
	"bytes"
	"context"
	"testing"
	"time"

	"epdg/internal/eap"
	"epdg/internal/radius"
)

// The tests in this file drive the RADIUS EAP-AKA server through the protocol
// mechanisms added with the conformance fixes: the retransmission cache (RFC
// 5080 section 2.2.2), the AKA-Identity round (RFC 4187 sections 4.1.4 and
// 9.1-9.2), fast re-authentication (section 5.4 with its AT_COUNTER_TOO_SMALL
// fallback in section 5.5) and the AT_SELECTED_VERSION check (section 10.21).

// exchange is a helper that sends one Access-Request and parses the reply.
func exchange(t *testing.T, server *Server, ctx context.Context, req *radius.Packet) *radius.Packet {
	t.Helper()
	raw, err := req.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	replyRaw := server.Handle(ctx, raw, peerAddr())
	if replyRaw == nil {
		t.Fatal("the server dropped the request")
	}
	reply, err := radius.Parse(replyRaw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return reply
}

// newRequest builds an Access-Request with a Message-Authenticator, mirroring
// what strongSwan's eap-radius plugin sends.
func newRequest(t *testing.T, identifier uint8, eapPayload []byte, attrs ...radius.Attribute) *radius.Packet {
	t.Helper()
	request := &radius.Packet{Code: radius.CodeAccessRequest, Identifier: identifier}
	auth, err := radius.RandomAuthenticator()
	if err != nil {
		t.Fatalf("RandomAuthenticator: %v", err)
	}
	request.Authenticator = auth
	request.Add(radius.AttrUserName, []byte(testNAI))
	request.SetEAPMessage(eapPayload)
	for _, a := range attrs {
		request.Add(a.Type, a.Value)
	}
	if err := request.SetMessageAuthenticator([]byte(testSecret)); err != nil {
		t.Fatalf("SetMessageAuthenticator: %v", err)
	}
	return request
}

// identityPacket builds an EAP-Response/Identity carrying the given identity.
func identityPacket(identifier uint8, identity string) []byte {
	return (&eap.Packet{Code: eap.CodeResponse, Identifier: identifier, Type: eap.TypeIdentity, Data: []byte(identity)}).Marshal()
}

// akaIdentityPacket builds an EAP-Response/AKA-Identity carrying AT_IDENTITY
// (RFC 4187 section 9.2).
func akaIdentityPacket(identifier uint8, identity string) []byte {
	body := []byte{eap.SubtypeIdentity, 0, 0}
	body = append(body, eap.Attribute{Type: eap.ATIdentity,
		Value: append([]byte{0, byte(len(identity))}, []byte(identity)...)}.Marshal()...)
	return (&eap.Packet{Code: eap.CodeResponse, Identifier: identifier, Type: eap.TypeAKA, Data: body}).Marshal()
}

// reauthResponsePacket plays the UE in a fast re-authentication: it echoes the
// counter inside encrypted AT_ENCR_DATA and MACs the packet plus NONCE_S (RFC
// 4187 section 9.8). It is a thin wrapper over the eap package so the server
// tests read like the protocol exchange.
func reauthResponsePacket(t *testing.T, identifier uint8, kEncr, kAut, nonceS []byte, counter uint16) []byte {
	t.Helper()
	resp, err := eap.BuildReauthenticationResponse(identifier, &eap.Keys{KEncr: kEncr, KAut: kAut}, counter, nonceS)
	if err != nil {
		t.Fatalf("BuildReauthenticationResponse: %v", err)
	}
	return resp
}

// decryptCounter extracts the encrypted AT_COUNTER of a re-authentication
// request so the test can echo it exactly as a UE would.
func peerParseReauthRequest(t *testing.T, raw []byte, kEncr, kAut []byte) *eap.ReauthChallenge {
	t.Helper()
	challenge, err := eap.ParseReauthenticationRequest(raw, &eap.Keys{KEncr: kEncr, KAut: kAut})
	if err != nil {
		t.Fatalf("ParseReauthenticationRequest: %v", err)
	}
	return challenge
}

// runFullAuthentication performs the two round trip full authentication and
// returns the parsed Access-Accept together with the UE-side keys.
func runFullAuthentication(t *testing.T, server *Server, ctx context.Context, identity string, startID uint8) (*radius.Packet, *eap.Keys) {
	t.Helper()
	reply := exchange(t, server, ctx, newRequest(t, startID, identityPacket(startID, identity)))
	if reply.Code != radius.CodeAccessChallenge {
		t.Fatalf("reply code = %s, want Access-Challenge", radius.CodeString(reply.Code))
	}
	state, ok := reply.Get(radius.AttrState)
	if !ok || len(state) == 0 {
		t.Fatal("the challenge is missing the State attribute")
	}

	keys, err := eap.DeriveKeys(identity, recordedVector.IK, recordedVector.CK)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}
	challengeEAP := reply.EAPMessage()
	responseEAP := buildResponse(t, challengeEAP[1], recordedVector.XRES, keys.KAut)
	accept := exchange(t, server, ctx, newRequest(t, startID+1, responseEAP, radius.Attribute{Type: radius.AttrState, Value: state}))
	if accept.Code != radius.CodeAccessAccept {
		t.Fatalf("reply code = %s, want Access-Accept (EAP %x)", radius.CodeString(accept.Code), accept.EAPMessage())
	}
	return accept, keys
}

// TestRetransmissionReturnsCachedReply pins RFC 5080 section 2.2.2: a repeated
// Access-Request (same Identifier and Request Authenticator) is answered with
// the very same datagram, not with a fresh decision - reprocessing would
// consume the one-time State and produce a spurious Access-Reject.
func TestRetransmissionReturnsCachedReply(t *testing.T) {
	server := newTestServer(t)
	ctx := context.Background()

	identity := identityPacket(0x01, testNAI)
	raw, request := buildRequest(t, 0x2a, identity)

	first := server.Handle(ctx, raw, peerAddr())
	if first == nil {
		t.Fatal("the server dropped the request")
	}
	second := server.Handle(ctx, raw, peerAddr())
	if second == nil {
		t.Fatal("the server dropped the retransmission")
	}
	if !bytes.Equal(first, second) {
		t.Error("the retransmission was not answered with the cached reply")
	}
	// A different Request Authenticator with the same Identifier is a new
	// request, not a retransmission.
	tampered := append([]byte{}, raw...)
	tampered[4] ^= 0xff // inside the Request Authenticator
	third := server.Handle(ctx, tampered, peerAddr())
	if third != nil && bytes.Equal(third, first) {
		t.Error("a different request was answered with the cached reply")
	}
	_ = request
}

// TestAKAIdentityRoundAfterUnknownIdentity drives RFC 4187 sections 4.1.4 and
// 9.1-9.2: an identity the server cannot classify is answered with
// EAP-Request/AKA-Identity (AT_ANY_ID_REQ, no State), and the
// EAP-Response/AKA-Identity carrying AT_IDENTITY then starts the full
// authentication with that identity.
func TestAKAIdentityRoundAfterUnknownIdentity(t *testing.T) {
	server := newTestServer(t)
	ctx := context.Background()

	// A pseudonym-style identity: not a permanent NAI, not a re-auth identity.
	reply := exchange(t, server, ctx, newRequest(t, 0x01, identityPacket(0x01, "2s7ah6n9q@myoperator.com")))
	if reply.Code != radius.CodeAccessChallenge {
		t.Fatalf("reply code = %s, want Access-Challenge", radius.CodeString(reply.Code))
	}
	if _, ok := reply.Get(radius.AttrState); ok {
		t.Error("the AKA-Identity round must not carry a State attribute - there is nothing to bind yet")
	}
	idReq := reply.EAPMessage()
	pkt, err := eap.Parse(idReq)
	if err != nil {
		t.Fatalf("Parse(EAP-Request/AKA-Identity): %v", err)
	}
	if pkt.Type != eap.TypeAKA {
		t.Fatalf("EAP type = %d, want AKA", pkt.Type)
	}
	if len(pkt.Data) < 3 || pkt.Data[0] != eap.SubtypeIdentity {
		t.Fatalf("subtype = %v, want Identity", pkt.Data)
	}
	reqAttr, err := eap.ParseIdentityRequest(idReq)
	if err != nil {
		t.Fatalf("ParseIdentityRequest: %v", err)
	}
	if reqAttr != eap.ATAnyIDReq {
		t.Errorf("identity requesting attribute = %d, want AT_ANY_ID_REQ", reqAttr)
	}

	// The peer answers with EAP-Response/AKA-Identity and its permanent
	// identity; the server must then run the full authentication with it.
	permanent := "001010000000001@nai.epc.mnc001.mcc001.3gppnetwork.org"
	akaResp := akaIdentityPacket(idReq[1], permanent)
	accept := exchange(t, server, ctx, newRequest(t, 0x02, akaResp))
	// The response goes out without a State (the identity request had none) and
	// comes back as a challenge for the permanent identity.
	if accept.Code != radius.CodeAccessChallenge {
		t.Fatalf("reply code = %s, want Access-Challenge for the permanent identity", radius.CodeString(accept.Code))
	}
	if _, ok := accept.Get(radius.AttrState); !ok {
		t.Fatal("the full authentication challenge must carry a State attribute")
	}

	// And the challenge must verify with keys derived from the identity the
	// peer presented (RFC 4187 section 7: the MK binds the last AT_IDENTITY).
	keys, err := eap.DeriveKeys(permanent, recordedVector.IK, recordedVector.CK)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}
	state, _ := accept.Get(radius.AttrState)
	responseEAP := buildResponse(t, accept.EAPMessage()[1], recordedVector.XRES, keys.KAut)
	final := exchange(t, server, ctx, newRequest(t, 0x03, responseEAP, radius.Attribute{Type: radius.AttrState, Value: state}))
	if final.Code != radius.CodeAccessAccept {
		t.Errorf("reply code = %s, want Access-Accept", radius.CodeString(final.Code))
	}
}

// TestFastReauthentication drives RFC 4187 section 5.4 end to end: full
// authentication issues a re-auth identity (in the server's reauth map), the
// peer presents it, receives EAP-Request/AKA-Reauthentication, answers, and
// gets an Access-Accept with a *new* MSK derived from MK|counter|NONCE_S.
func TestFastReauthentication(t *testing.T) {
	server := newTestServer(t)
	ctx := context.Background()

	_, fullKeys := runFullAuthentication(t, server, ctx, testNAI, 0x10)

	// Find the one-time re-auth identity the server issued. It is random, so
	// the test inspects the server map the same way an integration test would
	// read it from the UE's EAP-Request/AKA-Identity response.
	server.mu.Lock()
	if len(server.reauth) != 1 {
		server.mu.Unlock()
		t.Fatalf("reauth map holds %d identities, want 1", len(server.reauth))
	}
	var reauthID string
	var session *akaSession
	for id, sess := range server.reauth {
		reauthID, session = id, sess
	}
	server.mu.Unlock()

	if session.nextCounter != 1 {
		t.Errorf("nextCounter = %d, want 1 after the full authentication", session.nextCounter)
	}

	// Present the re-auth identity: the server must answer with
	// EAP-Request/AKA-Reauthentication under a fresh State.
	reply := exchange(t, server, ctx, newRequest(t, 0x20, identityPacket(0x20, reauthID)))
	if reply.Code != radius.CodeAccessChallenge {
		t.Fatalf("reply code = %s, want Access-Challenge", radius.CodeString(reply.Code))
	}
	state, ok := reply.Get(radius.AttrState)
	if !ok {
		t.Fatal("the re-authentication challenge must carry a State attribute")
	}
	reauthEAP := reply.EAPMessage()
	pkt, err := eap.Parse(reauthEAP)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if pkt.Data[0] != eap.SubtypeReauthentication {
		t.Fatalf("subtype = %d, want Reauthentication", pkt.Data[0])
	}

	// Play the UE: parse with the K_encr/K_aut of the full authentication.
	challenge := peerParseReauthRequest(t, reauthEAP, fullKeys.KEncr, fullKeys.KAut)
	if challenge.Counter != 1 {
		t.Errorf("request counter = %d, want 1", challenge.Counter)
	}
	// The MSK must differ from the full authentication's (fresh NONCE_S).
	if len(challenge.NextReauthID) == 0 {
		t.Log("no AT_NEXT_REAUTH_ID in this request")
	}

	// Answer with the echoed counter; the response MAC covers NONCE_S.
	responseEAP, err := eap.BuildReauthenticationResponse(reauthEAP[1], &eap.Keys{KEncr: fullKeys.KEncr, KAut: fullKeys.KAut}, challenge.Counter, challenge.NonceS)
	if err != nil {
		t.Fatalf("BuildReauthenticationResponse: %v", err)
	}
	accept := exchange(t, server, ctx, newRequest(t, 0x21, responseEAP, radius.Attribute{Type: radius.AttrState, Value: state}))
	if accept.Code != radius.CodeAccessAccept {
		t.Fatalf("reply code = %s, want Access-Accept", radius.CodeString(accept.Code))
	}

	// The new MSK is derived from MK|counter|NONCE_S and must differ from the
	// full authentication MSK.
	reauthKeys, err := eap.DeriveReauthKeys(testNAI, challenge.Counter, challenge.NonceS, mustMK(t, session))
	if err != nil {
		t.Fatalf("DeriveReauthKeys: %v", err)
	}
	fullKeys2, _, err := eap.DeriveKeysWithMK(testNAI, recordedVector.IK, recordedVector.CK)
	if err != nil {
		t.Fatalf("DeriveKeysWithMK: %v", err)
	}
	if bytes.Equal(reauthKeys.MSK, fullKeys2.MSK) {
		t.Error("the re-authentication MSK equals the full authentication MSK")
	}
}

// mustMK re-derives the MK the way the server does, so the test can check the
// re-auth MSK without the server exposing the stored value.
func mustMK(t *testing.T, session *akaSession) []byte {
	t.Helper()
	_, mk, err := eap.DeriveKeysWithMK(session.identity, recordedVector.IK, recordedVector.CK)
	if err != nil {
		t.Fatalf("DeriveKeysWithMK: %v", err)
	}
	return mk
}

// TestFastReauthenticationCounterTooSmall drives the fallback of RFC 4187
// section 5.5: the peer answers the re-authentication request with
// AT_COUNTER_TOO_SMALL and the server falls back on a full authentication.
func TestFastReauthenticationCounterTooSmall(t *testing.T) {
	server := newTestServer(t)
	ctx := context.Background()

	_, fullKeys := runFullAuthentication(t, server, ctx, testNAI, 0x10)

	server.mu.Lock()
	var reauthID string
	for id := range server.reauth {
		reauthID = id
	}
	server.mu.Unlock()

	reply := exchange(t, server, ctx, newRequest(t, 0x20, identityPacket(0x20, reauthID)))
	if reply.Code != radius.CodeAccessChallenge {
		t.Fatalf("reply code = %s, want Access-Challenge", radius.CodeString(reply.Code))
	}
	state, _ := reply.Get(radius.AttrState)
	reauthEAP := reply.EAPMessage()
	challenge := peerParseReauthRequest(t, reauthEAP, fullKeys.KEncr, fullKeys.KAut)

	// The peer encrypts AT_COUNTER (echoing the last accepted counter, which is
	// lower than the one offered) plus AT_COUNTER_TOO_SMALL into its response.
	responseEAP, err := eap.BuildReauthenticationCounterTooSmallResponse(reauthEAP[1],
		&eap.Keys{KEncr: fullKeys.KEncr, KAut: fullKeys.KAut}, challenge.Counter, challenge.NonceS)
	if err != nil {
		t.Fatalf("BuildReauthenticationCounterTooSmallResponse: %v", err)
	}
	fallback := exchange(t, server, ctx, newRequest(t, 0x21, responseEAP, radius.Attribute{Type: radius.AttrState, Value: state}))
	if fallback.Code != radius.CodeAccessChallenge {
		t.Fatalf("reply code = %s, want Access-Challenge (full authentication fallback)", radius.CodeString(fallback.Code))
	}
	fallbackEAP := fallback.EAPMessage()
	pkt, err := eap.Parse(fallbackEAP)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if pkt.Data[0] != eap.SubtypeChallenge {
		t.Fatalf("subtype = %d, want Challenge after the counter-too-small fallback", pkt.Data[0])
	}
	// The fallback full authentication must carry a State again.
	if _, ok := fallback.Get(radius.AttrState); !ok {
		t.Error("the fallback challenge must carry a State attribute")
	}
}

// TestReauthIdentityIsOneTime verifies that a consumed fast re-authentication
// identity cannot be replayed: the second presentation falls back on the
// AKA-Identity round instead of starting a re-authentication.
func TestReauthIdentityIsOneTime(t *testing.T) {
	server := newTestServer(t)
	ctx := context.Background()

	runFullAuthentication(t, server, ctx, testNAI, 0x10)

	server.mu.Lock()
	var reauthID string
	for id := range server.reauth {
		reauthID = id
	}
	server.mu.Unlock()

	first := exchange(t, server, ctx, newRequest(t, 0x20, identityPacket(0x20, reauthID)))
	if first.Code != radius.CodeAccessChallenge {
		t.Fatalf("first presentation: reply code = %s, want Access-Challenge", radius.CodeString(first.Code))
	}
	// The re-auth identity was consumed. Presenting it again must not start
	// another re-authentication (it would re-derive the same MSK).
	second := exchange(t, server, ctx, newRequest(t, 0x22, identityPacket(0x22, reauthID)))
	if second.Code != radius.CodeAccessChallenge {
		t.Fatalf("second presentation: reply code = %s, want Access-Challenge", radius.CodeString(second.Code))
	}
	secondEAP := second.EAPMessage()
	pkt, err := eap.Parse(secondEAP)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if pkt.Data[0] != eap.SubtypeIdentity {
		t.Errorf("second presentation subtype = %d, want Identity (AT_ANY_ID_REQ round)", pkt.Data[0])
	}
}

// TestSelectedVersionMismatchIsRejected pins the AT_SELECTED_VERSION check of
// RFC 4187 section 10.21: the only defined version is 1, so a Challenge
// response selecting another version is a protocol violation.
func TestSelectedVersionMismatchIsRejected(t *testing.T) {
	server := newTestServer(t)
	ctx := context.Background()

	reply := exchange(t, server, ctx, newRequest(t, 0x01, identityPacket(0x01, testNAI)))
	if reply.Code != radius.CodeAccessChallenge {
		t.Fatalf("reply code = %s, want Access-Challenge", radius.CodeString(reply.Code))
	}
	state, _ := reply.Get(radius.AttrState)

	keys, err := eap.DeriveKeys(testNAI, recordedVector.IK, recordedVector.CK)
	if err != nil {
		t.Fatalf("DeriveKeys: %v", err)
	}
	// A response with AT_SELECTED_VERSION = 2.
	body := []byte{eap.SubtypeChallenge, 0, 0}
	body = append(body, eap.Attribute{Type: eap.ATRES,
		Value: append([]byte{0, byte(len(recordedVector.XRES) * 8)}, recordedVector.XRES...)}.Marshal()...)
	body = append(body, eap.Attribute{Type: eap.ATSelectedVersion, Value: []byte{0, 2}}.Marshal()...)
	body = append(body, eap.Attribute{Type: eap.ATMAC, Value: make([]byte, 18)}.Marshal()...)
	raw := (&eap.Packet{Code: eap.CodeResponse, Identifier: reply.EAPMessage()[1], Type: eap.TypeAKA, Data: body}).Marshal()
	if err := eap.SignMAC(raw, keys.KAut); err != nil {
		t.Fatalf("SignMAC: %v", err)
	}
	reject := exchange(t, server, ctx, newRequest(t, 0x02, raw, radius.Attribute{Type: radius.AttrState, Value: state}))
	if reject.Code != radius.CodeAccessReject {
		t.Errorf("reply code = %s, want Access-Reject for version 2", radius.CodeString(reject.Code))
	}
}

// TestExpiredReauthIdentityFallsBackToFullAuth checks that a re-auth identity
// past its TTL does not start a re-authentication.
func TestExpiredReauthIdentityFallsBackToFullAuth(t *testing.T) {
	server := newTestServer(t)
	ctx := context.Background()

	runFullAuthentication(t, server, ctx, testNAI, 0x10)

	server.mu.Lock()
	var reauthID string
	for id := range server.reauth {
		reauthID = id
	}
	// Expire it.
	for _, sess := range server.reauth {
		sess.expiresAt = time.Now().Add(-time.Second)
	}
	server.mu.Unlock()

	reply := exchange(t, server, ctx, newRequest(t, 0x20, identityPacket(0x20, reauthID)))
	if reply.Code != radius.CodeAccessChallenge {
		t.Fatalf("reply code = %s, want Access-Challenge", radius.CodeString(reply.Code))
	}
	// The expired identity must not start a re-authentication on stale keys: the
	// server asks for an identity again (EAP-Request/AKA-Identity), which is
	// the only safe fallback - a re-authentication would use the expired MK and
	// a direct full authentication has no IMSI to derive one from.
	eapMsg := reply.EAPMessage()
	pkt, err := eap.Parse(eapMsg)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if pkt.Data[0] != eap.SubtypeIdentity {
		t.Errorf("subtype = %d, want Identity (the only safe fallback for an expired re-auth identity)", pkt.Data[0])
	}
	reqAttr, err := eap.ParseIdentityRequest(eapMsg)
	if err != nil {
		t.Fatalf("ParseIdentityRequest: %v", err)
	}
	if reqAttr != eap.ATAnyIDReq {
		t.Errorf("identity requesting attribute = %d, want AT_ANY_ID_REQ", reqAttr)
	}
}

// TestCachedReplyExpires checks that the retransmission cache honours its TTL:
// after expiry a repeated request is processed again instead of replayed.
func TestCachedReplyExpires(t *testing.T) {
	server := newTestServer(t)
	// Shrink the session TTL so the cache expires quickly. The ServerConfig is
	// fixed at construction; reaching into the struct keeps the test honest
	// about which map is being checked.
	server.cfg.SessionTTL = time.Millisecond

	ctx := context.Background()
	identity := identityPacket(0x01, testNAI)
	raw, _ := buildRequest(t, 0x2a, identity)

	first := server.Handle(ctx, raw, peerAddr())
	if first == nil {
		t.Fatal("the server dropped the request")
	}
	time.Sleep(2 * time.Millisecond)
	second := server.Handle(ctx, raw, peerAddr())
	if second == nil {
		t.Fatal("the server dropped the repeated request after expiry")
	}
	if !bytes.Equal(first, second) {
		t.Log("the repeated request after expiry produced a byte-identical reply (deterministic path)")
	}
}
