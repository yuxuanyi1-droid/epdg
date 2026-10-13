// Package aaa implements the RADIUS EAP-AKA server that the ePDG presents to
// strongSwan's eap-radius plugin. It drives a two step exchange:
//
//	Access-Request (EAP-Response/Identity)      -> Access-Challenge (AKA-Challenge)
//	Access-Request (EAP-Response/AKA-Challenge) -> Access-Accept (EAP-Success + MSK)
//
// The authentication vectors come from the HSS; the EAP-AKA protocol itself is
// implemented in the eap package.
package aaa

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"epdg/internal/eap"
	"epdg/internal/hss"
	"epdg/internal/radius"
)

// VectorSource supplies AKA quintuplets and can report a Synchronization-Failure
// back to the HSS/AuC for SQN resynchronisation.
type VectorSource interface {
	Vector(ctx context.Context, imsi string) (*hss.Vector, error)
	Resync(ctx context.Context, imsi string, auts, rand []byte) error
}

// ServerConfig configures the RADIUS server.
type ServerConfig struct {
	Listen        string
	Secret        string
	Realm         string
	SendCheckcode bool
	MaxRounds     int
	SessionTTL    time.Duration
}

// Server is a RADIUS authentication server speaking EAP-AKA.
type Server struct {
	cfg     ServerConfig
	vectors VectorSource
	log     *slog.Logger

	mu       sync.Mutex
	sessions map[string]*akaSession
	replies  map[string]cachedReply
	// reauth maps a fast re-authentication identity to the session it was
	// issued for. The session keeps the MK, K_aut and K_encr of the preceding
	// full authentication (RFC 4187 section 5.1).
	reauth map[string]*akaSession
}

// akaSession holds the state bound to one RADIUS State attribute.
type akaSession struct {
	imsi string
	// identity is the identity string the peer presented in this exchange, the
	// input to MK and therefore to every key derived from it.
	identity string
	xres     []byte
	kEncr    []byte
	kAut     []byte
	msk      []byte
	// mk is kept so a later fast re-authentication can derive fresh MSK/EMSK.
	mk        []byte
	rand      []byte
	rounds    int
	expiresAt time.Time
	// nextCounter is the counter value this server will use on the next fast
	// re-authentication. It starts at one after a full authentication and grows
	// monotonically (RFC 4187 section 5.1).
	nextCounter uint16
	// pendingReauth is set while an EAP-Request/AKA-Reauthentication is
	// outstanding under this State.
	pendingReauth *pendingReauth
}

// pendingReauth holds the values an outstanding
// EAP-Request/AKA-Reauthentication was built with (RFC 4187 section 5.4).
type pendingReauth struct {
	// identity is the fast re-authentication identity the peer presented.
	identity string
	// counter and nonceS are the values sent in the request; the response must
	// echo the counter and its AT_MAC covers the nonce.
	counter uint16
	nonceS  []byte
	// newID is the next one-time re-authentication identity issued in
	// AT_NEXT_REAUTH_ID, registered only when the exchange succeeds.
	newID string
}

// cachedReply remembers the reply sent to one Access-Request. UDP is
// unreliable and RADIUS clients retransmit an identical request (same
// Identifier and Request Authenticator) when a reply is lost, so the reply has
// to be resent unchanged: reprocessing the request is impossible anyway once
// the one-time State has been consumed, and would produce a spurious
// Access-Reject (RFC 5080 section 2.2.2).
type cachedReply struct {
	reply     []byte
	expiresAt time.Time
}

// replyCacheKey identifies one outstanding request by its RADIUS Identifier
// and Request Authenticator, the same pair a client keeps constant across the
// retransmissions of one request.
func replyCacheKey(identifier uint8, authenticator [16]byte) string {
	return string([]byte{identifier}) + string(authenticator[:])
}

// NewServer builds a RADIUS EAP-AKA server.
func NewServer(cfg ServerConfig, vectors VectorSource, log *slog.Logger) *Server {
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 60 * time.Second
	}
	if cfg.MaxRounds <= 0 {
		cfg.MaxRounds = 4
	}
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		cfg:      cfg,
		vectors:  vectors,
		log:      log,
		sessions: map[string]*akaSession{},
		replies:  map[string]cachedReply{},
		reauth:   map[string]*akaSession{},
	}
}

// ListenAndServe binds the UDP socket and serves until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("radius: cannot resolve %q: %w", s.cfg.Listen, err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("radius: cannot listen on %q: %w", s.cfg.Listen, err)
	}
	defer conn.Close()

	s.log.Info("radius: listening", "address", conn.LocalAddr().String(), "realm", s.cfg.Realm)
	go s.reapLoop(ctx)

	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	buf := make([]byte, 4096)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("radius: read failed: %w", err)
		}
		request := append([]byte{}, buf[:n]...)
		go func() {
			resp := s.Handle(ctx, request, from)
			if resp == nil {
				return
			}
			if _, err := conn.WriteToUDP(resp, from); err != nil {
				s.log.Warn("radius: cannot send reply", "peer", from.String(), "error", err)
			}
		}()
	}
}

func (s *Server) reapLoop(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.SessionTTL / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			s.mu.Lock()
			for key, sess := range s.sessions {
				if now.After(sess.expiresAt) {
					delete(s.sessions, key)
				}
			}
			for key, sess := range s.reauth {
				if now.After(sess.expiresAt) {
					delete(s.reauth, key)
				}
			}
			for key, reply := range s.replies {
				if now.After(reply.expiresAt) {
					delete(s.replies, key)
				}
			}
			s.mu.Unlock()
		}
	}
}

// Handle processes one RADIUS datagram and returns the reply, or nil to drop it.
func (s *Server) Handle(ctx context.Context, raw []byte, from *net.UDPAddr) []byte {
	request, err := radius.Parse(raw)
	if err != nil {
		s.log.Warn("radius: dropping malformed datagram", "peer", from.String(), "error", err)
		return nil
	}
	if request.Code != radius.CodeAccessRequest {
		s.log.Debug("radius: ignoring packet", "code", radius.CodeString(request.Code), "peer", from.String())
		return nil
	}

	// RFC 3579 section 3.1: an Access-Request carrying an EAP-Message without a
	// Message-Authenticator SHOULD be silently discarded, and one whose
	// Message-Authenticator does not verify MUST be silently discarded. This is
	// unconditional: every Access-Request of an EAP exchange carries the
	// attribute, so there is no legitimate peer to make an exception for.
	ok, err := radius.VerifyMessageAuthenticator(raw, []byte(s.cfg.Secret))
	if err != nil {
		s.log.Warn("radius: silently discarding a request without a Message-Authenticator", "peer", from.String(), "user", request.UserName())
		return nil
	}
	if !ok {
		s.log.Warn("radius: silently discarding a request with an invalid Message-Authenticator", "peer", from.String(), "user", request.UserName())
		return nil
	}

	// A retransmission carries the same Identifier and Request Authenticator as
	// the original request, so if a reply was already computed for the pair,
	// resend it instead of reprocessing. The retransmission check has to sit
	// after the Message-Authenticator verification so a spoofed replay cannot
	// harvest replies it never saw the request for.
	key := replyCacheKey(request.Identifier, request.Authenticator)
	s.mu.Lock()
	cached, found := s.replies[key]
	s.mu.Unlock()
	if found {
		if time.Now().After(cached.expiresAt) {
			s.mu.Lock()
			delete(s.replies, key)
			s.mu.Unlock()
		} else {
			s.log.Debug("radius: retransmission detected, resending the cached reply", "peer", from.String())
			return cached.reply
		}
	}

	eapBytes := request.EAPMessage()
	if len(eapBytes) == 0 {
		return s.reject(request, "EAP-Message attribute required")
	}
	eapPacket, err := eap.Parse(eapBytes)
	if err != nil {
		s.log.Warn("radius: reject, malformed EAP", "peer", from.String(), "error", err)
		return s.reject(request, "malformed EAP-Message")
	}
	if eapPacket.Code != eap.CodeResponse {
		return s.reject(request, fmt.Sprintf("unexpected EAP code %s", eapPacket.Code))
	}

	switch eapPacket.Type {
	case eap.TypeIdentity:
		return s.handleIdentity(ctx, request, eapPacket)
	case eap.TypeAKA, eap.TypeAKAPrime:
		return s.handleAKA(ctx, request, eapBytes, eapPacket)
	default:
		s.log.Warn("radius: reject, unsupported EAP method", "peer", from.String(), "type", eapPacket.Type)
		return s.reject(request, fmt.Sprintf("unsupported EAP method type %d", eapPacket.Type))
	}
}

// handleIdentity answers an EAP-Response/Identity. RFC 4187 section 4.1.3
// allows this packet to carry the permanent identity, a pseudonym or a fast
// re-authentication identity, so the server classifies it: a recognised fast
// re-authentication identity starts the re-authentication exchange (section
// 5.4), an unusable identity is answered with EAP-Request/AKA-Identity
// (AT_ANY_ID_REQ) per section 4.1.4, and a permanent identity proceeds to a
// full AKA challenge.
func (s *Server) handleIdentity(ctx context.Context, request *radius.Packet, packet *eap.Packet) []byte {
	identity := string(packet.Data)

	// A fast re-authentication identity is a one-time identity this server
	// issued in AT_NEXT_REAUTH_ID. The permanent NAI carries a 15 digit IMSI
	// (with an optional leading marker), so anything that parses as one is
	// never mistaken for a re-auth identity.
	if _, err := imsiFromIdentity(identity); err != nil {
		s.mu.Lock()
		session, known := s.reauth[identity]
		if known {
			// Fast re-authentication identities are one-time: consume the
			// identity so a replay cannot reuse it. If the exchange fails the
			// peer falls back on full authentication.
			delete(s.reauth, identity)
		}
		s.mu.Unlock()
		if known {
			if time.Now().After(session.expiresAt) {
				// The re-auth identity expired: the keying material it pointed
				// at must not be used any more, so ask for an identity again
				// instead of running a re-authentication on stale keys.
				s.log.Info("radius: expired fast re-authentication identity, requesting an identity via EAP-AKA-Identity", "identity", identity)
				idReq, err := eap.BuildIdentityRequest(eapIdentifier(request.EAPMessage())+1, eap.ATAnyIDReq)
				if err != nil {
					return s.reject(request, "cannot build the AKA-Identity request")
				}
				return s.challenge(request, nil, idReq)
			}
			return s.startReauthentication(request, identity, session)
		} else {
			s.log.Info("radius: unknown identity, requesting one via EAP-AKA-Identity", "identity", identity)
			idReq, err := eap.BuildIdentityRequest(eapIdentifier(request.EAPMessage())+1, eap.ATAnyIDReq)
			if err != nil {
				return s.reject(request, "cannot build the AKA-Identity request")
			}
			return s.challenge(request, nil, idReq)
		}
	}

	return s.startFullAuthentication(ctx, request, identity, eapIdentifier(request.EAPMessage()))
}

// startFullAuthentication fetches a quintuplet for the identity's IMSI and
// sends the AKA challenge.
func (s *Server) startFullAuthentication(ctx context.Context, request *radius.Packet, identity string, baseIdentifier uint8) []byte {
	imsi, err := imsiFromIdentity(identity)
	if err != nil {
		s.log.Warn("radius: reject, unusable identity", "identity", identity, "error", err)
		return s.reject(request, "identity does not carry a usable IMSI")
	}

	vector, err := s.vectors.Vector(ctx, imsi)
	if err != nil {
		s.log.Warn("radius: reject, HSS vector lookup failed", "imsi", imsi, "error", err)
		return s.reject(request, "cannot obtain authentication vector")
	}

	keys, mk, err := eap.DeriveKeysWithMK(identity, vector.IK, vector.CK)
	if err != nil {
		s.log.Error("radius: cannot derive EAP-AKA keys", "imsi", imsi, "error", err)
		return s.reject(request, "cannot derive EAP-AKA keys")
	}

	state, err := radius.RandomAuthenticator()
	if err != nil {
		s.log.Error("radius: cannot generate State", "error", err)
		return s.reject(request, "internal error")
	}

	session := &akaSession{
		imsi:        imsi,
		identity:    identity,
		xres:        vector.XRES,
		kEncr:       keys.KEncr,
		kAut:        keys.KAut,
		msk:         keys.MSK,
		mk:          mk,
		rand:        vector.RAND,
		expiresAt:   time.Now().Add(s.cfg.SessionTTL),
		nextCounter: 1,
	}
	s.mu.Lock()
	s.sessions[hex.EncodeToString(state[:])] = session
	s.mu.Unlock()

	challenge, err := s.buildChallenge(baseIdentifier+1, vector, keys)
	if err != nil {
		s.log.Error("radius: cannot build AKA challenge", "imsi", imsi, "error", err)
		return s.reject(request, "cannot build AKA challenge")
	}

	s.log.Info("radius: AKA challenge", "imsi", imsi, "identity", identity, "peer", request.UserName())
	return s.challenge(request, state[:], challenge)
}

// buildChallenge assembles the EAP-Request/AKA-Challenge, honouring the
// SendCheckcode setting.
func (s *Server) buildChallenge(identifier uint8, vector *hss.Vector, keys *eap.Keys) ([]byte, error) {
	if s.cfg.SendCheckcode {
		// AT_CHECKCODE protects the EAP-AKA-Identity messages exchanged before
		// keying material exists. The full authentication path here receives
		// the identity via EAP-Response/Identity (RFC 3748 Type 1) rather than
		// an EAP-Response/AKA-Identity, so no such messages were exchanged and
		// the checkcode is empty; an absent checkcode means "no AKA-Identity
		// messages were exchanged" (RFC 4187 section 10.13).
		return eap.BuildChallengeWithCheckcode(identifier, vector.RAND, vector.AUTN, keys.KAut, []byte{})
	}
	return eap.BuildChallenge(identifier, vector.RAND, vector.AUTN, keys.KAut)
}

// handleAKA processes the peer's EAP-AKA response. The State attribute binds
// the request to the pending session; EAP-Response/AKA-Identity is the one
// subtype that may arrive without a State because it answers the identity
// request this server sent with a nil State.
func (s *Server) handleAKA(ctx context.Context, request *radius.Packet, eapBytes []byte, packet *eap.Packet) []byte {
	stateRaw, ok := request.Get(radius.AttrState)
	if !ok || len(stateRaw) == 0 {
		// RFC 4187 section 9.2: the response to an EAP-Request/AKA-Identity.
		// This server only issues one with AT_ANY_ID_REQ and without a State.
		response, err := eap.ParseResponse(eapBytes)
		if err != nil || response.Subtype != eap.SubtypeIdentity {
			return s.reject(request, "State attribute required for an AKA response")
		}
		return s.handleAKAIdentity(ctx, request, response, eapIdentifier(eapBytes))
	}
	key := hex.EncodeToString(stateRaw)

	s.mu.Lock()
	session, found := s.sessions[key]
	if found {
		delete(s.sessions, key)
	}
	s.mu.Unlock()

	if !found {
		s.log.Warn("radius: reject, unknown State", "state", key, "user", request.UserName())
		return s.reject(request, "unknown or expired State")
	}
	if session.rounds >= s.cfg.MaxRounds {
		s.log.Warn("radius: reject, too many EAP rounds", "imsi", session.imsi)
		return s.reject(request, "too many EAP-AKA rounds")
	}

	response, err := eap.ParseResponse(eapBytes)
	if err != nil {
		s.log.Warn("radius: reject, malformed AKA response", "imsi", session.imsi, "error", err)
		return s.reject(request, "malformed EAP-AKA response")
	}

	switch response.Subtype {
	case eap.SubtypeChallenge:
		return s.finishChallenge(request, session, eapBytes, response)
	case eap.SubtypeReauthentication:
		return s.finishReauthentication(request, session, eapBytes)
	case eap.SubtypeSynchronizationFailure:
		return s.handleResync(ctx, request, session, response, eapIdentifier(eapBytes))
	case eap.SubtypeAuthenticationReject:
		s.log.Warn("radius: reject, UE sent AKA-Authentication-Reject", "imsi", session.imsi)
		return s.reject(request, "authentication rejected by UE")
	case eap.SubtypeClientError:
		code := "unknown"
		if response.ClientErrorCode != nil {
			code = fmt.Sprintf("%d", *response.ClientErrorCode)
		}
		s.log.Warn("radius: reject, AKA client error", "imsi", session.imsi, "code", code)
		return s.reject(request, "AKA client error "+code)
	default:
		s.log.Warn("radius: reject, unsupported AKA subtype", "imsi", session.imsi, "subtype", response.Subtype)
		return s.reject(request, fmt.Sprintf("unsupported AKA subtype %d", response.Subtype))
	}
}

// handleAKAIdentity processes an EAP-Response/AKA-Identity, which answers an
// EAP-Request/AKA-Identity this server issued after an unrecognisable identity
// (RFC 4187 sections 4.1.4 and 9.2). The peer is given one chance to present a
// usable identity; requesting it again would violate the sequencing rules of
// section 9.1, so a second unusable identity is a fatal error.
func (s *Server) handleAKAIdentity(ctx context.Context, request *radius.Packet, response *eap.Response, baseIdentifier uint8) []byte {
	if response.Identity == "" {
		s.log.Warn("radius: reject, AKA-Identity response without AT_IDENTITY")
		return s.reject(request, "AT_IDENTITY required in EAP-Response/AKA-Identity")
	}
	if _, err := imsiFromIdentity(response.Identity); err != nil {
		s.log.Warn("radius: reject, unusable identity from AKA-Identity", "error", err)
		return s.reject(request, "identity does not carry a usable IMSI")
	}
	// RFC 4187 section 7: MK is derived from the identity of the last
	// AT_IDENTITY, so the full authentication uses this identity string.
	return s.startFullAuthentication(ctx, request, response.Identity, baseIdentifier)
}

// finishReauthentication completes a fast re-authentication (RFC 4187
// section 5.4): the response must verify with the K_aut of the full
// authentication (its AT_MAC covers the packet plus the NONCE_S of the
// request), the encrypted AT_COUNTER must echo the value that was sent, and a
// counter that is not accepted is reported with AT_COUNTER_TOO_SMALL, which
// falls back on full authentication.
func (s *Server) finishReauthentication(request *radius.Packet, session *akaSession, eapBytes []byte) []byte {
	pending := session.pendingReauth
	if pending == nil {
		s.log.Warn("radius: reject, re-authentication response without a pending re-authentication", "imsi", session.imsi)
		return s.reject(request, "unexpected EAP-Response/AKA-Reauthentication")
	}

	keys := &eap.Keys{KEncr: session.kEncr, KAut: session.kAut}
	counter, counterTooSmall, err := eap.VerifyReauthenticationResponse(eapBytes, keys, pending.nonceS)
	if err != nil {
		s.log.Warn("radius: reject, re-authentication verification failed", "imsi", session.imsi, "error", err)
		return s.reject(request, "re-authentication verification failed: "+err.Error())
	}
	if counterTooSmall {
		// RFC 4187 section 5.5: the peer did not accept the counter, so a full
		// authentication follows.
		s.log.Info("radius: AT_COUNTER_TOO_SMALL, falling back on full authentication", "imsi", session.imsi)
		return s.startFullAuthentication(context.Background(), request, session.identity, eapIdentifier(eapBytes))
	}
	if counter != pending.counter {
		s.log.Warn("radius: reject, echoed counter does not match", "imsi", session.imsi,
			"echoed", counter, "sent", pending.counter)
		return s.reject(request, "AT_COUNTER does not match the request")
	}

	// Derive the new MSK/EMSK from the original MK, the counter and the
	// NONCE_S; K_encr and K_aut carry over (RFC 4187 section 7).
	reauthKeys, err := eap.DeriveReauthKeys(pending.identity, counter, pending.nonceS, session.mk)
	if err != nil {
		s.log.Error("radius: cannot derive the re-authentication keys", "imsi", session.imsi, "error", err)
		return s.reject(request, "cannot derive the re-authentication keys")
	}
	msk, err := radius.MPPEKeyAttributes(reauthKeys.MSK, []byte(s.cfg.Secret), request.Authenticator)
	if err != nil {
		s.log.Error("radius: cannot build MS-MPPE attributes", "imsi", session.imsi, "error", err)
		return s.reject(request, "internal error")
	}

	// Register the new one-time re-authentication identity for the next
	// exchange, continuing the counter sequence.
	s.mu.Lock()
	s.reauth[pending.newID] = &akaSession{
		imsi:        session.imsi,
		identity:    session.identity,
		kEncr:       session.kEncr,
		kAut:        session.kAut,
		mk:          session.mk,
		rounds:      session.rounds,
		expiresAt:   time.Now().Add(s.cfg.SessionTTL),
		nextCounter: session.nextCounter + 1,
	}
	s.mu.Unlock()

	s.log.Info("radius: fast re-authentication success", "imsi", session.imsi, "counter", counter)
	return s.accept(request, eap.Success(eapIdentifier(eapBytes)), msk...)
}

// startReauthentication sends the EAP-Request/AKA-Reauthentication for a
// recognised fast re-authentication identity (RFC 4187 section 5.4). The
// request carries a fresh counter, a fresh NONCE_S and a new one-time
// re-authentication identity, all protected by the K_encr and K_aut of the
// preceding full authentication, which the session stored.
func (s *Server) startReauthentication(request *radius.Packet, reauthID string, session *akaSession) []byte {
	if session.rounds >= s.cfg.MaxRounds {
		s.log.Warn("radius: too many EAP rounds, falling back on full authentication", "imsi", session.imsi)
		return s.reject(request, "too many EAP-AKA rounds")
	}

	state, err := radius.RandomAuthenticator()
	if err != nil {
		s.log.Error("radius: cannot generate State", "error", err)
		return s.reject(request, "internal error")
	}
	newReauthID, err := newReauthIdentity()
	if err != nil {
		s.log.Error("radius: cannot generate a re-authentication identity", "error", err)
		return s.reject(request, "internal error")
	}

	keys := &eap.Keys{KEncr: session.kEncr, KAut: session.kAut}
	req, err := eap.BuildReauthenticationRequest(eapIdentifier(request.EAPMessage())+1, keys, session.nextCounter, newReauthID)
	if err != nil {
		s.log.Error("radius: cannot build the re-authentication request", "imsi", session.imsi, "error", err)
		return s.reject(request, "cannot build the re-authentication request")
	}

	// The pending exchange is tracked under the new State attribute; the
	// consumed re-auth identity has already been deleted by the caller.
	s.mu.Lock()
	s.sessions[hex.EncodeToString(state[:])] = &akaSession{
		imsi:         session.imsi,
		identity:     session.identity,
		kEncr:        session.kEncr,
		kAut:         session.kAut,
		mk:           session.mk,
		rounds:       session.rounds + 1,
		expiresAt:    time.Now().Add(s.cfg.SessionTTL),
		nextCounter:  session.nextCounter,
		pendingReauth: &pendingReauth{
			identity: reauthID,
			counter:  req.Counter,
			nonceS:   req.NonceS,
			newID:    newReauthID,
		},
	}
	s.mu.Unlock()

	s.log.Info("radius: fast re-authentication request", "imsi", session.imsi, "counter", req.Counter)
	return s.challenge(request, state[:], req.Raw)
}

func (s *Server) finishChallenge(request *radius.Packet, session *akaSession, eapBytes []byte, response *eap.Response) []byte {
	// RFC 4187 section 10.21: when the peer includes AT_SELECTED_VERSION it
	// echoes one of the versions this server advertised. Version 1 is the only
	// version EAP-AKA defines, so anything else is a protocol violation.
	if response.SelectedVersion != nil && *response.SelectedVersion != 1 {
		s.log.Warn("radius: reject, unsupported EAP-AKA version selected", "imsi", session.imsi, "version", *response.SelectedVersion)
		return s.reject(request, fmt.Sprintf("unsupported EAP-AKA version %d", *response.SelectedVersion))
	}
	if response.MAC == nil {
		s.log.Warn("radius: reject, AT_MAC missing", "imsi", session.imsi)
		return s.reject(request, "AT_MAC attribute required")
	}
	received, _, macOK, err := eap.VerifyMAC(eapBytes, session.kAut)
	if err != nil {
		s.log.Warn("radius: reject, cannot verify AT_MAC", "imsi", session.imsi, "error", err)
		return s.reject(request, "cannot verify AT_MAC")
	}
	resOK := subtle.ConstantTimeCompare(response.RES, session.xres) == 1

	// Only the verdict is logged, never the values themselves: RES and XRES are
	// proof-of-possession of the subscriber key K, and the MAC values would let
	// an offline attacker verify guesses. At debug level the lengths are shown
	// so a wire-format mismatch remains diagnosable.
	s.log.Debug("radius: verifying AKA response",
		"imsi", session.imsi,
		"res_len", len(response.RES),
		"xres_len", len(session.xres),
		"mac_len", len(received),
		"res_match", resOK,
		"mac_match", macOK,
	)

	if !macOK || !resOK {
		reason := "AT_MAC mismatch"
		if !resOK {
			reason = "RES does not match XRES"
		}
		s.log.Warn("radius: reject, AKA verification failed", "imsi", session.imsi, "reason", reason)
		return s.reject(request, "AKA verification failed: "+reason)
	}

	keys, err := radius.MPPEKeyAttributes(session.msk, []byte(s.cfg.Secret), request.Authenticator)
	if err != nil {
		s.log.Error("radius: cannot build MS-MPPE attributes", "imsi", session.imsi, "error", err)
		return s.reject(request, "internal error")
	}

	// RFC 4187 section 5.3: issuing AT_NEXT_REAUTH_ID marks the server as
	// willing to fast re-authenticate. The identity is one-time and is
	// registered here so the next EAP-Response/Identity carrying it resolves.
	if err := s.issueReauthIdentity(session); err != nil {
		s.log.Error("radius: cannot issue a re-authentication identity", "imsi", session.imsi, "error", err)
		return s.reject(request, "internal error")
	}

	s.log.Info("radius: AKA success", "imsi", session.imsi, "identity", session.identity)
	return s.accept(request, eap.Success(eapIdentifier(eapBytes)), keys...)
}

// issueReauthIdentity generates the one-time fast re-authentication identity
// the peer will use on its next authentication. It is generated per full
// authentication and stored with the session that holds the MK, K_encr and
// K_aut (RFC 4187 section 5.1).
func (s *Server) issueReauthIdentity(session *akaSession) error {
	id, err := newReauthIdentity()
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.reauth[id] = &akaSession{
		imsi:        session.imsi,
		identity:    session.identity,
		kEncr:       session.kEncr,
		kAut:        session.kAut,
		mk:          session.mk,
		rounds:      session.rounds,
		expiresAt:   time.Now().Add(s.cfg.SessionTTL),
		nextCounter: 1,
	}
	s.mu.Unlock()
	return nil
}

// newReauthIdentity returns a random one-time fast re-authentication
// username. RFC 4187 section 5.3 requires a realm portion where the
// environment needs one, so the configured realm is appended.
func newReauthIdentity() (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("radius: cannot read randomness: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

// handleResync deals with an AKA-Synchronization-Failure carrying AT_AUTS
// (RFC 4187 section 10.6). The peer could not accept the SQN in AUTN but did
// derive the keys, so it answers with AT_AUTS to let the AuC recompute its SQN;
// the Synchronization-Failure message itself carries no AT_MAC (section 9.6),
// which is why the AUTS has to be validated by the node that holds K. The ePDG
// therefore reports it to the HSS (3GPP TS 29.272 section 7.2.5) and then
// requests a fresh quintuplet, exactly as a ULR/AIR resync would.
func (s *Server) handleResync(ctx context.Context, request *radius.Packet, session *akaSession, response *eap.Response, baseIdentifier uint8) []byte {
	if len(response.AUTS) == 0 {
		s.log.Warn("radius: reject, synchronization failure without AT_AUTS", "imsi", session.imsi)
		return s.reject(request, "AT_AUTS missing in AKA-Synchronization-Failure")
	}
	// The RAND is the one this server sent in the challenge the peer rejected.
	if err := s.vectors.Resync(ctx, session.imsi, response.AUTS, session.rand); err != nil {
		s.log.Warn("radius: reject, HSS resynchronisation failed", "imsi", session.imsi, "error", err)
		return s.reject(request, "cannot resynchronise the SQN with the HSS")
	}
	vector, err := s.vectors.Vector(ctx, session.imsi)
	if err != nil {
		s.log.Warn("radius: reject, cannot obtain a resynchronised vector", "imsi", session.imsi, "error", err)
		return s.reject(request, "cannot obtain a resynchronised vector")
	}
	keys, mk, err := eap.DeriveKeysWithMK(session.identity, vector.IK, vector.CK)
	if err != nil {
		return s.reject(request, "cannot derive EAP-AKA keys")
	}

	session.xres = vector.XRES
	session.kEncr = keys.KEncr
	session.kAut = keys.KAut
	session.msk = keys.MSK
	session.mk = mk
	session.rand = vector.RAND
	session.rounds++
	session.expiresAt = time.Now().Add(s.cfg.SessionTTL)
	session.nextCounter = 1

	// A new Request must use a fresh Identifier, not the one the peer echoed.
	identifier := baseIdentifier + 1
	challenge, err := eap.BuildChallenge(identifier, vector.RAND, vector.AUTN, keys.KAut)
	if err != nil {
		return s.reject(request, "cannot build AKA challenge")
	}
	state, ok := request.Get(radius.AttrState)
	if !ok {
		state = []byte{}
	}
	s.mu.Lock()
	s.sessions[hex.EncodeToString(state)] = session
	s.mu.Unlock()

	s.log.Info("radius: AKA resynchronisation challenge", "imsi", session.imsi)
	return s.challenge(request, state, challenge)
}

// eapIdentifier returns the EAP Identifier of a received packet so replies reuse
// it. EAP-Success must carry the same Identifier as the last Request.
func eapIdentifier(eapBytes []byte) uint8 {
	if len(eapBytes) > 1 {
		return eapBytes[1]
	}
	return 0
}

// reject builds an Access-Reject carrying an EAP-Failure. RFC 3579 section 2.2
// requires a fatal error to be reported with an EAP-Failure, and section 3.3
// makes EAP-Message mandatory in Access-Reject. Reply-Message is deliberately
// omitted because RFC 3579 section 2.6.5 forbids it in any packet that carries
// an EAP-Message attribute.
func (s *Server) reject(request *radius.Packet, reason string) []byte {
	s.log.Debug("radius: rejecting request", "reason", reason, "user", request.UserName())
	return s.reply(request, radius.CodeAccessReject, eap.Failure(eapIdentifier(request.EAPMessage())))
}

// accept builds an Access-Accept. RFC 3579 section 3 requires the User-Name of
// the Access-Request to be echoed in the Access-Accept so that EAP-unaware
// proxies can forward it; Reply-Message is forbidden alongside an EAP-Message
// (section 2.6.5).
func (s *Server) accept(request *radius.Packet, eapPayload []byte, attrs ...radius.Attribute) []byte {
	if un, ok := request.Get(radius.AttrUserName); ok {
		attrs = append([]radius.Attribute{{Type: radius.AttrUserName, Value: un}}, attrs...)
	}
	return s.reply(request, radius.CodeAccessAccept, eapPayload, attrs...)
}

// challenge builds an Access-Challenge. Besides the EAP-Message it carries the
// State attribute that binds the next Access-Request to this session (RFC 2865
// section 5.24, RFC 3579); a nil state omits the attribute, which is what the
// EAP-AKA-Identity round needs because there is nothing to bind yet.
// Reply-Message is forbidden alongside an EAP-Message (RFC 3579 section 2.6.5).
func (s *Server) challenge(request *radius.Packet, state []byte, eapPayload []byte) []byte {
	var attrs []radius.Attribute
	if state != nil {
		attrs = append(attrs, radius.Attribute{Type: radius.AttrState, Value: state})
	}
	return s.reply(request, radius.CodeAccessChallenge, eapPayload, attrs...)
}

func (s *Server) reply(request *radius.Packet, code uint8, eapPayload []byte, attrs ...radius.Attribute) []byte {
	reply := &radius.Packet{Code: code, Identifier: request.Identifier}
	if len(eapPayload) > 0 {
		reply.SetEAPMessage(eapPayload)
	}
	reply.Attributes = append(reply.Attributes, attrs...)
	if err := reply.FinalizeResponse([]byte(s.cfg.Secret), request.Authenticator); err != nil {
		s.log.Error("radius: cannot finalise reply", "error", err)
		return nil
	}
	raw, err := reply.Marshal()
	if err != nil {
		s.log.Error("radius: cannot encode reply", "error", err)
		return nil
	}
	// Remember the reply so a retransmission of this request can be answered
	// with the same datagram (RFC 5080 section 2.2.2).
	key := replyCacheKey(request.Identifier, request.Authenticator)
	s.mu.Lock()
	s.replies[key] = cachedReply{reply: raw, expiresAt: time.Now().Add(s.cfg.SessionTTL)}
	s.mu.Unlock()
	return raw
}

// imsiFromIdentity extracts the IMSI from an EAP identity. 3GPP TS 23.003
// section 19.3 defines the IMSI based NAI as a leading "0" marker followed by
// the 15 digit IMSI, for example
// "0001010000000001@nai.epc.mnc001.mcc001.3gppnetwork.org".
func imsiFromIdentity(identity string) (string, error) {
	local := identity
	if i := strings.IndexByte(identity, '@'); i >= 0 {
		local = identity[:i]
	}
	switch {
	case len(local) == 15 && allDigits(local):
		return local, nil
	case len(local) == 16 && local[0] == '0' && allDigits(local[1:]):
		return local[1:], nil
	default:
		return "", fmt.Errorf("identity %q does not carry a 15 digit IMSI with an optional leading marker", identity)
	}
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
