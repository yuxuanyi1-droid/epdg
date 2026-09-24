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

// VectorSource supplies AKA quintuplets.
type VectorSource interface {
	Vector(ctx context.Context, imsi string) (*hss.Vector, error)
}

// ServerConfig configures the RADIUS server.
type ServerConfig struct {
	Listen                      string
	Secret                      string
	Realm                       string
	RequireMessageAuthenticator bool
	SendCheckcode               bool
	MaxRounds                   int
	SessionTTL                  time.Duration
}

// Server is a RADIUS authentication server speaking EAP-AKA.
type Server struct {
	cfg     ServerConfig
	vectors VectorSource
	log     *slog.Logger

	mu       sync.Mutex
	sessions map[string]*akaSession
}

// akaSession holds the state bound to one RADIUS State attribute.
type akaSession struct {
	imsi      string
	identity  string
	xres      []byte
	kAut      []byte
	msk       []byte
	rand      []byte
	rounds    int
	expiresAt time.Time
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
	return &Server{cfg: cfg, vectors: vectors, log: log, sessions: map[string]*akaSession{}}
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

	if s.cfg.RequireMessageAuthenticator {
		ok, err := radius.VerifyMessageAuthenticator(raw, []byte(s.cfg.Secret))
		if err != nil {
			s.log.Warn("radius: reject, Message-Authenticator missing", "peer", from.String(), "user", request.UserName())
			return s.reject(request, "Message-Authenticator attribute required")
		}
		if !ok {
			s.log.Warn("radius: reject, Message-Authenticator invalid", "peer", from.String(), "user", request.UserName())
			return s.reject(request, "Message-Authenticator verification failed")
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

// handleIdentity answers an EAP-Response/Identity with an AKA challenge.
func (s *Server) handleIdentity(ctx context.Context, request *radius.Packet, packet *eap.Packet) []byte {
	identity := string(packet.Data)
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

	keys, err := eap.DeriveKeys(identity, vector.IK, vector.CK)
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
		imsi:      imsi,
		identity:  identity,
		xres:      vector.XRES,
		kAut:      keys.KAut,
		msk:       keys.MSK,
		rand:      vector.RAND,
		expiresAt: time.Now().Add(s.cfg.SessionTTL),
	}
	s.mu.Lock()
	s.sessions[hex.EncodeToString(state[:])] = session
	s.mu.Unlock()

	identifier := packet.Identifier + 1
	var challenge []byte
	if s.cfg.SendCheckcode {
		challenge, err = eap.BuildChallengeWithCheckcode(identifier, vector.RAND, vector.AUTN, keys.KAut, nil)
	} else {
		challenge, err = eap.BuildChallenge(identifier, vector.RAND, vector.AUTN, keys.KAut)
	}
	if err != nil {
		s.log.Error("radius: cannot build AKA challenge", "imsi", imsi, "error", err)
		return s.reject(request, "cannot build AKA challenge")
	}

	s.log.Info("radius: AKA challenge", "imsi", imsi, "identity", identity, "peer", request.UserName())
	return s.challenge(request, state[:], challenge, "aka challenge")
}

// handleAKA processes the peer's EAP-AKA response.
func (s *Server) handleAKA(ctx context.Context, request *radius.Packet, eapBytes []byte, packet *eap.Packet) []byte {
	stateRaw, ok := request.Get(radius.AttrState)
	if !ok || len(stateRaw) == 0 {
		return s.reject(request, "State attribute required for an AKA response")
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
	case eap.SubtypeSynchronizationFailure:
		return s.handleResync(ctx, request, session, response)
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

func (s *Server) finishChallenge(request *radius.Packet, session *akaSession, eapBytes []byte, response *eap.Response) []byte {
	if response.MAC == nil {
		s.log.Warn("radius: reject, AT_MAC missing", "imsi", session.imsi)
		return s.reject(request, "AT_MAC attribute required")
	}
	received, expected, macOK, err := eap.VerifyMAC(eapBytes, session.kAut)
	if err != nil {
		s.log.Warn("radius: reject, cannot verify AT_MAC", "imsi", session.imsi, "error", err)
		return s.reject(request, "cannot verify AT_MAC")
	}
	resOK := bytesEqual(response.RES, session.xres)

	s.log.Info("radius: verifying AKA response",
		"imsi", session.imsi,
		"res", hex.EncodeToString(response.RES),
		"xres", hex.EncodeToString(session.xres),
		"mac_received", hex.EncodeToString(received),
		"mac_expected", hex.EncodeToString(expected),
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
	attrs := append([]radius.Attribute{
		{Type: radius.AttrReplyMessage, Value: []byte("aka success")},
	}, keys...)

	s.log.Info("radius: AKA success", "imsi", session.imsi, "identity", session.identity)
	return s.accept(request, eap.Success(eapIdentifier(eapBytes)), attrs...)
}

// handleResync deals with an AKA-Synchronization-Failure carrying AT_AUTS. PyHSS
// advances SQN whenever it issues a vector, so requesting a fresh quintuplet is
// enough to resynchronise the UE.
func (s *Server) handleResync(ctx context.Context, request *radius.Packet, session *akaSession, response *eap.Response) []byte {
	if len(response.AUTS) == 0 {
		s.log.Warn("radius: reject, synchronization failure without AT_AUTS", "imsi", session.imsi)
		return s.reject(request, "AT_AUTS missing in AKA-Synchronization-Failure")
	}
	vector, err := s.vectors.Vector(ctx, session.imsi)
	if err != nil {
		s.log.Warn("radius: reject, cannot obtain a resynchronised vector", "imsi", session.imsi, "error", err)
		return s.reject(request, "cannot obtain a resynchronised vector")
	}
	keys, err := eap.DeriveKeys(session.identity, vector.IK, vector.CK)
	if err != nil {
		return s.reject(request, "cannot derive EAP-AKA keys")
	}

	session.xres = vector.XRES
	session.kAut = keys.KAut
	session.msk = keys.MSK
	session.rand = vector.RAND
	session.rounds++
	session.expiresAt = time.Now().Add(s.cfg.SessionTTL)

	identifier := eapIdentifier(nil)
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
	return s.challenge(request, state, challenge, "aka challenge resync")
}

// eapIdentifier returns the EAP Identifier of a received packet so replies reuse
// it. EAP-Success must carry the same Identifier as the last Request.
func eapIdentifier(eapBytes []byte) uint8 {
	if len(eapBytes) > 1 {
		return eapBytes[1]
	}
	return 0
}

func (s *Server) reject(request *radius.Packet, reason string) []byte {
	attrs := []radius.Attribute{{Type: radius.AttrReplyMessage, Value: []byte(reason)}}
	return s.reply(request, radius.CodeAccessReject, nil, attrs...)
}

func (s *Server) accept(request *radius.Packet, eapPayload []byte, attrs ...radius.Attribute) []byte {
	return s.reply(request, radius.CodeAccessAccept, eapPayload, attrs...)
}

func (s *Server) challenge(request *radius.Packet, state []byte, eapPayload []byte, reason string) []byte {
	attrs := []radius.Attribute{
		{Type: radius.AttrState, Value: state},
		{Type: radius.AttrReplyMessage, Value: []byte(reason)},
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

func bytesEqual(a, b []byte) bool {
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
