package swmaaa

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"epdg-go/internal/diameter"
)

const (
	eapCodeRequest  = 1
	eapCodeResponse = 2
	eapCodeSuccess  = 3

	eapTypeIdentity = 1
	eapTypeAKA      = 23
	eapTypeAKAPrime = 50
)

type sessionState struct {
	IMSI      string
	UpdatedAt time.Time
	Stage     int
}

type Handler struct {
	cfg      *Config
	logger   *log.Logger
	mu       sync.Mutex
	sessions map[string]sessionState
	allowed  map[string]struct{}
}

func NewHandler(cfg *Config, logger *log.Logger) *Handler {
	allowed := make(map[string]struct{}, len(cfg.AllowedIMSIs))
	for _, imsi := range cfg.AllowedIMSIs {
		imsi = strings.TrimSpace(imsi)
		if imsi != "" {
			allowed[imsi] = struct{}{}
		}
	}
	if logger == nil {
		logger = log.Default()
	}
	return &Handler{
		cfg:      cfg,
		logger:   logger,
		sessions: map[string]sessionState{},
		allowed:  allowed,
	}
}

func (h *Handler) Handle(msg diameter.Message) (diameter.Message, bool, error) {
	if !msg.IsRequest || msg.CommandCode != diameter.CommandDiameterEAP() {
		return diameter.Message{}, false, nil
	}
	sessionID, _ := msg.AVPString(diameter.AVPSessionID())
	imsi, _ := msg.AVPString(diameter.AVPUserName())
	if sessionID == "" {
		return diameter.Message{}, true, fmt.Errorf("missing Session-Id")
	}
	if imsi == "" {
		return h.newDEA(msg, sessionID, "", diameter.ResultMultiRoundAuth(), buildEAPFailureLikeRequest(msg)), true, nil
	}
	if !h.isAllowed(imsi) {
		return h.newDEA(msg, sessionID, imsi, 4001, nil), true, nil
	}

	eapPayload, _ := msg.AVPBytes(diameter.AVPEAPPayload())
	now := time.Now()

	h.mu.Lock()
	defer h.mu.Unlock()
	h.gcLocked(now)

	state := h.sessions[sessionID]
	state.IMSI = imsi
	state.UpdatedAt = now

	if state.Stage == 0 {
		state.Stage = 1
		h.sessions[sessionID] = state
		h.logger.Printf("swm auth stage1 imsi=%s session=%s", imsi, sessionID)
		return h.newDEA(msg, sessionID, imsi, diameter.ResultMultiRoundAuth(), buildAKAIdentityRequest(msg, imsi)), true, nil
	}

	if !isEAPResponse(eapPayload) {
		h.logger.Printf("swm auth invalid eap response imsi=%s session=%s", imsi, sessionID)
		delete(h.sessions, sessionID)
		return h.newDEA(msg, sessionID, imsi, 4001, nil), true, nil
	}

	delete(h.sessions, sessionID)
	h.logger.Printf("swm auth success imsi=%s session=%s", imsi, sessionID)
	return h.newDEA(msg, sessionID, imsi, diameter.ResultSuccess(), buildEAPSuccess(msg)), true, nil
}

func (h *Handler) isAllowed(imsi string) bool {
	if h.cfg.AllowUnknown || len(h.allowed) == 0 {
		return true
	}
	_, ok := h.allowed[imsi]
	return ok
}

func (h *Handler) gcLocked(now time.Time) {
	for sessionID, state := range h.sessions {
		if now.Sub(state.UpdatedAt) > h.cfg.SessionTimeout {
			delete(h.sessions, sessionID)
		}
	}
}

func (h *Handler) newDEA(req diameter.Message, sessionID, imsi string, result uint32, eapPayload []byte) diameter.Message {
	originHost := h.cfg.OriginHost
	originRealm := h.cfg.OriginRealm
	avps := []diameter.AVP{
		diameter.NewUTF8AVP(diameter.AVPSessionID(), true, sessionID),
		diameter.NewUnsigned32AVP(diameter.AVPAuthApplicationID(), true, diameter.ApplicationEAP()),
		diameter.NewUnsigned32AVP(diameter.AVPResultCode(), true, result),
		diameter.NewUTF8AVP(diameter.AVPOriginHost(), true, originHost),
		diameter.NewUTF8AVP(diameter.AVPOriginRealm(), true, originRealm),
	}
	if imsi != "" {
		avps = append(avps, diameter.NewUTF8AVP(diameter.AVPUserName(), false, imsi))
	}
	if len(eapPayload) > 0 {
		avps = append(avps, diameter.NewOctetsAVP(diameter.AVPEAPPayload(), false, eapPayload))
	}
	return diameter.Message{
		CommandCode: diameter.CommandDiameterEAP(),
		Application: diameter.ApplicationEAP(),
		HopByHop:    req.HopByHop,
		EndToEnd:    req.EndToEnd,
		IsRequest:   false,
		AVPs:        avps,
	}
}

func buildAKAIdentityRequest(req diameter.Message, imsi string) []byte {
	identifier := byte(1)
	if payload, ok := req.AVPBytes(diameter.AVPEAPPayload()); ok && len(payload) > 1 {
		identifier = payload[1]
	}
	return []byte{
		eapCodeRequest,
		identifier,
		0x00, 0x08,
		eapTypeAKAPrime,
		0x05,
		0x00, 0x00,
	}
}

func buildEAPSuccess(req diameter.Message) []byte {
	identifier := byte(1)
	if payload, ok := req.AVPBytes(diameter.AVPEAPPayload()); ok && len(payload) > 1 {
		identifier = payload[1]
	}
	return []byte{eapCodeSuccess, identifier, 0x00, 0x04}
}

func buildEAPFailureLikeRequest(req diameter.Message) []byte {
	identifier := byte(1)
	if payload, ok := req.AVPBytes(diameter.AVPEAPPayload()); ok && len(payload) > 1 {
		identifier = payload[1]
	}
	return []byte{eapCodeRequest, identifier, 0x00, 0x05, eapTypeIdentity}
}

func isEAPResponse(payload []byte) bool {
	return len(payload) >= 4 && payload[0] == eapCodeResponse
}
