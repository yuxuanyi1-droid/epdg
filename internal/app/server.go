package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"epdg-go/internal/aaa"
	"epdg-go/internal/compliance"
	"epdg-go/internal/config"
	"epdg-go/internal/diameter"
	"epdg-go/internal/ipsec"
	"epdg-go/internal/s2b"
	"epdg-go/internal/session"
)

type Server struct {
	cfg      *config.Config
	sessions *session.Store
	aaa      aaa.Client
	ipsec    ipsec.Backend
	s2b      s2b.Client
	mux      *http.ServeMux
	checker  *compliance.Checker
}

type SessionRequest struct {
	UEID string `json:"ue_id"`
	IMSI string `json:"imsi"`
	APN  string `json:"apn"`
}

func NewServer(cfg *config.Config) (*http.Server, error) {
	ipsecBackend := ipsec.Backend(ipsec.NoopBackend{})
	switch cfg.IPSec.Backend {
	case "swanctl":
		ipsecBackend = ipsec.SwanctlBackend{
			Binary:         cfg.IPSec.SwanctlBin,
			Mode:           cfg.IPSec.Mode,
			ConnectionName: cfg.IPSec.ConnectionName,
			ChildPrefix:    cfg.IPSec.ChildPrefix,
			ChildName:      cfg.IPSec.ChildName,
		}
	case "noop":
		ipsecBackend = ipsec.NoopBackend{}
	default:
		return nil, fmt.Errorf("unsupported ipsec backend: %s", cfg.IPSec.Backend)
	}

	aaaClient := aaa.Client(aaa.NoopClient{})
	switch cfg.AAA.Backend {
	case "noop":
		aaaClient = aaa.NoopClient{}
	case "swm_tcp_probe":
		aaaClient = aaa.SWmTCPProbeClient{
			Host:    cfg.Protocol.SWm.PeerHost,
			Port:    cfg.Protocol.SWm.Port,
			Realm:   cfg.Protocol.SWm.Realm,
			Timeout: 2 * time.Second,
		}
	case "swm_diameter_eap":
		var responder diameter.EAPResponder
		switch cfg.AAA.EAPProvider {
		case "unsupported":
			responder = aaa.UnsupportedEAPResponder{}
		case "nak_only":
			responder = aaa.NAKOnlyEAPResponder{}
		default:
			return nil, fmt.Errorf("unsupported aaa eap_provider: %s", cfg.AAA.EAPProvider)
		}
		aaaClient = aaa.SWmDiameterEAPClient{
			Diameter: diameter.New(diameter.Config{
				PeerHost:         cfg.Protocol.SWm.PeerHost,
				PeerPort:         cfg.Protocol.SWm.Port,
				OriginHost:       cfg.AAA.OriginHost,
				OriginRealm:      cfg.AAA.OriginRealm,
				DestinationRealm: cfg.AAA.DestinationRealm,
				DestinationHost:  cfg.AAA.DestinationHost,
				Timeout:          10 * time.Second,
			}),
			Responder: responder,
			MaxRounds: cfg.AAA.EAPMaxRounds,
		}
	default:
		return nil, fmt.Errorf("unsupported aaa backend: %s", cfg.AAA.Backend)
	}

	s2bClient := s2b.Client(s2b.NoopClient{})
	switch cfg.Protocol.S2b.Backend {
	case "noop":
		s2bClient = s2b.NoopClient{}
	case "gtpv2_echo":
		s2bClient = s2b.GTPv2EchoClient{
			PGWAddress: cfg.Protocol.S2b.PGWAddress,
			Port:       cfg.Protocol.S2b.GTPv2Port,
			Timeout:    2 * time.Second,
		}
	default:
		return nil, fmt.Errorf("unsupported s2b backend: %s", cfg.Protocol.S2b.Backend)
	}

	a := &Server{
		cfg:      cfg,
		sessions: session.NewStore(),
		aaa:      aaaClient,
		ipsec:    ipsecBackend,
		s2b:      s2bClient,
		mux:      http.NewServeMux(),
		checker:  compliance.NewChecker(cfg, s2bClient),
	}
	a.routes()
	return &http.Server{
		Addr:              cfg.HTTP.Listen,
		Handler:           a.mux,
		ReadHeaderTimeout: 3 * time.Second,
	}, nil
}

func (a *Server) routes() {
	a.mux.HandleFunc("/healthz", a.handleHealthz)
	a.mux.HandleFunc("/v1/sessions", a.handleSessions)
	a.mux.HandleFunc("/v1/sessions/create", a.handleCreateSession)
	a.mux.HandleFunc("/v1/sessions/delete", a.handleDeleteSession)
	a.mux.HandleFunc("/v1/compliance/check", a.handleComplianceCheck)
}

func (a *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
		"node":   a.cfg.NodeID,
	})
}

func (a *Server) handleSessions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.sessions.List())
}

func (a *Server) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req SessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("bad json: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	auth, err := a.aaa.Authorize(ctx, aaa.AuthRequest{IMSI: req.IMSI, APN: req.APN})
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("aaa error: %v", err))
		return
	}
	if !auth.Allowed {
		writeError(w, http.StatusForbidden, "aaa rejected")
		return
	}

	if err := a.ipsec.CreateChildSA(ctx, ipsec.CreateRequest{UEID: req.UEID, IMSI: req.IMSI}); err != nil {
		if ipsec.IsPending(err) {
			s := a.sessions.Upsert(session.Session{
				UEID:   req.UEID,
				IMSI:   req.IMSI,
				APN:    req.APN,
				Status: session.StatusPending,
			})
			writeJSON(w, http.StatusAccepted, map[string]any{
				"session": s,
				"message": err.Error(),
			})
			return
		}
		writeError(w, http.StatusBadGateway, fmt.Sprintf("ipsec create failed: %v", err))
		return
	}
	if err := a.s2b.CreateSession(ctx, req.UEID); err != nil {
		_ = a.ipsec.DeleteChildSA(ctx, req.UEID)
		writeError(w, http.StatusBadGateway, fmt.Sprintf("s2b create failed: %v", err))
		return
	}

	s := a.sessions.Upsert(session.Session{
		UEID:   req.UEID,
		IMSI:   req.IMSI,
		APN:    req.APN,
		Status: session.StatusUp,
	})
	writeJSON(w, http.StatusCreated, s)
}

func (a *Server) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		UEID string `json:"ue_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("bad json: %v", err))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := a.ipsec.DeleteChildSA(ctx, req.UEID); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("ipsec delete failed: %v", err))
		return
	}
	if err := a.s2b.DeleteSession(ctx, req.UEID); err != nil {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("s2b delete failed: %v", err))
		return
	}

	a.sessions.Delete(req.UEID)
	writeJSON(w, http.StatusOK, map[string]string{"result": "deleted"})
}

func (a *Server) handleComplianceCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	report := a.checker.Run(r.Context())
	code := http.StatusOK
	if !report.Passed {
		code = http.StatusConflict
	}
	writeJSON(w, code, report)
}

func writeJSON(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
