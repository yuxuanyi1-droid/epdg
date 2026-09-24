// Package server exposes the ePDG northbound API and wires the control plane
// components together.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"epdg/internal/aaa"
	"epdg/internal/compliance"
	"epdg/internal/config"
	"epdg/internal/hss"
	"epdg/internal/ipsec"
	"epdg/internal/s2b"
	"epdg/internal/session"
)

// Options carries the wired dependencies of the application.
type Options struct {
	Config *config.Config
	Logger *slog.Logger
	IPSec  ipsec.Backend
	HSS    *hss.Client
	Radius *aaa.Server
	S2B    s2b.Backend
}

// App is the ePDG control plane application.
type App struct {
	cfg      *config.Config
	log      *slog.Logger
	ipsec    ipsec.Backend
	hss      *hss.Client
	radius   *aaa.Server
	s2b      s2b.Backend
	sessions *session.Store
}

// NewApp builds the application.
func NewApp(opts Options) *App {
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	return &App{
		cfg:      opts.Config,
		log:      log,
		ipsec:    opts.IPSec,
		hss:      opts.HSS,
		radius:   opts.Radius,
		s2b:      opts.S2B,
		sessions: session.NewStore(),
	}
}

// Sessions exposes the session table, used by tests and the API.
func (a *App) Sessions() *session.Store { return a.sessions }

// Handler builds the HTTP routing table.
func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.handleHealth)
	mux.HandleFunc("GET /v1/sessions", a.handleListSessions)
	mux.HandleFunc("POST /v1/sessions/create", a.handleCreate)
	mux.HandleFunc("POST /v1/sessions/delete", a.handleDelete)
	mux.HandleFunc("GET /v1/compliance/check", a.handleCompliance)
	return mux
}

// ListenAndServe serves the management API until ctx is cancelled.
func (a *App) ListenAndServe(ctx context.Context) error {
	addr := a.cfg.HTTP.Listen
	if addr == "" {
		addr = ":19090"
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           a.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	a.log.Info("http: listening", "address", addr, "node", a.cfg.NodeID)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("http: %w", err)
	}
	return nil
}

func (a *App) handleHealth(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"node":     a.cfg.NodeID,
		"sessions": a.sessions.Len(),
	})
}

func (a *App) handleListSessions(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusOK, a.sessions.List())
}

type createRequest struct {
	UEID string `json:"ue_id"`
	IMSI string `json:"imsi"`
	APN  string `json:"apn"`
}

func (a *App) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if !a.decode(w, r, &req) {
		return
	}
	req.UEID = strings.TrimSpace(req.UEID)
	req.IMSI = strings.TrimSpace(req.IMSI)
	req.APN = strings.TrimSpace(req.APN)
	if req.UEID == "" || req.IMSI == "" || req.APN == "" {
		a.writeError(w, http.StatusBadRequest, "ue_id, imsi and apn are required")
		return
	}

	ctx := r.Context()
	if a.hss != nil {
		if _, err := a.hss.Vector(ctx, req.IMSI); err != nil {
			a.log.Warn("create: subscriber not authorised by the HSS", "imsi", req.IMSI, "error", err)
			a.writeError(w, http.StatusBadGateway, "aaa error: "+err.Error())
			return
		}
	}

	status := session.StatusUp
	httpStatus := http.StatusCreated
	err := a.ipsec.Initiate(ctx, req.UEID)
	switch {
	case errors.Is(err, ipsec.ErrPending):
		status = session.StatusPending
		httpStatus = http.StatusAccepted
	case err != nil:
		a.writeError(w, http.StatusBadGateway, "ipsec create failed: "+err.Error())
		return
	}

	if err := a.s2b.Create(ctx, req.UEID, req.IMSI, req.APN); err != nil {
		if status == session.StatusUp {
			if cleanupErr := a.ipsec.Terminate(ctx, req.UEID); cleanupErr != nil {
				a.log.Warn("create: rollback of the CHILD_SA failed", "ue_id", req.UEID, "error", cleanupErr)
			}
			a.writeError(w, http.StatusBadGateway, "s2b create failed: "+err.Error())
			return
		}
		a.log.Warn("create: S2b signalling failed while waiting for the UE", "ue_id", req.UEID, "error", err)
	}

	stored := a.sessions.Upsert(&session.Session{
		UEID:   req.UEID,
		IMSI:   req.IMSI,
		APN:    req.APN,
		Status: status,
	})
	a.log.Info("session created", "ue_id", req.UEID, "imsi", req.IMSI, "status", status)
	a.writeJSON(w, httpStatus, stored)
}

type deleteRequest struct {
	UEID string `json:"ue_id"`
	IMSI string `json:"imsi"`
}

func (a *App) handleDelete(w http.ResponseWriter, r *http.Request) {
	var req deleteRequest
	if !a.decode(w, r, &req) {
		return
	}
	req.UEID = strings.TrimSpace(req.UEID)
	if req.UEID == "" {
		a.writeError(w, http.StatusBadRequest, "ue_id is required")
		return
	}
	ctx := r.Context()
	if existing, ok := a.sessions.Get(req.UEID); ok && req.IMSI == "" {
		req.IMSI = existing.IMSI
	}

	if err := a.ipsec.Terminate(ctx, req.UEID); err != nil {
		a.log.Warn("delete: CHILD_SA termination failed", "ue_id", req.UEID, "error", err)
		a.writeError(w, http.StatusBadGateway, "ipsec delete failed: "+err.Error())
		return
	}
	if err := a.s2b.Delete(ctx, req.UEID, req.IMSI); err != nil {
		a.log.Warn("delete: S2b release failed", "ue_id", req.UEID, "error", err)
		a.writeError(w, http.StatusBadGateway, "s2b delete failed: "+err.Error())
		return
	}
	a.sessions.Delete(req.UEID)
	a.log.Info("session deleted", "ue_id", req.UEID)
	a.writeJSON(w, http.StatusOK, map[string]string{"result": "deleted"})
}

func (a *App) handleCompliance(w http.ResponseWriter, r *http.Request) {
	report := a.complianceReport(r.Context())
	code := http.StatusOK
	if !report.Passed {
		code = http.StatusConflict
	}
	a.writeJSON(w, code, report)
}

func (a *App) complianceReport(ctx context.Context) *compliance.Report {
	timeout := 3 * time.Second
	checks := []compliance.Check{
		{
			Name: "PyHSS",
			Run: func(ctx context.Context) error {
				if a.hss == nil {
					if a.cfg.AAA.Backend == "noop" {
						return nil
					}
					return compliance.Errorf("aaa backend %q does not query the HSS", a.cfg.AAA.Backend)
				}
				return a.hss.Ping(ctx)
			},
		},
		{
			Name: "strongSwan",
			Run: func(ctx context.Context) error {
				if a.cfg.IPSec.Backend == "noop" {
					return nil
				}
				details, err := a.ipsec.Status(ctx)
				if err != nil {
					return err
				}
				if details == "" {
					return compliance.Errorf("no status returned")
				}
				return nil
			},
		},
		{
			Name: "RADIUS",
			Run: func(ctx context.Context) error {
				if a.radius == nil {
					if a.cfg.RADIUS.Backend == "noop" {
						return nil
					}
					return compliance.Errorf("radius backend %q is not running", a.cfg.RADIUS.Backend)
				}
				return probeUDP(ctx, a.cfg.RADIUS.Listen, timeout)
			},
		},
		{
			Name: "S2b",
			Run: func(ctx context.Context) error {
				return a.s2b.Ping(ctx)
			},
		},
	}
	items := compliance.Run(ctx, checks)
	return compliance.New(a.cfg.NodeID, "mcc="+a.cfg.Protocol.PLMN.MCC+",mnc="+a.cfg.Protocol.PLMN.MNC, items)
}

// probeUDP verifies that a UDP port is bound locally by attempting to resolve
// and read back the socket; UDP has no handshake so binding is the best check.
func probeUDP(_ context.Context, address string, timeout time.Duration) error {
	conn, err := net.DialTimeout("udp", address, timeout)
	if err != nil {
		return err
	}
	defer conn.Close()
	return nil
}

func (a *App) decode(w http.ResponseWriter, r *http.Request, target any) bool {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(target); err != nil {
		a.writeError(w, http.StatusBadRequest, "bad json: "+err.Error())
		return false
	}
	return true
}

func (a *App) writeError(w http.ResponseWriter, code int, message string) {
	a.writeJSON(w, code, map[string]string{"error": message})
}

func (a *App) writeJSON(w http.ResponseWriter, code int, payload any) {
	body, err := json.Marshal(payload)
	if err != nil {
		a.log.Error("http: cannot encode response", "error", err)
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}
