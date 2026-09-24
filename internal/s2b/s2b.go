// Package s2b adapts the GTPv2-C client to the ePDG session lifecycle.
package s2b

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"sync"

	"epdg/internal/config"
	"epdg/internal/gtpv2"
)

// CauseRequestAccepted is the GTPv2-C cause value 16 (3GPP TS 29.274
// section 8.4).
const CauseRequestAccepted uint8 = 16

// Backend establishes and releases the S2b bearer for a UE.
type Backend interface {
	// Create establishes the S2b session and returns the allocated PDN address.
	Create(ctx context.Context, ueID, imsi, apn string) (*gtpv2.Result, error)
	// Delete releases the S2b session.
	Delete(ctx context.Context, ueID, imsi string) error
	// Ping verifies the S2b peer is reachable.
	Ping(ctx context.Context) error
	// Name identifies the backend for compliance reporting.
	Name() string
	// Peer returns the configured peer address.
	Peer() string
}

// Noop performs no S2b signalling.
type Noop struct{}

func (Noop) Create(context.Context, string, string, string) (*gtpv2.Result, error) {
	return nil, nil
}
func (Noop) Delete(context.Context, string, string) error { return nil }
func (Noop) Ping(context.Context) error                   { return nil }
func (Noop) Name() string                                 { return "noop" }
func (Noop) Peer() string                                 { return "" }

// Echo only performs a GTPv2-C Echo exchange, validating the S2b control plane
// path without allocating a bearer.
type Echo struct{ client *gtpv2.Client }

// GTPv2 establishes real S2b bearers with Create Session / Delete Session.
//
// It keeps the peer C-plane and U-plane TEIDs per UE, because every later
// transaction of the session has to be addressed to the peer C-plane TEID.
type GTPv2 struct {
	client *gtpv2.Client
	cfg    config.S2b
	plmn   config.PLMN

	mu       sync.Mutex
	sessions map[string]s2bSession
}

// s2bSession is the per-UE state needed to continue an S2b session.
type s2bSession struct {
	peerCTeid uint32
	peerUTeid uint32
	peerUAddr string
	ueIP      string
	ebi       uint8
	apn       string
}

// New builds the configured backend.
func New(cfg config.S2b, plmn config.PLMN, log *slog.Logger) (Backend, error) {
	if log == nil {
		log = slog.Default()
	}
	switch cfg.Backend {
	case "", "noop":
		return Noop{}, nil
	case "gtpv2_echo", "gtpv2":
		client, err := gtpv2.New(cfg.LocalAddress, cfg.PGWAddress, cfg.GTPv2Port, cfg.Timeout(), log.With("component", "gtpv2"))
		if err != nil {
			return nil, err
		}
		if cfg.Backend == "gtpv2_echo" {
			return &Echo{client: client}, nil
		}
		return &GTPv2{client: client, cfg: cfg, plmn: plmn, sessions: map[string]s2bSession{}}, nil
	default:
		return nil, fmt.Errorf("s2b: unsupported backend %q", cfg.Backend)
	}
}

func (e *Echo) Create(ctx context.Context, _, _, _ string) (*gtpv2.Result, error) {
	if err := e.client.Echo(ctx); err != nil {
		return nil, err
	}
	return nil, nil
}
func (e *Echo) Delete(context.Context, string, string) error { return nil }
func (e *Echo) Ping(ctx context.Context) error               { return e.client.Echo(ctx) }
func (e *Echo) Name() string                                 { return "gtpv2_echo" }
func (e *Echo) Peer() string                                 { return e.client.Peer() }

func (g *GTPv2) Create(ctx context.Context, ueID, imsi, apn string) (*gtpv2.Result, error) {
	if ueID == "" {
		return nil, errors.New("s2b: ue_id is required")
	}
	if apn == "" {
		apn = g.cfg.APN
	}
	ebi := uint8(5)
	result, err := g.client.CreateSession(ctx, gtpv2.Request{
		IMSI:       imsi,
		APN:        apn,
		MCC:        g.plmn.MCC,
		MNC:        g.plmn.MNC,
		LocalIP:    g.cfg.LocalAddress,
		LocalTEID:  cTeidFor(ueID),
		LocalUTEID: uTeidFor(ueID),
		EBI:        ebi,
	})
	if err != nil {
		return nil, err
	}
	if result.Cause != CauseRequestAccepted {
		return nil, fmt.Errorf("s2b: create session rejected with cause %d", result.Cause)
	}

	state := s2bSession{
		peerCTeid: result.PGWCTEID,
		ueIP:      result.PDNAddress,
		ebi:       ebi,
		apn:       apn,
	}
	if len(result.Bearers) > 0 {
		state.peerUTeid = result.Bearers[0].PGWUTEID
		state.peerUAddr = result.Bearers[0].PGWUAddress
	}
	g.mu.Lock()
	g.sessions[ueID] = state
	g.mu.Unlock()
	return result, nil
}

func (g *GTPv2) Delete(ctx context.Context, ueID, imsi string) error {
	if ueID == "" {
		return errors.New("s2b: ue_id is required")
	}
	g.mu.Lock()
	state, ok := g.sessions[ueID]
	delete(g.sessions, ueID)
	g.mu.Unlock()
	if !ok {
		return fmt.Errorf("s2b: no S2b session is known for ue %s", ueID)
	}
	ebi := state.ebi
	if ebi == 0 {
		ebi = 5
	}
	return g.client.DeleteSession(ctx, gtpv2.Request{
		EBI:      ebi,
		PeerTEID: state.peerCTeid,
		MCC:      g.plmn.MCC,
		MNC:      g.plmn.MNC,
	})
}

func (g *GTPv2) Ping(ctx context.Context) error { return g.client.Echo(ctx) }
func (g *GTPv2) Name() string                   { return "gtpv2" }
func (g *GTPv2) Peer() string                   { return g.client.Peer() }

// cTeidFor and uTeidFor derive stable local TEIDs from the UE identity. The ePDG
// allocates its own TEIDs, so any stable non-zero values are valid; the two
// planes must differ because they belong to different GTP tunnels.
func cTeidFor(ueID string) uint32 { return teidFor("c/" + ueID) }
func uTeidFor(ueID string) uint32 { return teidFor("u/" + ueID) }

func teidFor(key string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	if v := h.Sum32(); v != 0 {
		return v
	}
	return 1
}
