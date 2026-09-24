// Package s2b adapts the GTPv2-C client to the ePDG session lifecycle.
package s2b

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"

	"epdg/internal/config"
	"epdg/internal/gtpv2"
)

// CauseRequestAccepted is the GTPv2-C cause value 16 (3GPP TS 29.274
// section 8.4).
const CauseRequestAccepted uint8 = 16

// Backend establishes and releases the S2b bearer for a UE.
type Backend interface {
	// Create establishes the S2b session.
	Create(ctx context.Context, ueID, imsi, apn string) error
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

func (Noop) Create(context.Context, string, string, string) error { return nil }
func (Noop) Delete(context.Context, string, string) error         { return nil }
func (Noop) Ping(context.Context) error                           { return nil }
func (Noop) Name() string                                         { return "noop" }
func (Noop) Peer() string                                         { return "" }

// Echo only performs a GTPv2-C Echo exchange, validating the S2b control plane
// path without allocating a bearer.
type Echo struct{ client *gtpv2.Client }

// GTPv2 establishes real S2b bearers with Create Session / Delete Session.
type GTPv2 struct {
	client *gtpv2.Client
	cfg    config.S2b
	plmn   config.PLMN
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
		return &GTPv2{client: client, cfg: cfg, plmn: plmn}, nil
	default:
		return nil, fmt.Errorf("s2b: unsupported backend %q", cfg.Backend)
	}
}

func (e *Echo) Create(ctx context.Context, _, _, _ string) error { return e.client.Echo(ctx) }
func (e *Echo) Delete(context.Context, string, string) error     { return nil }
func (e *Echo) Ping(ctx context.Context) error                   { return e.client.Echo(ctx) }
func (e *Echo) Name() string                                     { return "gtpv2_echo" }
func (e *Echo) Peer() string                                     { return e.client.Peer() }

func (g *GTPv2) Create(ctx context.Context, ueID, imsi, apn string) error {
	if ueID == "" {
		return errors.New("s2b: ue_id is required")
	}
	if apn == "" {
		apn = g.cfg.APN
	}
	result, err := g.client.CreateSession(ctx, gtpv2.Request{
		IMSI:      imsi,
		APN:       apn,
		MCC:       g.plmn.MCC,
		MNC:       g.plmn.MNC,
		LocalIP:   g.cfg.LocalAddress,
		LocalTEID: teidFor(ueID),
	})
	if err != nil {
		return err
	}
	if result.Cause != CauseRequestAccepted {
		return fmt.Errorf("s2b: create session rejected with cause %d", result.Cause)
	}
	return nil
}

func (g *GTPv2) Delete(ctx context.Context, ueID, imsi string) error {
	if ueID == "" {
		return errors.New("s2b: ue_id is required")
	}
	return g.client.DeleteSession(ctx, gtpv2.Request{IMSI: imsi, EBI: 5, MCC: g.plmn.MCC, MNC: g.plmn.MNC})
}

func (g *GTPv2) Ping(ctx context.Context) error { return g.client.Echo(ctx) }
func (g *GTPv2) Name() string                   { return "gtpv2" }
func (g *GTPv2) Peer() string                   { return g.client.Peer() }

// teidFor derives a stable local C-plane TEID from the UE identity. The ePDG
// allocates its own TEID, so any stable non-zero value is valid.
func teidFor(ueID string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(ueID))
	if v := h.Sum32(); v != 0 {
		return v
	}
	return 1
}
