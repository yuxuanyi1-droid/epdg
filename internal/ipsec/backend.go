// Package ipsec drives strongSwan's charon daemon, which owns the SWu data
// plane (IKEv2, the EAP relay and the IPsec SAs). The ePDG control plane only
// orchestrates: it loads connections, initiates or terminates CHILD_SAs and
// reports state.
package ipsec

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"epdg/internal/config"
)

// ErrPending indicates that the request cannot complete synchronously because
// the peer has to initiate the exchange. On SWu the UE is always the IKEv2
// initiator, so the ePDG normally runs in passive mode.
var ErrPending = errors.New("ipsec: waiting for the UE to initiate IKEv2")

// Backend abstracts how charon is controlled.
type Backend interface {
	// Load makes sure the configured connection is present in charon.
	Load(ctx context.Context) error
	// Initiate starts the CHILD_SA for a UE. It returns ErrPending when the
	// backend runs in passive mode.
	Initiate(ctx context.Context, ueID string) error
	// Terminate tears down the CHILD_SA for a UE.
	Terminate(ctx context.Context, ueID string) error
	// Mode reports "active" or "passive".
	Mode() string
	// Name identifies the backend for compliance reporting.
	Name() string
	// Status returns a human readable health string.
	Status(ctx context.Context) (string, error)
	// Close releases any resources.
	Close() error
}

// ChildName renders the swanctl CHILD_SA name for a UE identity.
func ChildName(cfg config.IPSec, ueID string) string {
	if cfg.ChildName != "" {
		return cfg.ChildName
	}
	prefix := cfg.ChildPrefix
	if prefix == "" {
		prefix = "ue"
	}
	return prefix + "-" + sanitise(ueID)
}

var unsafeChildChars = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

func sanitise(in string) string {
	return unsafeChildChars.ReplaceAllString(in, "_")
}

// New builds the configured backend.
func New(cfg config.IPSec) (Backend, error) {
	switch cfg.Backend {
	case "noop":
		if cfg.Mode == "" {
			cfg.Mode = "passive"
		}
		return &NoopBackend{mode: cfg.Mode}, nil
	case "vici":
		return NewViciBackend(cfg)
	case "swanctl":
		return NewSwanctlBackend(cfg), nil
	default:
		return nil, fmt.Errorf("ipsec: unsupported backend %q", cfg.Backend)
	}
}

// NoopBackend performs no charon interaction, for development runs.
type NoopBackend struct{ mode string }

func (n *NoopBackend) Load(context.Context) error { return nil }

func (n *NoopBackend) Initiate(_ context.Context, ueID string) error {
	if ueID == "" {
		return errors.New("ipsec: ue_id is required")
	}
	if n.mode == "passive" {
		return ErrPending
	}
	return nil
}

func (n *NoopBackend) Terminate(_ context.Context, ueID string) error {
	if ueID == "" {
		return errors.New("ipsec: ue_id is required")
	}
	return nil
}

func (n *NoopBackend) Mode() string {
	if n.mode == "" {
		return "passive"
	}
	return n.mode
}

func (n *NoopBackend) Name() string { return "noop" }

func (n *NoopBackend) Status(context.Context) (string, error) {
	return "noop backend, charon not queried", nil
}

func (n *NoopBackend) Close() error { return nil }
