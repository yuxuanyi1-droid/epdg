package ipsec

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"epdg/internal/config"
)

// SwanctlBackend drives charon through the swanctl command line tool. It is kept
// as an alternative to the VICI backend for deployments that only expose the
// CLI.
type SwanctlBackend struct {
	binary      string
	mode        string
	connection  string
	childName   string
	childPrefix string
	timeout     time.Duration
}

// NewSwanctlBackend builds a swanctl CLI backend.
func NewSwanctlBackend(cfg config.IPSec) *SwanctlBackend {
	binary := cfg.SwanctlBin
	if binary == "" {
		binary = "/usr/sbin/swanctl"
	}
	return &SwanctlBackend{
		binary:      binary,
		mode:        cfg.Mode,
		connection:  cfg.ConnectionName,
		childName:   cfg.ChildName,
		childPrefix: cfg.ChildPrefix,
		timeout:     cfg.Timeout(),
	}
}

func (b *SwanctlBackend) Name() string { return "swanctl" }

func (b *SwanctlBackend) Mode() string { return b.mode }

func (b *SwanctlBackend) Close() error { return nil }

func (b *SwanctlBackend) run(ctx context.Context, args ...string) (string, error) {
	callCtx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()
	cmd := exec.CommandContext(callCtx, b.binary, args...)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("ipsec: %s %s failed: %w: %s", b.binary, strings.Join(args, " "), err, text)
	}
	return text, nil
}

// Status runs swanctl --version to prove the tool and configuration exist.
func (b *SwanctlBackend) Status(ctx context.Context) (string, error) {
	return b.run(ctx, "--version")
}

// Load runs swanctl --load-all.
func (b *SwanctlBackend) Load(ctx context.Context) error {
	_, err := b.run(ctx, "--load-all")
	return err
}

// Initiate either reports ErrPending (passive mode) or runs swanctl --initiate.
func (b *SwanctlBackend) Initiate(ctx context.Context, ueID string) error {
	if ueID == "" {
		return fmt.Errorf("ipsec: ue_id is required")
	}
	child := ChildName(config.IPSec{ChildName: b.childName, ChildPrefix: b.childPrefix}, ueID)
	if b.mode == "passive" {
		if err := b.Load(ctx); err != nil {
			return err
		}
		return fmt.Errorf("%w (child %s)", ErrPending, child)
	}
	args := []string{"--initiate", "--child", child}
	if b.connection != "" {
		args = append(args, "--ike", b.connection)
	}
	_, err := b.run(ctx, args...)
	return err
}

// Terminate runs swanctl --terminate for the UE's CHILD_SA.
func (b *SwanctlBackend) Terminate(ctx context.Context, ueID string) error {
	if ueID == "" {
		return fmt.Errorf("ipsec: ue_id is required")
	}
	child := ChildName(config.IPSec{ChildName: b.childName, ChildPrefix: b.childPrefix}, ueID)
	_, err := b.run(ctx, "--terminate", "--child", child)
	return err
}
