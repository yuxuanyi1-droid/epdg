package aaa

import (
	"context"
	"fmt"
	"net"
	"time"

	"epdg-go/internal/diameter"
)

type AuthRequest struct {
	IMSI string `json:"imsi"`
	APN  string `json:"apn"`
}

type AuthResult struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

type Client interface {
	Authorize(ctx context.Context, req AuthRequest) (AuthResult, error)
}

type NoopClient struct{}

func (NoopClient) Authorize(_ context.Context, req AuthRequest) (AuthResult, error) {
	if req.IMSI == "" {
		return AuthResult{}, fmt.Errorf("imsi required")
	}
	return AuthResult{Allowed: true}, nil
}

type SWmTCPProbeClient struct {
	Host    string
	Port    int
	Realm   string
	Timeout time.Duration
}

func (c SWmTCPProbeClient) Authorize(_ context.Context, req AuthRequest) (AuthResult, error) {
	if req.IMSI == "" {
		return AuthResult{}, fmt.Errorf("imsi required")
	}
	if c.Host == "" || c.Port == 0 || c.Realm == "" {
		return AuthResult{}, fmt.Errorf("swm config incomplete")
	}

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	address := net.JoinHostPort(c.Host, fmt.Sprintf("%d", c.Port))
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return AuthResult{}, fmt.Errorf("swm peer unreachable: %w", err)
	}
	_ = conn.Close()

	return AuthResult{Allowed: true}, nil
}

type SWmDiameterEAPClient struct {
	Diameter  *diameter.Client
	Responder diameter.EAPResponder
	MaxRounds int
}

func (c SWmDiameterEAPClient) Authorize(_ context.Context, req AuthRequest) (AuthResult, error) {
	if req.IMSI == "" {
		return AuthResult{}, fmt.Errorf("imsi required")
	}
	if c.Diameter == nil {
		return AuthResult{}, fmt.Errorf("diameter client is nil")
	}
	maxRounds := c.MaxRounds
	if maxRounds <= 0 {
		maxRounds = 4
	}
	if err := c.Diameter.ExchangeEAP(req.IMSI, c.Responder, maxRounds); err != nil {
		return AuthResult{}, fmt.Errorf("diameter eap auth failed: %w", err)
	}
	return AuthResult{Allowed: true}, nil
}
