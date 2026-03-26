package ipsec

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

type CreateRequest struct {
	UEID string `json:"ue_id"`
	IMSI string `json:"imsi"`
}

type Backend interface {
	CreateChildSA(ctx context.Context, req CreateRequest) error
	DeleteChildSA(ctx context.Context, ueID string) error
}

type NoopBackend struct{}

func (NoopBackend) CreateChildSA(_ context.Context, req CreateRequest) error {
	if req.UEID == "" {
		return fmt.Errorf("ue_id required")
	}
	return nil
}

func (NoopBackend) DeleteChildSA(_ context.Context, ueID string) error {
	if ueID == "" {
		return fmt.Errorf("ue_id required")
	}
	return nil
}

type SwanctlBackend struct {
	Binary         string
	Mode           string
	ConnectionName string
	ChildPrefix    string
	ChildName      string
	Timeout        time.Duration
}

type PendingError struct {
	Reason string
}

func (e PendingError) Error() string {
	if e.Reason == "" {
		return "waiting for UE initiated IKEv2/IPsec"
	}
	return e.Reason
}

func IsPending(err error) bool {
	_, ok := err.(PendingError)
	return ok
}

func (s SwanctlBackend) CreateChildSA(ctx context.Context, req CreateRequest) error {
	if req.UEID == "" {
		return fmt.Errorf("ue_id required")
	}

	childName := s.childName(req.UEID)
	if s.Mode == "passive" {
		return s.awaitInitiator(ctx, childName)
	}
	args := []string{"--initiate", "--child", childName}
	if s.ConnectionName != "" {
		args = append(args, "--ike", s.ConnectionName)
	}

	ctx, cancel := s.withTimeout(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.Binary, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("swanctl initiate failed: %w (%s)", err, string(out))
	}
	return nil
}

func (s SwanctlBackend) DeleteChildSA(ctx context.Context, ueID string) error {
	if ueID == "" {
		return fmt.Errorf("ue_id required")
	}

	childName := s.childName(ueID)
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.Binary, "--terminate", "--child", childName)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("swanctl terminate failed: %w (%s)", err, string(out))
	}
	return nil
}

func (s SwanctlBackend) childName(ueID string) string {
	if s.ChildName != "" {
		return s.ChildName
	}
	prefix := s.ChildPrefix
	if prefix == "" {
		prefix = "ue"
	}
	re := regexp.MustCompile(`[^a-zA-Z0-9_-]`)
	cleanUEID := re.ReplaceAllString(ueID, "_")
	return fmt.Sprintf("%s-%s", prefix, cleanUEID)
}

func (s SwanctlBackend) withTimeout(parent context.Context) (context.Context, context.CancelFunc) {
	if _, ok := parent.Deadline(); ok {
		return parent, func() {}
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return context.WithTimeout(parent, timeout)
}

func (s SwanctlBackend) awaitInitiator(ctx context.Context, childName string) error {
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.Binary, "--list-conns")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("swanctl list-conns failed: %w (%s)", err, string(out))
	}
	text := string(out)
	if s.ConnectionName != "" && !regexp.MustCompile(`(?m)^`+regexp.QuoteMeta(s.ConnectionName)+`:`).MatchString(text) {
		return fmt.Errorf("swanctl connection %q not loaded", s.ConnectionName)
	}
	if childName != "" && !strings.Contains(text, childName+":") {
		return fmt.Errorf("swanctl child %q not loaded", childName)
	}
	return PendingError{Reason: fmt.Sprintf("waiting for UE initiated IKEv2/IPsec on child %s", childName)}
}
