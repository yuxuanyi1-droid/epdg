package s2b

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

type Client interface {
	CreateSession(ctx context.Context, ueID string) error
	DeleteSession(ctx context.Context, ueID string) error
	Ping(ctx context.Context) error
}

type NoopClient struct{}

func (NoopClient) CreateSession(_ context.Context, ueID string) error {
	if ueID == "" {
		return fmt.Errorf("ue_id required")
	}
	return nil
}

func (NoopClient) DeleteSession(_ context.Context, ueID string) error {
	if ueID == "" {
		return fmt.Errorf("ue_id required")
	}
	return nil
}

func (NoopClient) Ping(_ context.Context) error {
	return nil
}

type GTPv2EchoClient struct {
	PGWAddress string
	Port       int
	Timeout    time.Duration
}

func (c GTPv2EchoClient) CreateSession(ctx context.Context, ueID string) error {
	if ueID == "" {
		return fmt.Errorf("ue_id required")
	}
	return c.Ping(ctx)
}

func (c GTPv2EchoClient) DeleteSession(_ context.Context, ueID string) error {
	if ueID == "" {
		return fmt.Errorf("ue_id required")
	}
	return nil
}

func (c GTPv2EchoClient) Ping(ctx context.Context) error {
	if c.PGWAddress == "" || c.Port == 0 {
		return fmt.Errorf("s2b config incomplete")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	serverAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(c.PGWAddress, fmt.Sprintf("%d", c.Port)))
	if err != nil {
		return fmt.Errorf("resolve pgw addr failed: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		return fmt.Errorf("dial pgw failed: %w", err)
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(timeout)
	}
	_ = conn.SetDeadline(deadline)

	seq := uint32(time.Now().UnixNano()) & 0x00FFFFFF
	req := buildEchoRequest(seq)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("send gtpv2 echo failed: %w", err)
	}

	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		return fmt.Errorf("recv gtpv2 echo failed: %w", err)
	}
	if n < 8 {
		return fmt.Errorf("short gtpv2 response: %d bytes", n)
	}
	if resp[1] != 2 {
		return fmt.Errorf("unexpected gtpv2 message type: %d", resp[1])
	}
	headerLen := 8
	if (resp[0] & 0x08) != 0 {
		headerLen = 12
		if n < headerLen {
			return fmt.Errorf("short gtpv2 response for teid header: %d bytes", n)
		}
	}
	gotSeq := uint32(resp[headerLen-4])<<16 | uint32(resp[headerLen-3])<<8 | uint32(resp[headerLen-2])
	if gotSeq != seq {
		return fmt.Errorf("gtpv2 seq mismatch: sent %d got %d", seq, gotSeq)
	}
	return nil
}

func buildEchoRequest(seq uint32) []byte {
	buf := make([]byte, 8)
	buf[0] = 0x40 // Version=2, T=0
	buf[1] = 1    // Echo Request
	binary.BigEndian.PutUint16(buf[2:4], 4)
	buf[4] = byte((seq >> 16) & 0xFF)
	buf[5] = byte((seq >> 8) & 0xFF)
	buf[6] = byte(seq & 0xFF)
	buf[7] = 0
	return buf
}
