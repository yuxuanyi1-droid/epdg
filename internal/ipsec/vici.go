package ipsec

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/strongswan/govici/vici"

	"epdg/internal/config"
)

// ViciBackend controls charon through the VICI protocol, the native control
// interface of the IKE daemon. Compared with shelling out to swanctl this gives
// structured SA state and precise error reporting.
type ViciBackend struct {
	socket      string
	mode        string
	connection  string
	childPrefix string
	childName   string
	timeout     time.Duration
	log         *slog.Logger
}

// NewViciBackend builds a VICI backend from the ePDG configuration.
func NewViciBackend(cfg config.IPSec) (*ViciBackend, error) {
	socket := cfg.Socket
	if socket == "" {
		socket = "/run/charon.vici"
	}
	connection := cfg.ConnectionName
	if connection == "" {
		return nil, fmt.Errorf("ipsec: ipsec.connection_name must be set for the vici backend")
	}
	return &ViciBackend{
		socket:      socket,
		mode:        cfg.Mode,
		connection:  connection,
		childPrefix: cfg.ChildPrefix,
		childName:   cfg.ChildName,
		timeout:     cfg.Timeout(),
		log:         slog.Default().With("component", "vici"),
	}, nil
}

func (b *ViciBackend) Name() string { return "vici" }

func (b *ViciBackend) Mode() string { return b.mode }

func (b *ViciBackend) Close() error { return nil }

// withSession opens a VICI session, runs fn with a bounded context and closes
// the session again.
func (b *ViciBackend) withSession(ctx context.Context, fn func(context.Context, *vici.Session) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	callCtx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()

	session, err := vici.NewSession(vici.WithSocketPath(b.socket))
	if err != nil {
		return fmt.Errorf("ipsec: cannot connect to charon at %s: %w", b.socket, err)
	}
	defer session.Close()
	return fn(callCtx, session)
}

// Status queries the charon version, proving VICI connectivity.
func (b *ViciBackend) Status(ctx context.Context) (string, error) {
	var version string
	err := b.withSession(ctx, func(callCtx context.Context, session *vici.Session) error {
		msg, err := session.Call(callCtx, "version", nil)
		if err != nil {
			return fmt.Errorf("ipsec: version command failed: %w", err)
		}
		version = fmt.Sprintf("%v %v on %v",
			msg.Get("daemon"), msg.Get("version"), msg.Get("sysname"))
		return nil
	})
	if err != nil {
		return "", err
	}
	return version, nil
}

// Load loads every connection defined in swanctl.conf into charon
// (the load-all VICI command).
func (b *ViciBackend) Load(ctx context.Context) error {
	return b.withSession(ctx, func(callCtx context.Context, session *vici.Session) error {
		if _, err := session.Call(callCtx, "load-all", nil); err != nil {
			return fmt.Errorf("ipsec: load-all failed: %w", err)
		}
		b.log.Debug("loaded swanctl configuration")
		return nil
	})
}

// Initiate starts the CHILD_SA for a UE. In passive mode, which is the SWu
// model, it only makes sure the connection is loaded and reports ErrPending.
func (b *ViciBackend) Initiate(ctx context.Context, ueID string) error {
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

	return b.withSession(ctx, func(callCtx context.Context, session *vici.Session) error {
		in := vici.NewMessage()
		if err := in.Set("ike", b.connection); err != nil {
			return fmt.Errorf("ipsec: cannot build initiate request: %w", err)
		}
		if err := in.Set("child", child); err != nil {
			return fmt.Errorf("ipsec: cannot build initiate request: %w", err)
		}
		for msg, err := range session.CallStreaming(callCtx, "initiate", "control-log", in) {
			if err != nil {
				return fmt.Errorf("ipsec: initiate %s failed: %w", child, err)
			}
			if line, ok := msg.Get("msg").(string); ok {
				b.log.Debug("charon", "message", line)
			}
		}
		return nil
	})
}

// Terminate tears down the CHILD_SA for a UE.
func (b *ViciBackend) Terminate(ctx context.Context, ueID string) error {
	if ueID == "" {
		return fmt.Errorf("ipsec: ue_id is required")
	}
	child := ChildName(config.IPSec{ChildName: b.childName, ChildPrefix: b.childPrefix}, ueID)
	return b.withSession(ctx, func(callCtx context.Context, session *vici.Session) error {
		in := vici.NewMessage()
		if err := in.Set("ike", b.connection); err != nil {
			return fmt.Errorf("ipsec: cannot build terminate request: %w", err)
		}
		if err := in.Set("child", child); err != nil {
			return fmt.Errorf("ipsec: cannot build terminate request: %w", err)
		}
		for _, err := range session.CallStreaming(callCtx, "terminate", "control-log", in) {
			if err != nil {
				return fmt.Errorf("ipsec: terminate %s failed: %w", child, err)
			}
		}
		return nil
	})
}

// SAInfo summarises one IKE_SA and its CHILD_SAs as reported by list-sas.
type SAInfo struct {
	Name     string
	State    string
	Children map[string]string
}

// ListSAs returns the IKE_SAs currently known to charon.
func (b *ViciBackend) ListSAs(ctx context.Context) (map[string]SAInfo, error) {
	out := map[string]SAInfo{}
	err := b.withSession(ctx, func(callCtx context.Context, session *vici.Session) error {
		msg, err := session.Call(callCtx, "list-sas", nil)
		if err != nil {
			return fmt.Errorf("ipsec: list-sas failed: %w", err)
		}
		for _, name := range msg.Keys() {
			ike := asMessage(msg.Get(name))
			if ike == nil {
				continue
			}
			info := SAInfo{Name: name, State: stringOf(ike.Get("state")), Children: map[string]string{}}
			if children := asMessage(ike.Get("child-sas")); children != nil {
				for _, child := range children.Keys() {
					if cm := asMessage(children.Get(child)); cm != nil {
						info.Children[child] = stringOf(cm.Get("state"))
					}
				}
			}
			out[name] = info
		}
		return nil
	})
	return out, err
}

func asMessage(v any) *vici.Message {
	switch t := v.(type) {
	case *vici.Message:
		return t
	case []*vici.Message:
		if len(t) > 0 {
			return t[0]
		}
	}
	return nil
}

func stringOf(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
