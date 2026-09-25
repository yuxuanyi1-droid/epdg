package ipsec

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
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

// Load loads the swanctl configuration into charon.
//
// Two things about this are easy to get wrong:
//
//   - There is no "load-all" VICI command. charon answers one with
//     pktCmdUnkown, which govici reports as "unexpected response type: 2";
//     swanctl's --load-all issues the four commands below instead.
//   - They must be plain requests, not streaming ones. Registering a
//     "control-log" subscription first fails against this charon, and the
//     failure surfaces as the same "unexpected response type: 2" message, which
//     makes it look like the command name is wrong when it is the subscription.
func (b *ViciBackend) Load(ctx context.Context) error {
	commands := []string{"load-creds", "load-authorities", "load-pools", "load-conns"}
	return b.withSession(ctx, func(callCtx context.Context, session *vici.Session) error {
		for _, cmd := range commands {
			if _, err := session.Call(callCtx, cmd, nil); err != nil {
				return fmt.Errorf("ipsec: %s failed: %w", cmd, err)
			}
		}
		b.log.Debug("loaded the swanctl configuration")
		return nil
	})
}

// Initiate starts the CHILD_SA for a UE.
//
// On SWu the UE is always the IKEv2 initiator, so the ePDG runs in passive mode:
// the connection already exists in charon (loaded from swanctl.conf by swanctl or
// by charon itself) and the correct answer is to report ErrPending and wait for
// the UE. No VICI call is made here on purpose: reloading the configuration is
// charon's lifecycle, not the ePDG's, and a failure to do so must not stop a
// session from being accepted.
func (b *ViciBackend) Initiate(ctx context.Context, ueID string) error {
	if ueID == "" {
		return fmt.Errorf("ipsec: ue_id is required")
	}
	child := ChildName(config.IPSec{ChildName: b.childName, ChildPrefix: b.childPrefix}, ueID)
	if b.mode == "passive" {
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
//
// It is idempotent: a session that is still pending has no CHILD_SA yet, because
// the UE has not brought IKEv2 up, and charon then answers "no matching SAs to
// terminate found". There is nothing to tear down in that case, so it is not an
// error; reporting one would leave the S2b session unreleased.
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
				if isNoSuchSA(err) {
					b.log.Debug("nothing to terminate, the CHILD_SA was never established", "child", child)
					return nil
				}
				return fmt.Errorf("ipsec: terminate %s failed: %w", child, err)
			}
		}
		return nil
	})
}

// isNoSuchSA reports whether charon's error means the requested SA is absent.
func isNoSuchSA(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no matching sa") || strings.Contains(msg, "no child sa")
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
