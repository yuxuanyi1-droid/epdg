package compliance

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"epdg-go/internal/config"
	"epdg-go/internal/s2b"
)

type Item struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Details string `json:"details"`
}

type Report struct {
	Profile string `json:"profile"`
	Passed  bool   `json:"passed"`
	Items   []Item `json:"items"`
}

type Checker struct {
	cfg       *config.Config
	s2bClient s2b.Client
}

func NewChecker(cfg *config.Config, s2bClient s2b.Client) *Checker {
	return &Checker{cfg: cfg, s2bClient: s2bClient}
}

func (c *Checker) Run(ctx context.Context) Report {
	items := []Item{
		c.checkSWuPorts(ctx),
		c.checkSWmReachability(ctx),
		c.checkS2bReachability(ctx),
		c.checkOpen5GSEPC(ctx),
		c.checkKamailioIMS(ctx),
		c.checkPyHSS(ctx),
	}

	passed := true
	for _, item := range items {
		if !item.Passed {
			passed = false
			break
		}
	}

	return Report{
		Profile: fmt.Sprintf("mcc=%s,mnc=%s", c.cfg.Protocol.PLMN.MCC, c.cfg.Protocol.PLMN.MNC),
		Passed:  passed,
		Items:   items,
	}
}

func (c *Checker) checkSWuPorts(ctx context.Context) Item {
	if c.cfg.Protocol.SWu.LocalAddress == "" {
		return Item{Name: "SWu", Passed: false, Details: "missing protocol.swu.local_address"}
	}
	details := fmt.Sprintf("expected UDP %d/%d on %s", c.cfg.Protocol.SWu.IKEPort, c.cfg.Protocol.SWu.NATTPort, c.cfg.Protocol.SWu.LocalAddress)
	return Item{Name: "SWu", Passed: true, Details: details}
}

func (c *Checker) checkSWmReachability(ctx context.Context) Item {
	if c.cfg.Protocol.SWm.PeerHost == "" || c.cfg.Protocol.SWm.Realm == "" {
		return Item{Name: "SWm", Passed: false, Details: "missing protocol.swm.peer_host or protocol.swm.realm"}
	}
	if c.cfg.AAA.Backend == "swm_diameter_eap" {
		ok, msg := run(ctx, "bash", "-lc", fmt.Sprintf("timeout 2 bash -lc 'cat </dev/null >/dev/tcp/%s/%d' >/dev/null 2>&1", c.cfg.Protocol.SWm.PeerHost, c.cfg.Protocol.SWm.Port))
		if !ok {
			return Item{Name: "SWm", Passed: false, Details: fmt.Sprintf("diameter peer not reachable: %s", msg)}
		}
		return Item{Name: "SWm", Passed: true, Details: fmt.Sprintf("diameter peer reachable %s:%d", c.cfg.Protocol.SWm.PeerHost, c.cfg.Protocol.SWm.Port)}
	}
	ok, msg := run(ctx, "bash", "-lc", fmt.Sprintf("timeout 2 bash -lc 'cat </dev/null >/dev/tcp/%s/%d' >/dev/null 2>&1", c.cfg.Protocol.SWm.PeerHost, c.cfg.Protocol.SWm.Port))
	if !ok {
		return Item{Name: "SWm", Passed: false, Details: fmt.Sprintf("diameter peer not reachable: %s", msg)}
	}
	return Item{Name: "SWm", Passed: true, Details: fmt.Sprintf("peer %s:%d reachable", c.cfg.Protocol.SWm.PeerHost, c.cfg.Protocol.SWm.Port)}
}

func (c *Checker) checkS2bReachability(ctx context.Context) Item {
	if c.cfg.Protocol.S2b.PGWAddress == "" {
		return Item{Name: "S2b", Passed: false, Details: "missing protocol.s2b.pgw_address"}
	}
	if c.s2bClient == nil {
		return Item{Name: "S2b", Passed: false, Details: "s2b client not initialized"}
	}
	if err := c.s2bClient.Ping(ctx); err != nil {
		return Item{Name: "S2b", Passed: false, Details: fmt.Sprintf("GTPv2 echo failed: %v", err)}
	}
	return Item{Name: "S2b", Passed: true, Details: fmt.Sprintf("GTPv2 echo ok %s:%d", c.cfg.Protocol.S2b.PGWAddress, c.cfg.Protocol.S2b.GTPv2Port)}
}

func (c *Checker) checkOpen5GSEPC(ctx context.Context) Item {
	okMME, _ := systemdActive(ctx, "open5gs-mmed")
	okSMF, _ := systemdActive(ctx, "open5gs-smfd")
	okUPF, _ := systemdActive(ctx, "open5gs-upfd")
	if okMME && okSMF && okUPF {
		return Item{Name: "Open5GS-EPC", Passed: true, Details: "mmed/smfd/upfd active"}
	}
	return Item{Name: "Open5GS-EPC", Passed: false, Details: "expect open5gs-mmed/open5gs-smfd/open5gs-upfd active"}
}

func (c *Checker) checkKamailioIMS(ctx context.Context) Item {
	ok, msg := run(ctx, "bash", "-lc", "ss -lunp | rg -q '10.46.0.2:5060|10.46.0.2:5061|10.46.0.2:5062'")
	if !ok {
		return Item{Name: "Kamailio-IMS", Passed: false, Details: fmt.Sprintf("SIP listeners not ready: %s", msg)}
	}
	return Item{Name: "Kamailio-IMS", Passed: true, Details: "P/I/S-CSCF listeners detected"}
}

func (c *Checker) checkPyHSS(ctx context.Context) Item {
	okHSS, _ := systemdActive(ctx, "pyhss_hss")
	okDia, _ := systemdActive(ctx, "pyhss_diameter")
	if okHSS && okDia {
		return Item{Name: "PyHSS", Passed: true, Details: "hss and diameter services active"}
	}
	return Item{Name: "PyHSS", Passed: false, Details: "expect pyhss_hss and pyhss_diameter active"}
}

func systemdActive(ctx context.Context, unit string) (bool, string) {
	return run(ctx, "systemctl", "is-active", "--quiet", unit)
}

func run(parent context.Context, name string, args ...string) (bool, string) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return false, msg
	}
	return true, strings.TrimSpace(string(out))
}
