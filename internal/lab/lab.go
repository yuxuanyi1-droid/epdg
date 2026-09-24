// Package lab manages the containerised ePDG/EPC/IMS lab described by
// deploy/lab.yaml. That file is the single source of truth: `render` turns it
// into the per-container configuration and the addresses docker-compose needs,
// and `serve` exposes it to the configuration UI.
package lab

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Lab is the root of deploy/lab.yaml.
type Lab struct {
	Network     Network     `yaml:"network" json:"network"`
	PLMN        PLMN        `yaml:"plmn" json:"plmn"`
	Credentials Credentials `yaml:"credentials" json:"credentials"`
	EPDG        EPDG        `yaml:"epdg" json:"epdg"`
	Open5GS     Open5GS     `yaml:"open5gs" json:"open5gs"`
	ENB         ENB         `yaml:"enb" json:"enb"`
}

// Network holds the bridge definition and the static address of every node.
type Network struct {
	Name        string            `yaml:"name" json:"name"`
	Subnet      string            `yaml:"subnet" json:"subnet"`
	Nodes       map[string]string `yaml:"nodes" json:"nodes"`
	HostAddress string            `yaml:"host_address" json:"host_address"`
}

// Node returns the address of a named node.
func (n Network) Node(name string) string { return n.Nodes[name] }

// PLMN is the home network identity in both MNC widths.
type PLMN struct {
	MCC  string `yaml:"mcc" json:"mcc"`
	MNC  string `yaml:"mnc" json:"mnc"`
	MNC3 string `yaml:"mnc3" json:"mnc3"`
}

// Realm renders the 3GPP network realm, for example
// ims.mnc001.mcc001.3gppnetwork.org.
func (p PLMN) Realm() string {
	return fmt.Sprintf("ims.mnc%s.mcc%s.3gppnetwork.org", p.MNC3, p.MCC)
}

// Credentials are the secrets and the subscriber the lab provisions.
type Credentials struct {
	KamailioDBPassword string `yaml:"kamailio_db_password" json:"kamailio_db_password"`
	RadiusSecret       string `yaml:"radius_secret" json:"radius_secret"`
	IMSI               string `yaml:"imsi" json:"imsi"`
	KI                 string `yaml:"ki" json:"ki"`
	OPC                string `yaml:"opc" json:"opc"`
}

// EPDG mirrors the ePDG control plane configuration.
type EPDG struct {
	Enabled bool   `yaml:"enabled" json:"enabled"`
	NodeID  string `yaml:"node_id" json:"node_id"`
	HTTP    struct {
		Listen string `yaml:"listen" json:"listen"`
	} `yaml:"http" json:"http"`
	IPSec struct {
		Backend        string `yaml:"backend" json:"backend"`
		Mode           string `yaml:"mode" json:"mode"`
		Socket         string `yaml:"socket" json:"socket"`
		ConnectionName string `yaml:"connection_name" json:"connection_name"`
		ChildName      string `yaml:"child_name" json:"child_name"`
	} `yaml:"ipsec" json:"ipsec"`
	AAA struct {
		Backend          string `yaml:"backend" json:"backend"`
		OriginHost       string `yaml:"origin_host" json:"origin_host"`
		OriginRealm      string `yaml:"origin_realm" json:"origin_realm"`
		DestinationHost  string `yaml:"destination_host" json:"destination_host"`
		DestinationRealm string `yaml:"destination_realm" json:"destination_realm"`
		EAPMaxRounds     int    `yaml:"eap_max_rounds" json:"eap_max_rounds"`
	} `yaml:"aaa" json:"aaa"`
	RADIUS struct {
		Backend string `yaml:"backend" json:"backend"`
		Listen  string `yaml:"listen" json:"listen"`
	} `yaml:"radius" json:"radius"`
	Protocol struct {
		SWu struct {
			LocalAddress string `yaml:"local_address" json:"local_address"`
			IKEPort      int    `yaml:"ike_port" json:"ike_port"`
			NATTPort     int    `yaml:"natt_port" json:"natt_port"`
		} `yaml:"swu" json:"swu"`
		S2b struct {
			Backend        string `yaml:"backend" json:"backend"`
			LocalAddress   string `yaml:"local_address" json:"local_address"`
			APN            string `yaml:"apn" json:"apn"`
			TimeoutSeconds int    `yaml:"timeout_seconds" json:"timeout_seconds"`
		} `yaml:"s2b" json:"s2b"`
	} `yaml:"protocol" json:"protocol"`
	UEPool Pool `yaml:"ue_pool" json:"ue_pool"`
}

// O5GSMME holds the base station facing MME parameters.
type O5GSMME struct {
	MMEName          string   `yaml:"mme_name" json:"mme_name"`
	MMEGID           int      `yaml:"mme_gid" json:"mme_gid"`
	MMECode          int      `yaml:"mme_code" json:"mme_code"`
	TAC              int      `yaml:"tac" json:"tac"`
	NetworkNameFull  string   `yaml:"network_name_full" json:"network_name_full"`
	NetworkNameShort string   `yaml:"network_name_short" json:"network_name_short"`
	IntegrityOrder   []string `yaml:"integrity_order" json:"integrity_order"`
	CipheringOrder   []string `yaml:"ciphering_order" json:"ciphering_order"`
}

// Open5GSSGW holds the serving gateway parameters.
type Open5GSSGW struct {
	GTPUAddress string `yaml:"gtpu_address" json:"gtpu_address"`
}

// Open5GS is the EPC configuration.
type Open5GS struct {
	Enabled    bool       `yaml:"enabled" json:"enabled"`
	HSSBackend string     `yaml:"hss_backend" json:"hss_backend"`
	MME        O5GSMME    `yaml:"mme" json:"mme"`
	SGW        Open5GSSGW `yaml:"sgw" json:"sgw"`
	UEPool     Pool       `yaml:"ue_pool" json:"ue_pool"`
	DNS        []string   `yaml:"dns" json:"dns"`
	GTPCPort   int        `yaml:"gtpc_port" json:"gtpc_port"`
	PFCPPort   int        `yaml:"pfcp_port" json:"pfcp_port"`
}

// Pool is an IP address pool with an optional DHCP-style range.
type Pool struct {
	Subnet     string `yaml:"subnet" json:"subnet"`
	Gateway    string `yaml:"gateway" json:"gateway"`
	RangeStart string `yaml:"range_start" json:"range_start,omitempty"`
	RangeEnd   string `yaml:"range_end" json:"range_end,omitempty"`
}

// ENB is the base station configuration (srsRAN enb.conf).
type ENB struct {
	Enabled bool `yaml:"enabled" json:"enabled"`
	Device  struct {
		Name string `yaml:"name" json:"name"`
		Args string `yaml:"args" json:"args"`
	} `yaml:"device" json:"device"`
	ENBID          string   `yaml:"enb_id" json:"enb_id"`
	MCC            string   `yaml:"mcc" json:"mcc"`
	MNC            string   `yaml:"mnc" json:"mnc"`
	TAC            int      `yaml:"tac" json:"tac"`
	S1CBindAddress string   `yaml:"s1c_bind_address" json:"s1c_bind_address"`
	GTPBindAddress string   `yaml:"gtp_bind_address" json:"gtp_bind_address"`
	NPRB           int      `yaml:"n_prb" json:"n_prb"`
	DLEARFCN       int      `yaml:"dl_earfcn" json:"dl_earfcn"`
	TXGain         int      `yaml:"tx_gain" json:"tx_gain"`
	RXGain         int      `yaml:"rx_gain" json:"rx_gain"`
	CipherAlgoPref []string `yaml:"cipher_algo_pref" json:"cipher_algo_pref"`
	IntegAlgoPref  []string `yaml:"integ_algo_pref" json:"integ_algo_pref"`
}

// Load reads and validates a lab definition.
func Load(path string) (*Lab, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("lab: cannot read %s: %w", path, err)
	}
	lab := &Lab{}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(lab); err != nil {
		return nil, fmt.Errorf("lab: cannot parse %s: %w", path, err)
	}
	if err := lab.Validate(); err != nil {
		return nil, fmt.Errorf("lab: %s: %w", path, err)
	}
	return lab, nil
}

// Save writes the lab definition back, which is how the UI persists edits.
func (l *Lab) Save(path string) error {
	if err := l.Validate(); err != nil {
		return err
	}
	body, err := yaml.Marshal(l)
	if err != nil {
		return fmt.Errorf("lab: cannot encode %s: %w", path, err)
	}
	header := "# Managed by labctl. Edit through the configuration UI or by hand;\n" +
		"# `labctl render` regenerates deploy/.env and deploy/runtime from this file.\n"
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(tmp, append([]byte(header), body...), 0o644); err != nil {
		return fmt.Errorf("lab: cannot write %s: %w", tmp, err)
	}
	return os.Rename(tmp, path)
}

// Validate rejects definitions that would produce a broken stack.
func (l *Lab) Validate() error {
	if l.Network.Name == "" {
		return fmt.Errorf("network.name must be set")
	}
	subnet, err := netip.ParsePrefix(l.Network.Subnet)
	if err != nil {
		return fmt.Errorf("network.subnet %q is not a CIDR prefix: %w", l.Network.Subnet, err)
	}
	// Every declared node must be a usable address inside the bridge subnet.
	seen := map[string]string{}
	for node, addr := range l.Network.Nodes {
		ip, err := netip.ParseAddr(addr)
		if err != nil {
			return fmt.Errorf("network.nodes.%s %q is not an IP address: %w", node, addr, err)
		}
		if !subnet.Contains(ip) {
			return fmt.Errorf("network.nodes.%s %s is outside network.subnet %s", node, addr, subnet)
		}
		if other, dup := seen[addr]; dup {
			return fmt.Errorf("network.nodes.%s and network.nodes.%s share the address %s", other, node, addr)
		}
		seen[addr] = node
	}
	// The containers this lab always needs.
	required := []string{
		"mariadb", "redis", "pyhss", "pcscf", "icscf", "scscf",
		"mme", "sgwc", "sgwu", "smf", "upf", "epdg",
	}
	for _, node := range required {
		if l.Network.Nodes[node] == "" {
			return fmt.Errorf("network.nodes.%s must be set", node)
		}
	}
	// Only needed when Open5GS runs its own HSS/PCRF instead of PyHSS.
	if l.Open5GS.HSSBackend == "open5gs" {
		for _, node := range []string{"o5gshss", "o5gpcrf", "mongo"} {
			if l.Network.Nodes[node] == "" {
				return fmt.Errorf("network.nodes.%s must be set when open5gs.hss_backend is open5gs", node)
			}
		}
	}
	if err := validatePool(l.Network.Subnet, l.EPDG.UEPool, "epdg.ue_pool"); err != nil {
		return err
	}
	if err := validatePool(l.Network.Subnet, l.Open5GS.UEPool, "open5gs.ue_pool"); err != nil {
		return err
	}
	if a, b := l.EPDG.UEPool.Subnet, l.Open5GS.UEPool.Subnet; a != "" && a == b {
		return fmt.Errorf("epdg.ue_pool and open5gs.ue_pool both use %s; they must not overlap", a)
	}
	if len(l.PLMN.MCC) != 3 {
		return fmt.Errorf("plmn.mcc %q must be three digits", l.PLMN.MCC)
	}
	if len(l.PLMN.MNC) < 2 || len(l.PLMN.MNC) > 3 {
		return fmt.Errorf("plmn.mnc %q must be two or three digits", l.PLMN.MNC)
	}
	if len(l.PLMN.MNC3) != 3 {
		return fmt.Errorf("plmn.mnc3 %q must be three digits (the IMS domain form)", l.PLMN.MNC3)
	}
	if len(l.Credentials.IMSI) != 15 {
		return fmt.Errorf("credentials.imsi %q must be 15 digits", l.Credentials.IMSI)
	}
	if len(l.Credentials.KI) != 32 || len(l.Credentials.OPC) != 32 {
		return fmt.Errorf("credentials.ki and credentials.opc must be 32 hex digits each")
	}
	switch l.Open5GS.HSSBackend {
	case "pyhss", "open5gs":
	default:
		return fmt.Errorf("open5gs.hss_backend must be pyhss or open5gs, got %q", l.Open5GS.HSSBackend)
	}
	switch l.EPDG.IPSec.Backend {
	case "vici", "swanctl", "noop":
	default:
		return fmt.Errorf("epdg.ipsec.backend must be vici, swanctl or noop, got %q", l.EPDG.IPSec.Backend)
	}
	if l.EPDG.Enabled && l.EPDG.Protocol.S2b.Backend == "gtpv2" && l.EPDG.Protocol.S2b.LocalAddress == "" {
		return fmt.Errorf("epdg.protocol.s2b.local_address is required for the gtpv2 backend")
	}
	return nil
}

func validatePool(subnet string, pool Pool, label string) error {
	if pool.Subnet == "" {
		return fmt.Errorf("%s.subnet must be set", label)
	}
	p, err := netip.ParsePrefix(pool.Subnet)
	if err != nil {
		return fmt.Errorf("%s.subnet %q is not a CIDR prefix: %w", label, pool.Subnet, err)
	}
	gw, err := netip.ParseAddr(pool.Gateway)
	if err != nil {
		return fmt.Errorf("%s.gateway %q is not an IP address: %w", label, pool.Gateway, err)
	}
	if !p.Contains(gw) {
		return fmt.Errorf("%s.gateway %s is outside %s", label, gw, p)
	}
	// The pools must not collide with the node addresses, otherwise a container
	// and a UE can end up with the same address.
	lab, err := netip.ParsePrefix(subnet)
	if err != nil {
		return fmt.Errorf("network.subnet %q is not a CIDR prefix: %w", subnet, err)
	}
	if lab.Overlaps(p) {
		return fmt.Errorf("%s.subnet %s overlaps network.subnet %s", label, p, lab)
	}
	if pool.RangeStart != "" {
		start, err := netip.ParseAddr(pool.RangeStart)
		if err != nil {
			return fmt.Errorf("%s.range_start %q is not an IP address: %w", label, pool.RangeStart, err)
		}
		if !p.Contains(start) {
			return fmt.Errorf("%s.range_start %s is outside %s", label, start, p)
		}
	}
	if pool.RangeEnd != "" {
		end, err := netip.ParseAddr(pool.RangeEnd)
		if err != nil {
			return fmt.Errorf("%s.range_end %q is not an IP address: %w", label, pool.RangeEnd, err)
		}
		if !p.Contains(end) {
			return fmt.Errorf("%s.range_end %s is outside %s", label, end, p)
		}
	}
	return nil
}
