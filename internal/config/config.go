// Package config loads the ePDG YAML configuration. The schema is a superset
// of the one used by the earlier Python control plane so the existing files
// under configs/epdg keep working unchanged.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root of the ePDG configuration.
type Config struct {
	NodeID   string   `yaml:"node_id"`
	HTTP     HTTP     `yaml:"http"`
	IPSec    IPSec    `yaml:"ipsec"`
	AAA      AAA      `yaml:"aaa"`
	RADIUS   RADIUS   `yaml:"radius"`
	Protocol Protocol `yaml:"protocol"`
}

// HTTP configures the northbound management API.
type HTTP struct {
	Listen string `yaml:"listen"`
}

// IPSec selects how the control plane drives strongSwan.
type IPSec struct {
	// Backend is one of "vici", "swanctl" or "noop".
	Backend string `yaml:"backend"`
	// Mode is "passive" (wait for the UE to initiate, the SWu model) or
	// "active" (initiate the CHILD_SA ourselves).
	Mode string `yaml:"mode"`
	// Socket is the charon VICI socket used by the vici backend.
	Socket string `yaml:"socket"`
	// SwanctlBin is the swanctl binary used by the swanctl backend.
	SwanctlBin string `yaml:"swanctl_bin"`
	// ConnectionName is the swanctl connection the ePDG manages.
	ConnectionName string `yaml:"connection_name"`
	// ChildPrefix is used to synthesise per-UE CHILD_SA names.
	ChildPrefix string `yaml:"child_prefix"`
	// ChildName pins a single CHILD_SA name, overriding ChildPrefix.
	ChildName      string  `yaml:"child_name"`
	TimeoutSeconds float64 `yaml:"timeout_seconds"`
}

// Timeout returns the configured timeout as a duration.
func (i IPSec) Timeout() time.Duration {
	return duration(i.TimeoutSeconds, 5*time.Second)
}

// AAA selects the authentication backend that supplies AKA vectors.
type AAA struct {
	// Backend is "pyhss_api" or "noop".
	Backend string `yaml:"backend"`
	// OriginHost and OriginRealm populate Diameter identities where relevant.
	OriginHost       string `yaml:"origin_host"`
	OriginRealm      string `yaml:"origin_realm"`
	DestinationHost  string `yaml:"destination_host"`
	DestinationRealm string `yaml:"destination_realm"`
	// EAPMaxRounds bounds the EAP-AKA challenge/response rounds per session.
	EAPMaxRounds int `yaml:"eap_max_rounds"`
	// AllowUnknownIMSI permits sessions for IMSIs unknown to the HSS.
	AllowUnknownIMSI bool     `yaml:"allow_unknown_imsi"`
	PyHSS            PyHSSAPI `yaml:"pyhss_api"`
}

// PyHSSAPI configures the PyHSS REST client.
type PyHSSAPI struct {
	BaseURL string `yaml:"base_url"`
	// VectorPathTemplate must render to an endpoint returning a JSON array of
	// AKA quintuplets (rand, autn, xres, ck, ik) in hex. The object form used
	// by /auc/swm/eap_aka omits CK and IK, so the AKA endpoint is the default.
	VectorPathTemplate string  `yaml:"vector_path_template"`
	SWMPathTemplate    string  `yaml:"swm_path_template"`
	OAMPingPath        string  `yaml:"oam_ping_path"`
	TimeoutSeconds     float64 `yaml:"timeout_seconds"`
}

// Timeout returns the configured timeout as a duration.
func (p PyHSSAPI) Timeout() time.Duration {
	return duration(p.TimeoutSeconds, 5*time.Second)
}

// RADIUS configures the RADIUS EAP-AKA server that answers strongSwan's
// eap-radius plugin.
type RADIUS struct {
	// Backend is "eap_aka" or "noop".
	Backend string `yaml:"backend"`
	Listen  string `yaml:"listen"`
	// Secret is the shared secret configured in strongSwan's eap-radius plugin.
	Secret string `yaml:"secret"`
	// Realm is advertised in the RADIUS realm handling of the identity.
	Realm string `yaml:"realm"`
	// RequireMessageAuthenticator rejects requests without a valid
	// Message-Authenticator (RFC 3579 section 3.2).
	RequireMessageAuthenticator bool `yaml:"require_message_authenticator"`
	// SendCheckcode includes AT_CHECKCODE in the AKA challenge when true.
	SendCheckcode bool `yaml:"send_checkcode"`
}

// Protocol groups the 3GPP identifiers and reference points.
type Protocol struct {
	PLMN PLMN `yaml:"plmn"`
	SWu  SWu  `yaml:"swu"`
	SWm  SWm  `yaml:"swm"`
	S2b  S2b  `yaml:"s2b"`
}

// PLMN carries the home network identity.
type PLMN struct {
	MCC string `yaml:"mcc"`
	MNC string `yaml:"mnc"`
}

// String renders the five or six digit PLMN used by PyHSS path segments.
func (p PLMN) String() string {
	return p.MCC + p.MNC
}

// SWu carries the SWu (IKEv2/IPsec) reference point parameters.
type SWu struct {
	LocalAddress string `yaml:"local_address"`
	IKEPort      int    `yaml:"ike_port"`
	NATTPort     int    `yaml:"natt_port"`
}

// SWm carries the SWm (Diameter) reference point parameters.
type SWm struct {
	PeerHost string `yaml:"peer_host"`
	Realm    string `yaml:"realm"`
	Port     int    `yaml:"port"`
}

// S2b carries the S2b (GTPv2-C) reference point parameters.
type S2b struct {
	// Backend is "gtpv2" (real Create Session over GTPv2-C), "gtpv2_echo" or
	// "noop".
	Backend        string  `yaml:"backend"`
	PGWAddress     string  `yaml:"pgw_address"`
	GTPv2Port      int     `yaml:"gtpv2_port"`
	APN            string  `yaml:"apn"`
	LocalAddress   string  `yaml:"local_address"`
	TimeoutSeconds float64 `yaml:"timeout_seconds"`
	// IMSService indicates the IMS APN, which selects the IMS PDN type.
	IMSService bool `yaml:"ims_service"`
}

// Timeout returns the configured timeout as a duration.
func (s S2b) Timeout() time.Duration {
	return duration(s.TimeoutSeconds, 2*time.Second)
}

func duration(seconds float64, fallback time.Duration) time.Duration {
	if seconds <= 0 {
		return fallback
	}
	return time.Duration(seconds * float64(time.Second))
}

// Load reads and validates a configuration file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: cannot read %s: %w", path, err)
	}
	cfg := Default()
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("config: cannot parse %s: %w", path, err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	return cfg, nil
}

// Default returns the built-in defaults.
func Default() *Config {
	return &Config{
		NodeID: "epdg.local",
		HTTP:   HTTP{Listen: ":19090"},
		IPSec: IPSec{
			Backend:        "noop",
			Mode:           "passive",
			Socket:         "/run/charon.vici",
			SwanctlBin:     "/usr/sbin/swanctl",
			ConnectionName: "epdg-ike",
			ChildPrefix:    "ue",
			TimeoutSeconds: 5,
		},
		AAA: AAA{
			Backend:      "noop",
			EAPMaxRounds: 4,
			PyHSS: PyHSSAPI{
				BaseURL:            "http://127.0.0.1:8080",
				VectorPathTemplate: "/auc/aka/vector_count/1/imsi/{imsi}",
				SWMPathTemplate:    "/auc/swm/eap_aka/plmn/{plmn}/imsi/{imsi}",
				OAMPingPath:        "/oam/ping",
				TimeoutSeconds:     5,
			},
		},
		RADIUS: RADIUS{
			Backend:                     "noop",
			Listen:                      "127.0.0.1:18120",
			Secret:                      "pyhss-radius-secret",
			RequireMessageAuthenticator: true,
		},
		Protocol: Protocol{
			PLMN: PLMN{MCC: "001", MNC: "001"},
			SWu:  SWu{LocalAddress: "10.46.0.2", IKEPort: 500, NATTPort: 4500},
			SWm:  SWm{PeerHost: "127.0.0.8", Realm: "localdomain", Port: 3868},
			S2b: S2b{
				Backend:        "noop",
				PGWAddress:     "127.0.0.4",
				GTPv2Port:      2123,
				TimeoutSeconds: 2,
			},
		},
	}
}

func (c *Config) applyDefaults() {
	d := Default()
	if c.NodeID == "" {
		c.NodeID = d.NodeID
	}
	if c.HTTP.Listen == "" {
		c.HTTP.Listen = d.HTTP.Listen
	}
	if c.IPSec.Backend == "" {
		c.IPSec.Backend = d.IPSec.Backend
	}
	if c.IPSec.Mode == "" {
		c.IPSec.Mode = d.IPSec.Mode
	}
	if c.IPSec.Socket == "" {
		c.IPSec.Socket = d.IPSec.Socket
	}
	if c.IPSec.SwanctlBin == "" {
		c.IPSec.SwanctlBin = d.IPSec.SwanctlBin
	}
	if c.IPSec.ConnectionName == "" {
		c.IPSec.ConnectionName = d.IPSec.ConnectionName
	}
	if c.IPSec.ChildPrefix == "" {
		c.IPSec.ChildPrefix = d.IPSec.ChildPrefix
	}
	if c.AAA.Backend == "" {
		c.AAA.Backend = d.AAA.Backend
	}
	if c.AAA.EAPMaxRounds == 0 {
		c.AAA.EAPMaxRounds = d.AAA.EAPMaxRounds
	}
	if c.AAA.PyHSS.BaseURL == "" {
		c.AAA.PyHSS.BaseURL = d.AAA.PyHSS.BaseURL
	}
	if c.AAA.PyHSS.VectorPathTemplate == "" {
		c.AAA.PyHSS.VectorPathTemplate = d.AAA.PyHSS.VectorPathTemplate
	}
	if c.AAA.PyHSS.SWMPathTemplate == "" {
		c.AAA.PyHSS.SWMPathTemplate = d.AAA.PyHSS.SWMPathTemplate
	}
	if c.AAA.PyHSS.OAMPingPath == "" {
		c.AAA.PyHSS.OAMPingPath = d.AAA.PyHSS.OAMPingPath
	}
	if c.RADIUS.Backend == "" {
		c.RADIUS.Backend = d.RADIUS.Backend
	}
	if c.RADIUS.Listen == "" {
		c.RADIUS.Listen = d.RADIUS.Listen
	}
	if c.RADIUS.Secret == "" {
		c.RADIUS.Secret = d.RADIUS.Secret
	}
	if c.Protocol.PLMN.MCC == "" {
		c.Protocol.PLMN.MCC = d.Protocol.PLMN.MCC
	}
	if c.Protocol.PLMN.MNC == "" {
		c.Protocol.PLMN.MNC = d.Protocol.PLMN.MNC
	}
	if c.Protocol.S2b.Backend == "" {
		c.Protocol.S2b.Backend = d.Protocol.S2b.Backend
	}
	if c.Protocol.S2b.GTPv2Port == 0 {
		c.Protocol.S2b.GTPv2Port = d.Protocol.S2b.GTPv2Port
	}
}

// Validate checks the enumerated fields and required values.
func (c *Config) Validate() error {
	switch c.IPSec.Backend {
	case "vici", "swanctl", "noop":
	default:
		return fmt.Errorf("unsupported ipsec backend %q", c.IPSec.Backend)
	}
	switch c.IPSec.Mode {
	case "passive", "active":
	default:
		return fmt.Errorf("unsupported ipsec mode %q", c.IPSec.Mode)
	}
	switch c.AAA.Backend {
	case "pyhss_api", "noop":
	default:
		return fmt.Errorf("unsupported aaa backend %q", c.AAA.Backend)
	}
	switch c.RADIUS.Backend {
	case "eap_aka", "noop":
	default:
		return fmt.Errorf("unsupported radius backend %q", c.RADIUS.Backend)
	}
	switch c.Protocol.S2b.Backend {
	case "gtpv2", "gtpv2_echo", "noop":
	default:
		return fmt.Errorf("unsupported s2b backend %q", c.Protocol.S2b.Backend)
	}
	if len(c.Protocol.PLMN.MCC) != 3 {
		return fmt.Errorf("plmn mcc %q must be three digits", c.Protocol.PLMN.MCC)
	}
	if l := len(c.Protocol.PLMN.MNC); l != 2 && l != 3 {
		return fmt.Errorf("plmn mnc %q must be two or three digits", c.Protocol.PLMN.MNC)
	}
	if c.AAA.Backend == "pyhss_api" && c.AAA.PyHSS.BaseURL == "" {
		return fmt.Errorf("aaa.pyhss_api.base_url must be set when aaa.backend is pyhss_api")
	}
	if c.RADIUS.Backend == "eap_aka" {
		if c.AAA.Backend != "pyhss_api" {
			return fmt.Errorf("radius.backend eap_aka requires aaa.backend pyhss_api to source AKA vectors")
		}
		if c.RADIUS.Secret == "" {
			return fmt.Errorf("radius.secret must be set when radius.backend is eap_aka")
		}
	}
	return nil
}
