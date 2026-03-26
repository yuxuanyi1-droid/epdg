package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	NodeID   string   `yaml:"node_id"`
	HTTP     HTTP     `yaml:"http"`
	IPSec    IPSec    `yaml:"ipsec"`
	AAA      AAA      `yaml:"aaa"`
	Protocol Protocol `yaml:"protocol"`
}

type HTTP struct {
	Listen string `yaml:"listen"`
}

type IPSec struct {
	Backend        string `yaml:"backend"`
	Mode           string `yaml:"mode"`
	SwanctlBin     string `yaml:"swanctl_bin"`
	ConnectionName string `yaml:"connection_name"`
	ChildPrefix    string `yaml:"child_prefix"`
	ChildName      string `yaml:"child_name"`
}

type AAA struct {
	Backend          string `yaml:"backend"`
	OriginHost       string `yaml:"origin_host"`
	OriginRealm      string `yaml:"origin_realm"`
	DestinationHost  string `yaml:"destination_host"`
	DestinationRealm string `yaml:"destination_realm"`
	EAPProvider      string `yaml:"eap_provider"`
	EAPMaxRounds     int    `yaml:"eap_max_rounds"`
}

type Protocol struct {
	PLMN PLMN `yaml:"plmn"`
	SWu  SWu  `yaml:"swu"`
	SWm  SWm  `yaml:"swm"`
	S2b  S2b  `yaml:"s2b"`
}

type PLMN struct {
	MCC string `yaml:"mcc"`
	MNC string `yaml:"mnc"`
}

type SWu struct {
	LocalAddress string `yaml:"local_address"`
	IKEPort      int    `yaml:"ike_port"`
	NATTPort     int    `yaml:"natt_port"`
}

type SWm struct {
	PeerHost string `yaml:"peer_host"`
	Realm    string `yaml:"realm"`
	Port     int    `yaml:"port"`
}

type S2b struct {
	Backend    string `yaml:"backend"`
	PGWAddress string `yaml:"pgw_address"`
	GTPv2Port  int    `yaml:"gtpv2_port"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse yaml %s: %w", path, err)
	}

	if cfg.NodeID == "" {
		cfg.NodeID = "epdg.local"
	}
	if cfg.HTTP.Listen == "" {
		cfg.HTTP.Listen = ":9090"
	}
	if cfg.IPSec.Backend == "" {
		cfg.IPSec.Backend = "swanctl"
	}
	if cfg.IPSec.Mode == "" {
		cfg.IPSec.Mode = "active"
	}
	if cfg.IPSec.SwanctlBin == "" {
		cfg.IPSec.SwanctlBin = "/usr/sbin/swanctl"
	}
	if cfg.IPSec.ChildPrefix == "" {
		cfg.IPSec.ChildPrefix = "ue"
	}
	if cfg.AAA.Backend == "" {
		cfg.AAA.Backend = "noop"
	}
	if cfg.AAA.OriginHost == "" {
		cfg.AAA.OriginHost = "epdg.localdomain"
	}
	if cfg.AAA.OriginRealm == "" {
		cfg.AAA.OriginRealm = "localdomain"
	}
	if cfg.AAA.DestinationRealm == "" {
		cfg.AAA.DestinationRealm = cfg.Protocol.SWm.Realm
	}
	if cfg.AAA.EAPProvider == "" {
		cfg.AAA.EAPProvider = "unsupported"
	}
	if cfg.AAA.EAPMaxRounds == 0 {
		cfg.AAA.EAPMaxRounds = 4
	}
	if cfg.Protocol.SWu.IKEPort == 0 {
		cfg.Protocol.SWu.IKEPort = 500
	}
	if cfg.Protocol.SWu.NATTPort == 0 {
		cfg.Protocol.SWu.NATTPort = 4500
	}
	if cfg.Protocol.SWm.Port == 0 {
		cfg.Protocol.SWm.Port = 3868
	}
	if cfg.Protocol.S2b.GTPv2Port == 0 {
		cfg.Protocol.S2b.GTPv2Port = 2123
	}
	if cfg.Protocol.S2b.Backend == "" {
		cfg.Protocol.S2b.Backend = "gtpv2_echo"
	}

	return &cfg, nil
}
