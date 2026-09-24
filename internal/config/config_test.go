package config

import (
	"path/filepath"
	"testing"
)

func TestLoadShippedConfigurations(t *testing.T) {
	// Every configuration shipped in the repository must load and validate,
	// otherwise the documented run commands are broken.
	for _, name := range []string{"epdg.yaml", "epdg.std.yaml", "epdg.dev.yaml"} {
		path := filepath.Join("..", "..", "configs", "epdg", name)
		cfg, err := Load(path)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if cfg.NodeID == "" {
			t.Errorf("%s: node_id was not populated", name)
		}
		if cfg.Protocol.PLMN.String() == "" {
			t.Errorf("%s: PLMN was not populated", name)
		}
	}
}

func TestProductionProfileMatchesTheLayer(t *testing.T) {
	cfg, err := Load(filepath.Join("..", "..", "configs", "epdg", "epdg.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.IPSec.Backend != "vici" {
		t.Errorf("ipsec.backend = %q, want vici", cfg.IPSec.Backend)
	}
	if cfg.IPSec.Mode != "passive" {
		t.Errorf("ipsec.mode = %q, want passive for SWu", cfg.IPSec.Mode)
	}
	if cfg.AAA.Backend != "pyhss_api" {
		t.Errorf("aaa.backend = %q, want pyhss_api", cfg.AAA.Backend)
	}
	if cfg.RADIUS.Backend != "eap_aka" {
		t.Errorf("radius.backend = %q, want eap_aka", cfg.RADIUS.Backend)
	}
	if !cfg.RADIUS.RequireMessageAuthenticator {
		t.Error("radius.require_message_authenticator must default to true for EAP")
	}
	// The SWm flavoured endpoint omits CK and IK, so the AKA endpoint must be
	// the one used to source vectors.
	if cfg.AAA.PyHSS.VectorPathTemplate != "/auc/aka/vector_count/1/imsi/{imsi}" {
		t.Errorf("vector path template = %q", cfg.AAA.PyHSS.VectorPathTemplate)
	}
}

func TestValidateRejectsInconsistentProfiles(t *testing.T) {
	cases := map[string]func(*Config){
		"unknown ipsec backend":  func(c *Config) { c.IPSec.Backend = "ipsec-tools" },
		"unknown aaa backend":    func(c *Config) { c.AAA.Backend = "freeDiameter" },
		"unknown radius backend": func(c *Config) { c.RADIUS.Backend = "freeradius" },
		"unknown s2b backend":    func(c *Config) { c.Protocol.S2b.Backend = "gtpv1" },
		"bad mcc":                func(c *Config) { c.Protocol.PLMN.MCC = "01" },
		"bad mnc":                func(c *Config) { c.Protocol.PLMN.MNC = "1" },
		"eap_aka without pyhss":  func(c *Config) { c.AAA.Backend = "noop" },
		"eap_aka without secret": func(c *Config) { c.RADIUS.Secret = "" },
	}
	for name, mutate := range cases {
		cfg := Default()
		cfg.AAA.Backend = "pyhss_api"
		cfg.RADIUS.Backend = "eap_aka"
		cfg.RADIUS.Secret = "secret"
		mutate(cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: Validate accepted an invalid configuration", name)
		}
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	writeFile(t, path, "node_id: epdg\ntypo_field: 1\n")
	if _, err := Load(path); err == nil {
		t.Error("Load accepted a configuration with an unknown field")
	}
}

func TestDurationsFallBackToDefaults(t *testing.T) {
	ipsec := IPSec{}
	if ipsec.Timeout().Seconds() != 5 {
		t.Errorf("IPSec timeout default = %v, want 5s", ipsec.Timeout())
	}
	s2b := S2b{}
	if s2b.Timeout().Seconds() != 2 {
		t.Errorf("S2b timeout default = %v, want 2s", s2b.Timeout())
	}
	api := PyHSSAPI{}
	if api.Timeout().Seconds() != 5 {
		t.Errorf("PyHSS timeout default = %v, want 5s", api.Timeout())
	}
}
