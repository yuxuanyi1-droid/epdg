package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("cannot resolve the repository root: %v", err)
	}
	return abs
}

func loadDefaultLab(t *testing.T) *Lab {
	t.Helper()
	def, err := Load(filepath.Join(repoRoot(t), "deploy", "lab.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return def
}

// TestLoadAppliesIMSDefaults checks that a lab definition without an `ims`
// section still gets identities derived from the PLMN, so the render cannot
// silently disagree with the subscriber's IMS domain.
func TestLoadAppliesIMSDefaults(t *testing.T) {
	def := &Lab{PLMN: PLMN{MCC: "001", MNC: "01", MNC3: "001"}}
	def.applyDefaults()
	if def.IMS.Domain != "ims.mnc001.mcc001.3gppnetwork.org" {
		t.Errorf("ims.domain = %q, want ims.mnc001.mcc001.3gppnetwork.org", def.IMS.Domain)
	}
	if def.IMS.PCSCFFQDN != "pcscf.mnc001.mcc001.3gppnetwork.org" {
		t.Errorf("ims.pcscf_fqdn = %q", def.IMS.PCSCFFQDN)
	}
	if def.IMS.DiameterPort != 3868 || def.IMS.RTPEngineAddress != "localhost:9910" {
		t.Errorf("ims defaults = %+v", def.IMS)
	}
}

// TestRenderKamailioAppliesIMS checks that the values edited in the IMS panel
// reach the rendered CSCF configurations.
func TestRenderKamailioAppliesIMS(t *testing.T) {
	root := repoRoot(t)
	def := loadDefaultLab(t)
	def.IMS.Domain = "ims.mnc999.mcc999.3gppnetwork.org"
	def.IMS.PCSCFFQDN = "pcscf.mnc999.mcc999.3gppnetwork.org"
	def.IMS.PCRFFQDN = "pcrf.mnc999.mcc999.3gppnetwork.org"
	def.IMS.DiameterHSS = "hss.example.net"
	def.IMS.DiameterPort = 4242
	def.IMS.RTPEngineAddress = "rtpengine:22222"

	r := NewRenderer(root, t.TempDir(), def)
	if err := r.renderKamailio(); err != nil {
		t.Fatalf("renderKamailio: %v", err)
	}
	read := func(rel string) string {
		b, err := os.ReadFile(filepath.Join(r.RuntimeDir, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		return string(b)
	}

	pcscfXML := read("kamailio/pcscf/pcscf.xml")
	for _, want := range []string{
		`Realm="ims.mnc999.mcc999.3gppnetwork.org"`,
		`FQDN="pcscf.mnc999.mcc999.3gppnetwork.org"`,
		`FQDN="pcrf.mnc999.mcc999.3gppnetwork.org"`,
	} {
		if !strings.Contains(pcscfXML, want) {
			t.Errorf("pcscf.xml is missing %q", want)
		}
	}

	scscfXML := read("kamailio/scscf/scscf.xml")
	if !strings.Contains(scscfXML, `FQDN="hss.example.net"`) {
		t.Errorf("scscf.xml does not carry ims.diameter_hss:\n%s", scscfXML)
	}
	if !strings.Contains(scscfXML, `port="4242"`) {
		t.Errorf("scscf.xml does not carry ims.diameter_port:\n%s", scscfXML)
	}

	pcscfCfg := read("kamailio/pcscf/kamailio.cfg")
	if !strings.Contains(pcscfCfg, "udp:rtpengine:22222") {
		t.Error("pcscf kamailio.cfg does not carry ims.rtpengine_address")
	}
	if strings.Contains(pcscfCfg, "localhost:9910") {
		t.Error("pcscf kamailio.cfg still has the shipped rtpengine address")
	}
}

func TestValidateIMSRejectsBadValues(t *testing.T) {
	def := loadDefaultLab(t)
	def.IMS.RTPEngineAddress = "not-an-address"
	if err := def.Validate(); err == nil {
		t.Error("Validate accepted an rtpengine address without a port")
	}
	def = loadDefaultLab(t)
	def.IMS.DiameterPort = 0
	if err := def.Validate(); err == nil {
		t.Error("Validate accepted an empty diameter port")
	}
}
