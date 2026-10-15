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

// TestRenderKamailioAppliesRunParameters checks that the ims.kamailio panel
// values (worker counts, log level, SIP ports) reach the rendered configs,
// including the references one node carries to another node's port.
func TestRenderKamailioAppliesRunParameters(t *testing.T) {
	root := repoRoot(t)
	def := loadDefaultLab(t)
	def.IMS.Kamailio.Children = 24
	def.IMS.Kamailio.TCPChildren = 7
	def.IMS.Kamailio.Debug = 4
	def.IMS.Kamailio.PCSCFPort = 6060
	def.IMS.Kamailio.ICSCFPort = 6061
	def.IMS.Kamailio.SCSCFPort = 6062

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

	scscfCfg := read("kamailio/scscf/kamailio.cfg")
	if !strings.Contains(scscfCfg, "children=24") || strings.Contains(scscfCfg, "children=12") {
		t.Error("scscf kamailio.cfg did not take ims.kamailio.udp_children")
	}
	if !strings.Contains(scscfCfg, "TCP_PROCESSES 7") {
		t.Error("scscf kamailio.cfg did not take ims.kamailio.tcp_children")
	}
	if !strings.Contains(scscfCfg, "debug=4") || strings.Contains(scscfCfg, "debug=2") {
		t.Error("scscf kamailio.cfg did not take ims.kamailio.debug")
	}

	// The UDP listen socket and the node's own URI (feeding ims_auth and the
	// SAR) live in scscf.cfg, the included file; both must carry the new port.
	scscfCfgFile := read("kamailio/scscf/scscf.cfg")
	if !strings.Contains(scscfCfgFile, "listen=udp:"+def.Network.Node("scscf")+":6062") {
		t.Error("scscf.cfg did not take ims.kamailio.scscf_port on its listen socket")
	}
	if !strings.Contains(scscfCfgFile, `sip:`+def.Network.Node("scscf")+`:6062`) {
		t.Errorf("scscf.cfg lost its own URI port:\n%s", scscfCfgFile)
	}

	// The I-CSCF routes to the S-CSCF by literal; it must follow scscf_port.
	icscfCfg := read("kamailio/icscf/kamailio.cfg")
	if !strings.Contains(icscfCfg, def.Network.Node("scscf")+`:6062`) {
		t.Error("icscf $rd does not follow ims.kamailio.scscf_port")
	}
	if strings.Contains(icscfCfg, `127.0.0.1:5062`) {
		t.Error("icscf still carries the shipped S-CSCF address")
	}

	// The P-CSCF's dispatcher list points at the I-CSCF; it must follow icscf_port.
	dispatcher := read("kamailio/pcscf/dispatcher.list")
	if !strings.Contains(dispatcher, def.Network.Node("icscf")+":6061") {
		t.Errorf("pcscf dispatcher.list does not follow ims.kamailio.icscf_port: %s", dispatcher)
	}

	// The P-CSCF listen sockets follow pcscf_port.
	pcscfCfg := read("kamailio/pcscf/pcscf.cfg")
	if !strings.Contains(pcscfCfg, "listen=udp:"+def.Network.Node("pcscf")+":6060") {
		t.Error("pcscf.cfg did not take ims.kamailio.pcscf_port")
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
	def = loadDefaultLab(t)
	def.IMS.Kamailio.Debug = 9
	if err := def.Validate(); err == nil {
		t.Error("Validate accepted a debug level outside 0-5")
	}
	def = loadDefaultLab(t)
	def.IMS.Kamailio.ICSCFPort = def.IMS.Kamailio.PCSCFPort
	if err := def.Validate(); err == nil {
		t.Error("Validate accepted identical P/I-CSCF ports")
	}
}

// TestLoadAppliesKamailioDefaults checks that a lab.yaml without the
// ims.kamailio section still renders the shipped worker counts and ports
// instead of zeros.
func TestLoadAppliesKamailioDefaults(t *testing.T) {
	def := &Lab{PLMN: PLMN{MCC: "001", MNC: "01", MNC3: "001"}}
	def.applyDefaults()
	k := def.IMS.Kamailio
	if k.Children != 64 || k.TCPChildren != 16 || k.Debug != 2 {
		t.Errorf("ims.kamailio defaults = %+v, want children 64/16, debug 2", k)
	}
	if k.PCSCFPort != 5060 || k.ICSCFPort != 5061 || k.SCSCFPort != 5062 {
		t.Errorf("ims.kamailio port defaults = %+v", k)
	}
}

// TestSaveKeepsComments checks that a save made through the console merges the
// values into the existing document instead of re-encoding it, so hand written
// comments survive. This is what used to silently drop the note above
// network.nodes.aaa on every UI save.
func TestSaveKeepsComments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lab.yaml")
	src, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "lab.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, src, 0o644); err != nil {
		t.Fatal(err)
	}
	def, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// Edit through the "console": update an existing value and add a section
	// (ims.kamailio) the document does not carry yet.
	def.Network.Nodes["aaa"] = "10.99.0.99"
	def.IMS.Kamailio.Children = 24
	if err := def.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}

	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, want := range []string{
		"# The Gx/S6b Diameter peer. Open5GS's PGW-C requires both before it will",
		"aaa: 10.99.0.99",
		"udp_children: 24",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("saved file lost %q; got:\n%s", want, text)
		}
	}
	// The merged document must still parse and carry the new values.
	again, err := Load(path)
	if err != nil {
		t.Fatalf("reload after save: %v", err)
	}
	if again.Network.Nodes["aaa"] != "10.99.0.99" || again.IMS.Kamailio.Children != 24 {
		t.Errorf("reloaded values = %s/%d, want 10.99.0.99/24",
			again.Network.Nodes["aaa"], again.IMS.Kamailio.Children)
	}
}
