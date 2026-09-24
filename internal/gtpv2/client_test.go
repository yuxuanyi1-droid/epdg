package gtpv2

import (
	"testing"
	"time"

	"github.com/wmnsk/go-gtp/gtpv2/message"
)

// TestCreateSessionRequestRoundTrip encodes the S2b Create Session Request we
// generate and decodes it again with the library's own parser, asserting that
// every mandatory information element survives the wire format
// (3GPP TS 29.274 section 7.2.1).
func TestCreateSessionRequestRoundTrip(t *testing.T) {
	ies := buildCreateSessionIEs(Request{
		IMSI:      "001010000000001",
		MSISDN:    "123456789",
		APN:       "ims",
		MCC:       "001",
		MNC:       "001",
		LocalIP:   "10.46.0.2",
		LocalTEID: 0x11223344,
	})
	request := message.NewCreateSessionRequest(0, 42, ies...)

	raw := make([]byte, request.MarshalLen())
	if err := request.MarshalTo(raw); err != nil {
		t.Fatalf("MarshalTo: %v", err)
	}
	decoded, err := message.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	csr, ok := decoded.(*message.CreateSessionRequest)
	if !ok {
		t.Fatalf("decoded message is %T, want CreateSessionRequest", decoded)
	}
	if csr.Sequence() != 42 {
		t.Errorf("sequence = %d, want 42", csr.Sequence())
	}

	if csr.IMSI == nil {
		t.Fatal("IMSI IE is missing")
	}
	if imsi, err := csr.IMSI.IMSI(); err != nil || imsi != "001010000000001" {
		t.Errorf("IMSI = %q (%v)", imsi, err)
	}
	if csr.ServingNetwork == nil {
		t.Fatal("Serving Network IE is missing")
	}
	if csr.RATType == nil {
		t.Fatal("RAT Type IE is missing")
	}
	if rat, err := csr.RATType.RATType(); err != nil || rat != RATTypeWLAN {
		t.Errorf("RAT type = %d (%v), want %d (WLAN)", rat, err, RATTypeWLAN)
	}
	if csr.APN == nil {
		t.Fatal("APN IE is missing")
	}
	if csr.SenderFTEIDC == nil {
		t.Fatal("Sender F-TEID IE is missing")
	}
	if csr.PDNType == nil {
		t.Fatal("PDN Type IE is missing")
	}
	if csr.AMBR == nil {
		t.Fatal("APN-AMBR IE is missing")
	}
	if len(csr.BearerContextsToBeCreated) == 0 {
		t.Fatal("Bearer Context IE is missing")
	}
}

func TestNewRejectsIncompleteConfiguration(t *testing.T) {
	if _, err := New("10.0.0.1", "", 2123, time.Second, nil); err == nil {
		t.Error("New accepted an empty peer address")
	}
	if _, err := New("not-an-ip", "127.0.0.4", 2123, time.Second, nil); err == nil {
		t.Error("New accepted an invalid local address")
	}
}

func TestCreateSessionValidatesRequiredFields(t *testing.T) {
	client, err := New("10.46.0.2", "127.0.0.4", 2123, time.Second, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := t.Context()
	cases := map[string]Request{
		"no imsi":       {APN: "ims", MCC: "001", MNC: "001", LocalIP: "10.46.0.2", LocalTEID: 1},
		"no apn":        {IMSI: "001010000000001", MCC: "001", MNC: "001", LocalIP: "10.46.0.2", LocalTEID: 1},
		"no plmn":       {IMSI: "001010000000001", APN: "ims", LocalIP: "10.46.0.2", LocalTEID: 1},
		"no local teid": {IMSI: "001010000000001", APN: "ims", MCC: "001", MNC: "001", LocalIP: "10.46.0.2"},
		"no local ip":   {IMSI: "001010000000001", APN: "ims", MCC: "001", MNC: "001", LocalTEID: 1},
	}
	for name, req := range cases {
		if _, err := client.CreateSession(ctx, req); err == nil {
			t.Errorf("%s: CreateSession accepted an invalid request", name)
		}
	}
}
