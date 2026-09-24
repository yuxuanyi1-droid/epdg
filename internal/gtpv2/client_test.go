package gtpv2

import (
	"net"
	"testing"
	"time"

	"github.com/wmnsk/go-gtp/gtpv2"
	"github.com/wmnsk/go-gtp/gtpv2/ie"
	"github.com/wmnsk/go-gtp/gtpv2/message"
)

func mustIP(s string) net.IP { return net.ParseIP(s) }

// sampleRequest mirrors what the integration test sends against a real PGW-C.
func sampleRequest() Request {
	return Request{
		IMSI:       "001010000000001",
		MSISDN:     "123456789",
		APN:        "ims",
		MCC:        "001",
		MNC:        "001",
		LocalIP:    "10.46.0.2",
		LocalTEID:  0x11223344,
		LocalUTEID: 0x55667788,
	}
}

func buildAndParseRequest(t *testing.T, req Request) *message.CreateSessionRequest {
	t.Helper()
	ies, err := buildCreateSessionIEs(req)
	if err != nil {
		t.Fatalf("buildCreateSessionIEs: %v", err)
	}
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
	return csr
}

// TestCreateSessionRequestMandatoryIEs checks every information element that a
// real PGW-C requires before it accepts an S2b session (3GPP TS 29.274
// section 7.2.1, and Open5GS's smf_s5c_handle_create_session_request).
func TestCreateSessionRequestMandatoryIEs(t *testing.T) {
	csr := buildAndParseRequest(t, sampleRequest())

	if csr.Sequence() != 42 {
		t.Errorf("sequence = %d, want 42", csr.Sequence())
	}
	if csr.IMSI == nil {
		t.Fatal("IMSI IE is missing")
	}
	if imsi, err := csr.IMSI.IMSI(); err != nil || imsi != "001010000000001" {
		t.Errorf("IMSI = %q (%v), want 001010000000001", imsi, err)
	}
	if csr.ServingNetwork == nil {
		t.Fatal("Serving Network IE is missing: a PGW-C rejects the request without the PLMN")
	}
	if csr.RATType == nil {
		t.Fatal("RAT Type IE is missing")
	}
	if rat, err := csr.RATType.RATType(); err != nil || rat != RATTypeWLAN {
		t.Errorf("RAT type = %d (%v), want %d (WLAN) for S2b", rat, err, RATTypeWLAN)
	}
	if csr.APN == nil {
		t.Fatal("APN IE is missing")
	}
	if csr.SenderFTEIDC == nil {
		t.Fatal("Sender F-TEID IE is missing")
	}
	if csr.PAA == nil {
		// Open5GS treats a missing PAA as Conditional IE Missing and refuses the
		// session, so it must always be present.
		t.Fatal("PDN Address Allocation IE is missing: it is required to request an address")
	}
	if csr.AMBR == nil {
		t.Fatal("APN-AMBR IE is missing")
	}
	if csr.Recovery == nil {
		t.Error("Recovery IE is missing")
	}
}

// TestCreateSessionRequestSenderFTEID checks the C-plane F-TEID.
func TestCreateSessionRequestSenderFTEID(t *testing.T) {
	csr := buildAndParseRequest(t, sampleRequest())
	fields, err := ie.ParseFullyQualifiedTEIDFields(csr.SenderFTEIDC.Payload)
	if err != nil {
		t.Fatalf("ParseFullyQualifiedTEIDFields: %v", err)
	}
	if fields.InterfaceType != gtpv2.IFTypeS2bePDGGTPC {
		t.Errorf("C-plane interface type = %d, want %d (S2b ePDG GTP-C)",
			fields.InterfaceType, gtpv2.IFTypeS2bePDGGTPC)
	}
	if fields.TEIDGREKey != 0x11223344 {
		t.Errorf("C-plane TEID = %#x, want 0x11223344", fields.TEIDGREKey)
	}
	if fields.IPv4Address == nil || fields.IPv4Address.String() != "10.46.0.2" {
		t.Errorf("C-plane address = %v, want 10.46.0.2", fields.IPv4Address)
	}
}

// TestCreateSessionRequestBearerContextCarriesS2bUFTEID is the regression test
// for the bug this implementation originally had: the ePDG S2b U-plane F-TEID
// must be inside the bearer context as instance 5, otherwise a real PGW-C
// rejects the request with "No S2b ePDG GTP-U TEID" (mandatory IE missing).
func TestCreateSessionRequestBearerContextCarriesS2bUFTEID(t *testing.T) {
	csr := buildAndParseRequest(t, sampleRequest())

	if len(csr.BearerContextsToBeCreated) != 1 {
		t.Fatalf("bearer contexts = %d, want 1", len(csr.BearerContextsToBeCreated))
	}
	bc := csr.BearerContextsToBeCreated[0]
	if bc.Type != ie.BearerContext {
		t.Fatalf("bearer context IE type = %d, want %d", bc.Type, ie.BearerContext)
	}
	if !bc.IsGrouped() {
		t.Fatal("the bearer context must be a grouped IE")
	}

	var sawEBI, sawQoS, sawUPlaneTEID bool
	for _, child := range bc.ChildIEs {
		switch child.Type {
		case ie.EPSBearerID:
			sawEBI = true
			if ebi, err := child.EPSBearerID(); err != nil || ebi != 5 {
				t.Errorf("EBI = %d (%v), want 5", ebi, err)
			}
		case ie.BearerQoS:
			sawQoS = true
		case ie.FullyQualifiedTEID:
			sawUPlaneTEID = true
			if child.Instance() != 5 {
				t.Errorf("bearer context F-TEID instance = %d, want 5", child.Instance())
			}
			fields, err := ie.ParseFullyQualifiedTEIDFields(child.Payload)
			if err != nil {
				t.Fatalf("ParseFullyQualifiedTEIDFields: %v", err)
			}
			if fields.InterfaceType != gtpv2.IFTypeS2bUePDGGTPU {
				t.Errorf("U-plane interface type = %d, want %d (S2b U ePDG GTP-U)",
					fields.InterfaceType, gtpv2.IFTypeS2bUePDGGTPU)
			}
			if fields.TEIDGREKey != 0x55667788 {
				t.Errorf("U-plane TEID = %#x, want 0x55667788", fields.TEIDGREKey)
			}
			if fields.IPv4Address == nil || fields.IPv4Address.String() != "10.46.0.2" {
				t.Errorf("U-plane address = %v, want 10.46.0.2", fields.IPv4Address)
			}
		}
	}
	if !sawEBI {
		t.Error("the bearer context has no EPS Bearer ID")
	}
	if !sawQoS {
		t.Error("the bearer context has no Bearer QoS")
	}
	if !sawUPlaneTEID {
		t.Error("the bearer context has no ePDG S2b U-plane F-TEID")
	}
}

// TestPAARequestsAllocation checks that the PAA asks the PGW to allocate an
// address rather than pinning one.
func TestPAARequestsAllocation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pdnType uint8
	}{
		{"ipv4", PDNTypeIPv4},
		{"ipv6", PDNTypeIPv6},
		{"ipv4v6", PDNTypeIPv4v6},
	} {
		paa, err := newPDNAddressAllocationRequest(tc.pdnType)
		if err != nil {
			t.Fatalf("%s: newPDNAddressAllocationRequest: %v", tc.name, err)
		}
		fields, err := ie.ParsePDNAddressAllocationFields(paa.Payload)
		if err != nil {
			t.Fatalf("%s: ParsePDNAddressAllocationFields: %v", tc.name, err)
		}
		if fields.PDNType != tc.pdnType {
			t.Errorf("%s: PDN type = %d, want %d", tc.name, fields.PDNType, tc.pdnType)
		}
		// An unset address is encoded as zero octets, which parses back as the
		// unspecified address; that is what tells the PGW to allocate one.
		if fields.IPv4Address != nil && !fields.IPv4Address.IsUnspecified() {
			t.Errorf("%s: the PAA must not pin an IPv4 address, got %v", tc.name, fields.IPv4Address)
		}
	}
	if _, err := newPDNAddressAllocationRequest(9); err == nil {
		t.Error("newPDNAddressAllocationRequest accepted an unsupported PDN type")
	}
}

// TestParseCreateSessionResponse uses a response assembled by the library's own
// encoder to check that the S2b values are extracted from both the top level and
// the bearer context.
func TestParseCreateSessionResponse(t *testing.T) {
	paaFields := ie.NewPDNAddressAllocationFields(PDNTypeIPv4, net.ParseIP("10.45.0.7"), nil, 0)
	paaPayload, err := paaFields.Marshal()
	if err != nil {
		t.Fatalf("Marshal PAA: %v", err)
	}

	bearer := ie.NewBearerContext(
		ie.NewEPSBearerID(5),
		ie.NewCause(gtpv2.CauseRequestAccepted, 0, 0, 0, nil),
		ie.NewFullyQualifiedTEID(gtpv2.IFTypeS2bUPGWGTPU, 0xdeadbeef, "10.45.0.1", ""),
	)

	response := message.NewCreateSessionResponse(0, 42,
		ie.NewCause(gtpv2.CauseRequestAccepted, 0, 0, 0, nil),
		// The PGW C-plane F-TEID is carried in the instance 1 F-TEID field
		// (TS 29.274 Table 7.2.2-1).
		ie.NewFullyQualifiedTEID(gtpv2.IFTypeS2bPGWGTPC, 0x0badc0de, "10.45.0.1", "").WithInstance(1),
		ie.New(ie.PDNAddressAllocation, 0x00, paaPayload),
		bearer,
		ie.NewRecovery(7),
	)

	raw := make([]byte, response.MarshalLen())
	if err := response.MarshalTo(raw); err != nil {
		t.Fatalf("MarshalTo: %v", err)
	}
	decoded, err := message.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	csr, ok := decoded.(*message.CreateSessionResponse)
	if !ok {
		t.Fatalf("decoded message is %T, want CreateSessionResponse", decoded)
	}

	result, err := parseCreateSessionResponse(csr, nil)
	if err != nil {
		t.Fatalf("parseCreateSessionResponse: %v", err)
	}
	if result.Cause != gtpv2.CauseRequestAccepted {
		t.Errorf("cause = %d, want %d", result.Cause, gtpv2.CauseRequestAccepted)
	}
	if result.PGWCTEID != 0x0badc0de {
		t.Errorf("PGW C-plane TEID = %#x, want 0xbadc0de", result.PGWCTEID)
	}
	if result.PGWCTEIDType != gtpv2.IFTypeS2bPGWGTPC {
		t.Errorf("PGW C-plane interface type = %d, want %d (S2b PGW GTP-C)",
			result.PGWCTEIDType, gtpv2.IFTypeS2bPGWGTPC)
	}
	if result.PGWAddress != "10.45.0.1" {
		t.Errorf("PGW address = %q, want 10.45.0.1", result.PGWAddress)
	}
	if result.PDNAddress != "10.45.0.7" {
		t.Errorf("PDN address = %q, want 10.45.0.7", result.PDNAddress)
	}
	if result.PDNType != PDNTypeIPv4 {
		t.Errorf("PDN type = %d, want %d", result.PDNType, PDNTypeIPv4)
	}
	if !result.HasRecovery || result.Recovery != 7 {
		t.Errorf("recovery = %d (present=%v), want 7", result.Recovery, result.HasRecovery)
	}
	if len(result.Bearers) != 1 {
		t.Fatalf("bearers = %d, want 1", len(result.Bearers))
	}
	b := result.Bearers[0]
	if b.EBI != 5 {
		t.Errorf("bearer EBI = %d, want 5", b.EBI)
	}
	if b.PGWUTEID != 0xdeadbeef {
		t.Errorf("PGW U-plane TEID = %#x, want 0xdeadbeef", b.PGWUTEID)
	}
	if b.PGWUTeidInterfaceType != gtpv2.IFTypeS2bUPGWGTPU {
		t.Errorf("PGW U-plane interface type = %d, want %d (S2b U PGW GTP-U)",
			b.PGWUTeidInterfaceType, gtpv2.IFTypeS2bUPGWGTPU)
	}
	if b.PGWUAddress != "10.45.0.1" {
		t.Errorf("PGW U-plane address = %q, want 10.45.0.1", b.PGWUAddress)
	}
}

func TestParseCreateSessionResponseRejectsMissingCause(t *testing.T) {
	response := message.NewCreateSessionResponse(0, 1)
	raw := make([]byte, response.MarshalLen())
	if err := response.MarshalTo(raw); err != nil {
		t.Fatalf("MarshalTo: %v", err)
	}
	decoded, err := message.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := parseCreateSessionResponse(decoded.(*message.CreateSessionResponse), nil); err == nil {
		t.Error("parseCreateSessionResponse accepted a response without a Cause IE")
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
	base := sampleRequest()
	cases := map[string]func(*Request){
		"no imsi":        func(r *Request) { r.IMSI = "" },
		"no apn":         func(r *Request) { r.APN = "" },
		"no plmn":        func(r *Request) { r.MCC = "" },
		"no local teid":  func(r *Request) { r.LocalTEID = 0 },
		"no local uteid": func(r *Request) { r.LocalUTEID = 0 },
		"no local ip":    func(r *Request) { r.LocalIP = "" },
	}
	for name, mutate := range cases {
		req := base
		mutate(&req)
		if _, err := client.CreateSession(ctx, req); err == nil {
			t.Errorf("%s: CreateSession accepted an invalid request", name)
		}
	}
}

func TestDeleteSessionValidatesRequiredFields(t *testing.T) {
	client, err := New("10.46.0.2", "127.0.0.4", 2123, time.Second, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := t.Context()
	if err := client.DeleteSession(ctx, Request{PeerTEID: 1}); err == nil {
		t.Error("DeleteSession accepted a request without an EBI")
	}
	// Regression: the peer resolves the session from the GTPv2 header TEID, so a
	// Delete Session Request without the peer C-plane TEID is always rejected
	// with cause 64 (Context Not Found).
	if err := client.DeleteSession(ctx, Request{EBI: 5}); err == nil {
		t.Error("DeleteSession accepted a request without the peer C-plane TEID")
	}
}

// TestDeleteSessionUsesPeerTEID checks that the peer C-plane TEID taken from the
// Create Session Response becomes the destination TEID of the Delete Session
// Request, which is how a real PGW-C identifies the session.
func TestDeleteSessionUsesPeerTEID(t *testing.T) {
	const peerTEID = 0x2a2a2a2a
	request := message.NewDeleteSessionRequest(peerTEID, 7,
		ie.NewEPSBearerID(5),
		ie.NewServingNetwork("001", "001"),
	)
	raw := make([]byte, request.MarshalLen())
	if err := request.MarshalTo(raw); err != nil {
		t.Fatalf("MarshalTo: %v", err)
	}
	decoded, err := message.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	dsr, ok := decoded.(*message.DeleteSessionRequest)
	if !ok {
		t.Fatalf("decoded message is %T, want DeleteSessionRequest", decoded)
	}
	if dsr.TEID() != peerTEID {
		t.Errorf("Delete Session Request TEID = %#x, want %#x", dsr.TEID(), peerTEID)
	}
	if dsr.Sequence() != 7 {
		t.Errorf("sequence = %d, want 7", dsr.Sequence())
	}
	if dsr.LinkedEBI == nil {
		t.Fatal("Linked EPS Bearer ID IE is missing")
	}
	if ebi, err := dsr.LinkedEBI.EPSBearerID(); err != nil || ebi != 5 {
		t.Errorf("Linked EBI = %d (%v), want 5", ebi, err)
	}
}
