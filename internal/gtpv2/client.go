// Package gtpv2 implements the S2b control plane between the ePDG and the
// SGW/PGW. Messages are encoded and decoded with github.com/wmnsk/go-gtp, which
// implements GTPv2-C as specified in 3GPP TS 29.274; this package only provides
// the S2b specific message composition and the transaction handling.
package gtpv2

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/wmnsk/go-gtp/gtpv2"
	"github.com/wmnsk/go-gtp/gtpv2/ie"
	"github.com/wmnsk/go-gtp/gtpv2/message"
)

// RAT types used on S2b (3GPP TS 29.274 section 8.17): untrusted non-3GPP
// access through an ePDG is reported as WLAN.
const RATTypeWLAN uint8 = 3

// PDN types (3GPP TS 29.274 section 8.34).
const (
	PDNTypeIPv4   uint8 = 1
	PDNTypeIPv6   uint8 = 2
	PDNTypeIPv4v6 uint8 = 3
)

// Request describes the S2b session to establish.
type Request struct {
	IMSI   string
	MSISDN string
	APN    string
	MCC    string
	MNC    string
	// LocalIP is the ePDG address advertised in both F-TEIDs.
	LocalIP string
	// LocalTEID is the ePDG S2b C-plane (GTP-C) TEID.
	LocalTEID uint32
	// LocalUTEID is the ePDG S2b U-plane (GTP-U) TEID. TS 29.274 requires the
	// ePDG to advertise it in the bearer context so the PGW-U can build the
	// downlink tunnel.
	LocalUTEID uint32
	// PeerTEID is the peer's C-plane TEID, taken from the Create Session
	// Response. It is the destination TEID of every later transaction of the
	// same session, such as Delete Session, and the peer resolves the session
	// from the GTPv2 header TEID (3GPP TS 29.274 section 7.2.9).
	PeerTEID uint32
	PDNType  uint8
	EBI      uint8
	QCI      uint8
	// PriorityLevel is the ARP priority level carried in the bearer QoS.
	PriorityLevel uint8
	AMBRUp        uint32
	AMBRDown      uint32
	RATType       uint8
}

// BearerResult carries the per-bearer values of a Create Session Response.
type BearerResult struct {
	EBI uint8
	// PGWUTEID and PGWUAddress are the PGW-U S2b U-plane endpoint, which the
	// ePDG needs to program its own GTP-U side.
	PGWUTEID    uint32
	PGWUAddress string
	// PGWUTeidInterfaceType records which interface type the peer used, so the
	// caller can tell an S2b reply from an S5/S8 one.
	PGWUTeidInterfaceType uint8
}

// Result carries the values extracted from a Create Session Response.
type Result struct {
	Cause uint8
	// PGWCTEID and PGWAddress identify the peer's C-plane endpoint.
	PGWCTEID     uint32
	PGWAddress   string
	PGWCTEIDType uint8
	PDNAddress   string
	PDNType      uint8
	Bearers      []BearerResult
	Recovery     uint8
	HasRecovery  bool
}

// Client is a transaction oriented S2b GTPv2-C client.
type Client struct {
	peer    *net.UDPAddr
	localIP string
	timeout time.Duration
	log     *slog.Logger
	seq     uint32
}

// New builds a client that talks to the SGW-C/PGW-C at peerAddress:port.
func New(localIP, peerAddress string, port int, timeout time.Duration, log *slog.Logger) (*Client, error) {
	if peerAddress == "" {
		return nil, errors.New("gtpv2: peer address is required")
	}
	if port == 0 {
		port = 2123
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	if log == nil {
		log = slog.Default()
	}
	peer, err := net.ResolveUDPAddr("udp", net.JoinHostPort(peerAddress, fmt.Sprintf("%d", port)))
	if err != nil {
		return nil, fmt.Errorf("gtpv2: cannot resolve peer %s: %w", peerAddress, err)
	}
	if localIP != "" && net.ParseIP(localIP) == nil {
		return nil, fmt.Errorf("gtpv2: local address %q is not a valid IP address", localIP)
	}
	return &Client{peer: peer, localIP: localIP, timeout: timeout, log: log}, nil
}

// Peer returns the configured peer address.
func (c *Client) Peer() string { return c.peer.String() }

func (c *Client) nextSequence() uint32 {
	c.seq = (c.seq + 1) & 0x00FFFFFF
	return c.seq
}

// roundTrip sends one request and waits for the matching response.
func (c *Client) roundTrip(ctx context.Context, request message.Message, wantType uint8) (message.Message, error) {
	var laddr *net.UDPAddr
	if c.localIP != "" {
		ip := net.ParseIP(c.localIP)
		if ip == nil {
			return nil, fmt.Errorf("gtpv2: local address %q is not a valid IP address", c.localIP)
		}
		laddr = &net.UDPAddr{IP: ip}
	}
	conn, err := net.DialUDP("udp", laddr, c.peer)
	if err != nil {
		return nil, fmt.Errorf("gtpv2: cannot open UDP socket to %s: %w", c.peer, err)
	}
	defer conn.Close()

	deadline := time.Now().Add(c.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("gtpv2: cannot set deadline: %w", err)
	}

	raw := make([]byte, request.MarshalLen())
	if err := request.MarshalTo(raw); err != nil {
		return nil, fmt.Errorf("gtpv2: cannot encode %s: %w", request.MessageTypeName(), err)
	}
	if _, err := conn.Write(raw); err != nil {
		return nil, fmt.Errorf("gtpv2: cannot send %s: %w", request.MessageTypeName(), err)
	}

	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) || isTimeout(err) {
				return nil, fmt.Errorf("gtpv2: no %s from %s within %s", messageTypeName(wantType), c.peer, c.timeout)
			}
			return nil, fmt.Errorf("gtpv2: read failed: %w", err)
		}
		response, err := message.Parse(buf[:n])
		if err != nil {
			return nil, fmt.Errorf("gtpv2: cannot decode response: %w", err)
		}
		if response.MessageType() == wantType {
			if response.Sequence() != request.Sequence() {
				// A stale response from an earlier transaction.
				continue
			}
			return response, nil
		}
		c.log.Debug("gtpv2: ignoring unrelated message",
			"received", response.MessageTypeName(), "want", messageTypeName(wantType))
	}
}

func isTimeout(err error) bool {
	var nerr net.Error
	return errors.As(err, &nerr) && nerr.Timeout()
}

// ueTimeZone builds the optional UE Time Zone IE from the host's current UTC
// offset (3GPP TS 29.274 section 8.44).
func ueTimeZone() *ie.IE {
	_, offsetSeconds := time.Now().Zone()
	return ie.NewUETimeZone(time.Duration(offsetSeconds)*time.Second, 0)
}

func messageTypeName(t uint8) string {
	switch t {
	case message.MsgTypeEchoResponse:
		return "Echo Response"
	case message.MsgTypeCreateSessionResponse:
		return "Create Session Response"
	case message.MsgTypeDeleteSessionResponse:
		return "Delete Session Response"
	default:
		return fmt.Sprintf("message type %d", t)
	}
}

// Echo performs a GTPv2-C Echo Request/Response exchange (3GPP TS 29.274
// section 7.1). It is used as a liveness check towards the S2b peer.
func (c *Client) Echo(ctx context.Context) error {
	request := message.NewEchoRequest(c.nextSequence(), ie.NewRecovery(0))
	response, err := c.roundTrip(ctx, request, message.MsgTypeEchoResponse)
	if err != nil {
		return err
	}
	echo, ok := response.(*message.EchoResponse)
	if !ok {
		return fmt.Errorf("gtpv2: unexpected echo response type %T", response)
	}
	if echo.Recovery == nil {
		return errors.New("gtpv2: echo response lacks the mandatory Recovery IE")
	}
	recovery, err := echo.Recovery.Recovery()
	if err != nil {
		return fmt.Errorf("gtpv2: cannot decode Recovery IE: %w", err)
	}
	c.log.Debug("gtpv2: echo response", "peer", c.peer.String(), "recovery", recovery)
	return nil
}

// buildCreateSessionIEs assembles the information elements of an S2b Create
// Session Request as required by 3GPP TS 29.274 section 7.2.1 and as accepted
// by a real PGW-C. Defaults are applied for optional fields.
//
// Note that a WLAN (S2b) session must carry the ePDG S2b U-plane F-TEID inside
// the bearer context, otherwise the PGW rejects the request with
// "No S2b ePDG GTP-U TEID" (mandatory IE missing). The reference composition is
// Open5GS's own ePDG test harness, tests/non3gpp/s2b-build.c.
func buildCreateSessionIEs(req Request) ([]*ie.IE, error) {
	pdnType := req.PDNType
	if pdnType == 0 {
		pdnType = PDNTypeIPv4
	}
	ratType := req.RATType
	if ratType == 0 {
		ratType = RATTypeWLAN
	}
	ebi := req.EBI
	if ebi == 0 {
		ebi = 5
	}
	qci := req.QCI
	if qci == 0 {
		qci = 9
	}
	priority := req.PriorityLevel
	if priority == 0 {
		priority = 1
	}
	ambrUp := req.AMBRUp
	if ambrUp == 0 {
		ambrUp = 100000
	}
	ambrDown := req.AMBRDown
	if ambrDown == 0 {
		ambrDown = 100000
	}

	paa, err := newPDNAddressAllocationRequest(pdnType)
	if err != nil {
		return nil, err
	}

	// Bearer Context: EBI, the ePDG S2b-U F-TEID (instance 5) and the QoS.
	bearerContext := ie.NewBearerContext(
		ie.NewEPSBearerID(ebi),
		ie.NewFullyQualifiedTEID(gtpv2.IFTypeS2bUePDGGTPU, req.LocalUTEID, req.LocalIP, "").WithInstance(5),
		ie.NewBearerQoS(priority, 0, 0, qci, uint64(ambrUp), uint64(ambrDown), 0, 0),
	)

	ies := []*ie.IE{
		ie.NewIMSI(req.IMSI),
		ie.NewServingNetwork(req.MCC, req.MNC),
		ie.NewRATType(ratType),
		// Sender F-TEID for the control plane: the ePDG S2b C-plane endpoint.
		ie.NewFullyQualifiedTEID(gtpv2.IFTypeS2bePDGGTPC, req.LocalTEID, req.LocalIP, ""),
		ie.NewAccessPointName(req.APN),
		ie.NewSelectionMode(gtpv2.SelectionModeMSOrNetworkProvidedAPNSubscribedVerified),
		paa,
		ie.NewAggregateMaximumBitRate(ambrUp, ambrDown),
		bearerContext,
		// Recovery is not mandatory but every reference implementation sends it
		// and the peer echoes its own value back.
		ie.NewRecovery(0),
	}
	if req.MSISDN != "" {
		ies = append(ies, ie.NewMSISDN(req.MSISDN))
	}
	return append(ies, ueTimeZone()), nil
}

// newPDNAddressAllocationRequest builds a PDN Address Allocation IE that carries
// only the requested PDN type, which asks the PGW to allocate an address
// (TS 29.274 section 8.14).
func newPDNAddressAllocationRequest(pdnType uint8) (*ie.IE, error) {
	switch pdnType {
	case PDNTypeIPv4, PDNTypeIPv6, PDNTypeIPv4v6:
	default:
		return nil, fmt.Errorf("gtpv2: unsupported PDN type %d", pdnType)
	}
	fields := ie.NewPDNAddressAllocationFields(pdnType, nil, nil, 0)
	payload, err := fields.Marshal()
	if err != nil {
		return nil, fmt.Errorf("gtpv2: cannot encode the PDN Address Allocation: %w", err)
	}
	return ie.New(ie.PDNAddressAllocation, 0x00, payload), nil
}

// CreateSession establishes an S2b session (3GPP TS 29.274 section 7.2.1).
func (c *Client) CreateSession(ctx context.Context, req Request) (*Result, error) {
	if req.IMSI == "" || req.APN == "" {
		return nil, errors.New("gtpv2: imsi and apn are required")
	}
	if req.MCC == "" || req.MNC == "" {
		return nil, errors.New("gtpv2: mcc and mnc are required")
	}
	if req.LocalTEID == 0 {
		return nil, errors.New("gtpv2: a local C-plane TEID is required")
	}
	if req.LocalUTEID == 0 {
		return nil, errors.New("gtpv2: a local U-plane TEID is required for the S2b bearer")
	}
	if req.LocalIP == "" {
		return nil, errors.New("gtpv2: a local IP address is required for the S2b F-TEID")
	}

	ies, err := buildCreateSessionIEs(req)
	if err != nil {
		return nil, err
	}
	request := message.NewCreateSessionRequest(0, c.nextSequence(), ies...)
	response, err := c.roundTrip(ctx, request, message.MsgTypeCreateSessionResponse)
	if err != nil {
		return nil, err
	}
	csr, ok := response.(*message.CreateSessionResponse)
	if !ok {
		return nil, fmt.Errorf("gtpv2: unexpected create session response type %T", response)
	}
	return parseCreateSessionResponse(csr, c.log)
}

func parseCreateSessionResponse(csr *message.CreateSessionResponse, log *slog.Logger) (*Result, error) {
	if csr.Cause == nil {
		return nil, errors.New("gtpv2: Create Session Response lacks the mandatory Cause IE")
	}
	cause, err := csr.Cause.Cause()
	if err != nil {
		return nil, fmt.Errorf("gtpv2: cannot decode Cause IE: %w", err)
	}
	result := &Result{Cause: cause}

	if csr.PGWS5S8FTEIDC != nil {
		fields, err := ie.ParseFullyQualifiedTEIDFields(csr.PGWS5S8FTEIDC.Payload)
		if err != nil {
			return nil, fmt.Errorf("gtpv2: cannot decode the PGW C-plane F-TEID: %w", err)
		}
		result.PGWCTEID = fields.TEIDGREKey
		result.PGWCTEIDType = fields.InterfaceType
		if fields.IPv4Address != nil {
			result.PGWAddress = fields.IPv4Address.String()
		}
	}
	if csr.PAA != nil {
		fields, err := ie.ParsePDNAddressAllocationFields(csr.PAA.Payload)
		if err != nil {
			return nil, fmt.Errorf("gtpv2: cannot decode the PDN Address Allocation: %w", err)
		}
		result.PDNType = fields.PDNType
		// An all-zero address means no address was allocated, which is not the
		// same as the literal address 0.0.0.0.
		switch {
		case fields.IPv4Address != nil && !fields.IPv4Address.IsUnspecified():
			result.PDNAddress = fields.IPv4Address.String()
		case fields.IPv6Address != nil && !fields.IPv6Address.IsUnspecified():
			result.PDNAddress = fmt.Sprintf("%s/%d", fields.IPv6Address.String(), fields.IPv6PrefixLength)
		}
	}
	if csr.Recovery != nil {
		if v, err := csr.Recovery.Recovery(); err == nil {
			result.Recovery = v
			result.HasRecovery = true
		}
	}
	for _, bc := range csr.BearerContextsCreated {
		bearer, err := parseBearerContext(bc)
		if err != nil {
			return nil, err
		}
		result.Bearers = append(result.Bearers, *bearer)
	}
	if log != nil {
		log.Info("gtpv2: create session response",
			"cause", cause,
			"pgw_c_teid", result.PGWCTEID, "pgw_address", result.PGWAddress,
			"pdn_address", result.PDNAddress, "bearers", len(result.Bearers))
	}
	return result, nil
}

// parseBearerContext walks the grouped information elements of a bearer context
// and extracts the EBI and the peer's U-plane F-TEID.
func parseBearerContext(bc *ie.IE) (*BearerResult, error) {
	if bc == nil {
		return nil, errors.New("gtpv2: nil bearer context")
	}
	out := &BearerResult{}
	for _, child := range bc.ChildIEs {
		switch child.Type {
		case ie.EPSBearerID:
			if ebi, err := child.EPSBearerID(); err == nil {
				out.EBI = ebi
			}
		case ie.FullyQualifiedTEID:
			fields, err := ie.ParseFullyQualifiedTEIDFields(child.Payload)
			if err != nil {
				continue
			}
			// The U-plane F-TEID is the only one in a bearer context; record it
			// together with its interface type so the caller can verify whether
			// the peer answered on S2b or on S5/S8.
			if out.PGWUTEID == 0 {
				out.PGWUTEID = fields.TEIDGREKey
				out.PGWUTeidInterfaceType = fields.InterfaceType
				if fields.IPv4Address != nil {
					out.PGWUAddress = fields.IPv4Address.String()
				}
			}
		}
	}
	return out, nil
}

// DeleteSession tears down an S2b session (3GPP TS 29.274 section 7.2.9). The
// request is addressed to the peer C-plane TEID obtained from the Create
// Session Response, because that is how the peer identifies the session.
func (c *Client) DeleteSession(ctx context.Context, req Request) error {
	if req.EBI == 0 {
		return errors.New("gtpv2: an EBI is required to delete a session")
	}
	if req.PeerTEID == 0 {
		return errors.New("gtpv2: the peer C-plane TEID is required to delete a session")
	}
	ies := []*ie.IE{
		ie.NewEPSBearerID(req.EBI),
	}
	if req.MCC != "" && req.MNC != "" {
		ies = append(ies, ueTimeZone(), ie.NewServingNetwork(req.MCC, req.MNC))
	}
	request := message.NewDeleteSessionRequest(req.PeerTEID, c.nextSequence(), ies...)
	response, err := c.roundTrip(ctx, request, message.MsgTypeDeleteSessionResponse)
	if err != nil {
		return err
	}
	dsr, ok := response.(*message.DeleteSessionResponse)
	if !ok {
		return fmt.Errorf("gtpv2: unexpected delete session response type %T", response)
	}
	if dsr.Cause == nil {
		return errors.New("gtpv2: Delete Session Response lacks the mandatory Cause IE")
	}
	cause, err := dsr.Cause.Cause()
	if err != nil {
		return fmt.Errorf("gtpv2: cannot decode Cause IE: %w", err)
	}
	if cause != gtpv2.CauseRequestAccepted {
		return fmt.Errorf("gtpv2: delete session rejected with cause %d", cause)
	}
	return nil
}
