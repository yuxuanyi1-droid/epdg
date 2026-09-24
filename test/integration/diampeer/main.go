// Command diampeer is a minimal Diameter peer used only by the S2b integration
// test. It stands in for the two Diameter nodes that are not part of this
// repository's deliverable but that a PGW-C insists on before it will allocate
// an S2b session:
//
//   - the PCRF, over Gx (CCR/CCA)
//   - the 3GPP AAA server, over S6b (AAR/AAA)
//
// It is a test double, not a product component: it always grants what it is
// asked for. Its purpose is to let a real Open5GS PGW-C reach the point where it
// answers the ePDG's S2b Create Session Request, so that the ePDG's own
// messages can be validated against a real implementation.
//
// Usage:
//
//	diampeer -listen 127.0.0.10:3868 -origin-host aaa.localdomain -origin-realm localdomain
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync/atomic"
)

// Diameter command codes (RFC 6733 and 3GPP TS 29.212/29.273/29.274).
const (
	cmdCapabilitiesExchange uint32 = 257
	cmdReAuth               uint32 = 258
	cmdAA                   uint32 = 265
	cmdCreditControl        uint32 = 272
	cmdAbortSession         uint32 = 274
	cmdSessionTermination   uint32 = 275
	cmdDeviceWatchdog       uint32 = 280
	cmdDisconnectPeer       uint32 = 282
)

// Application identifiers.
const (
	appGx  uint32 = 16777238
	appGy  uint32 = 16777228
	appS6b uint32 = 16777272
)

// AVP codes.
const (
	avpHostIPAddress               uint32 = 257
	avpAuthApplicationID           uint32 = 258
	avpAcctApplicationID           uint32 = 259
	avpVendorSpecificApplicationID uint32 = 260
	avpSessionID                   uint32 = 263
	avpOriginHost                  uint32 = 264
	avpResultCode                  uint32 = 268
	avpProductName                 uint32 = 269
	avpDisconnectCause             uint32 = 273
	avpOriginStateID               uint32 = 278
	avpDestinationHost             uint32 = 293
	avpOriginRealm                 uint32 = 296
	avpVendorID                    uint32 = 266
	avpErrorMessage                uint32 = 281
	avpDefaultEPSBearerQoS         uint32 = 1049
	avpQoSInformation              uint32 = 1032
	avpAPNAggregateMaxBitRateUL    uint32 = 1043
	avpAPNAggregateMaxBitRateDL    uint32 = 1044
	avpAllocationRetentionPriority uint32 = 1034
	avpQoSClassIdentifier          uint32 = 1028
	avpPriorityLevel               uint32 = 1046
	avpPreemptionCapability        uint32 = 1047
	avpPreemptionVulnerability     uint32 = 1048
	// Auth-Request-Type is AVP 274, not 1; AVP 1 is User-Name.
	avpAuthRequestType uint32 = 274
	avpCCRequestNumber uint32 = 415
	avpCCRequestType   uint32 = 416
)

// Result codes.
const resultCodeSuccess uint32 = 2001

// VENDOR_3GPP is the 3GPP vendor id.
const vendor3GPP uint32 = 10415

// Message flags.
const (
	flagRequest    uint8 = 0x80
	flagProxiable  uint8 = 0x40
	flagError      uint8 = 0x20
	flagRetransmit uint8 = 0x10
)

type avp struct {
	code   uint32
	flags  uint8
	vendor uint32
	data   []byte
}

func newAVP(code uint32, data []byte) avp {
	return avp{code: code, flags: 0x40, data: data}
}

func newVendorAVP(code uint32, vendor uint32, data []byte) avp {
	return avp{code: code, flags: 0x40 | 0x80, vendor: vendor, data: data}
}

func (a avp) marshal() []byte {
	length := 8 + len(a.data)
	if a.flags&0x80 != 0 {
		length += 4
	}
	buf := make([]byte, 0, length+3)
	var hdr [8]byte
	binary.BigEndian.PutUint32(hdr[0:4], a.code)
	hdr[4] = a.flags
	// RFC 6733 section 4.1: the AVP Length field does not include the padding
	// octets that follow a non 4-octet-aligned value.
	hdr[5] = byte(length >> 16)
	hdr[6] = byte(length >> 8)
	hdr[7] = byte(length)
	buf = append(buf, hdr[:]...)
	if a.flags&0x80 != 0 {
		var v [4]byte
		binary.BigEndian.PutUint32(v[:], a.vendor)
		buf = append(buf, v[:]...)
	}
	buf = append(buf, a.data...)
	for len(buf)%4 != 0 {
		buf = append(buf, 0)
	}
	return buf
}

func marshalAVPs(avps []avp) []byte {
	var out []byte
	for _, a := range avps {
		out = append(out, a.marshal()...)
	}
	return out
}

// parseAVPs decodes a sequence of AVPs, recursing into the grouped ones listed
// in groupedAVPs so that nested attributes can be inspected.
func parseAVPs(raw []byte) ([]avp, error) {
	var out []avp
	for pos := 0; pos+8 <= len(raw); {
		code := binary.BigEndian.Uint32(raw[pos : pos+4])
		flags := raw[pos+4]
		length := int(raw[pos+5])<<16 | int(raw[pos+6])<<8 | int(raw[pos+7])
		if length < 8 || pos+length > len(raw) {
			return nil, fmt.Errorf("malformed AVP %d: length %d at offset %d", code, length, pos)
		}
		header := 8
		var vendor uint32
		if flags&0x80 != 0 {
			if length < 12 {
				return nil, fmt.Errorf("malformed vendor AVP %d: length %d", code, length)
			}
			vendor = binary.BigEndian.Uint32(raw[pos+8 : pos+12])
			header = 12
		}
		out = append(out, avp{code: code, flags: flags, vendor: vendor, data: raw[pos+header : pos+length]})
		// The Length excludes padding, so advance to the next 4-octet boundary.
		pos += (length + 3) &^ 3
	}
	return out, nil
}

func findAVP(avps []avp, code uint32) (avp, bool) {
	for _, a := range avps {
		if a.code == code {
			return a, true
		}
	}
	return avp{}, false
}

func (a avp) asString() string { return string(a.data) }

func (a avp) asUint32() uint32 { return binary.BigEndian.Uint32(a.data) }

// message is a decoded Diameter message.
type message struct {
	flags         uint8
	command       uint32
	applicationID uint32
	hopByHop      uint32
	endToEnd      uint32
	avps          []avp
}

func parseMessage(raw []byte) (*message, error) {
	if len(raw) < 20 {
		return nil, fmt.Errorf("short Diameter message: %d octets", len(raw))
	}
	if raw[0] != 1 {
		return nil, fmt.Errorf("unsupported Diameter version %d", raw[0])
	}
	length := int(raw[1])<<16 | int(raw[2])<<8 | int(raw[3])
	if length < 20 || length > len(raw) {
		return nil, fmt.Errorf("invalid Diameter message length %d (have %d)", length, len(raw))
	}
	avps, err := parseAVPs(raw[20:length])
	if err != nil {
		return nil, err
	}
	return &message{
		flags:         raw[4],
		command:       uint32(raw[5])<<16 | uint32(raw[6])<<8 | uint32(raw[7]),
		applicationID: binary.BigEndian.Uint32(raw[8:12]),
		hopByHop:      binary.BigEndian.Uint32(raw[12:16]),
		endToEnd:      binary.BigEndian.Uint32(raw[16:20]),
		avps:          avps,
	}, nil
}

func (m *message) marshal() []byte {
	body := marshalAVPs(m.avps)
	total := 20 + len(body)
	out := make([]byte, total)
	out[0] = 1
	out[1] = byte(total >> 16)
	out[2] = byte(total >> 8)
	out[3] = byte(total)
	out[4] = m.flags
	// The command code is three octets (RFC 6733 section 3), followed by the
	// four octet Application-Id.
	out[5] = byte(m.command >> 16)
	out[6] = byte(m.command >> 8)
	out[7] = byte(m.command)
	binary.BigEndian.PutUint32(out[8:12], m.applicationID)
	binary.BigEndian.PutUint32(out[12:16], m.hopByHop)
	binary.BigEndian.PutUint32(out[16:20], m.endToEnd)
	copy(out[20:], body)
	return out
}

func (m *message) String() string {
	name := map[uint32]string{
		cmdCapabilitiesExchange: "CER/CEA",
		cmdReAuth:               "RAR/RAA",
		cmdAA:                   "AAR/AAA",
		cmdCreditControl:        "CCR/CCA",
		cmdAbortSession:         "ASR/ASA",
		cmdSessionTermination:   "STR/STA",
		cmdDeviceWatchdog:       "DWR/DWA",
		cmdDisconnectPeer:       "DPR/DPA",
	}[m.command]
	if name == "" {
		name = fmt.Sprintf("cmd-%d", m.command)
	}
	kind := "answer"
	if m.flags&flagRequest != 0 {
		kind = "request"
	}
	return fmt.Sprintf("%s %s app=%d", name, kind, m.applicationID)
}

// describe renders the AVPs of interest for the test log.
func (m *message) describe() string {
	out := ""
	if sid, ok := findAVP(m.avps, avpSessionID); ok {
		out += " session-id=" + sid.asString()
	}
	if oh, ok := findAVP(m.avps, avpOriginHost); ok {
		out += " origin-host=" + oh.asString()
	}
	if rc, ok := findAVP(m.avps, avpResultCode); ok && len(rc.data) == 4 {
		out += fmt.Sprintf(" result-code=%d", rc.asUint32())
	}
	return out
}

// dumpAVPs lists every AVP in the message, recursing into grouped ones, so the
// test log shows exactly what a real peer sent.
func (m *message) dumpAVPs() string {
	var sb strings.Builder
	dumpAVPList(&sb, m.avps, "  ")
	return sb.String()
}

func dumpAVPList(sb *strings.Builder, avps []avp, indent string) {
	for _, a := range avps {
		fmt.Fprintf(sb, "\n%savp %d", indent, a.code)
		if a.flags&0x80 != 0 {
			fmt.Fprintf(sb, " vendor=%d", a.vendor)
		}
		fmt.Fprintf(sb, " len=%d flags=%#02x", len(a.data), a.flags)
		if isGroupedAVP(a.code) {
			inner, err := parseAVPs(a.data)
			if err == nil {
				dumpAVPList(sb, inner, indent+"  ")
				continue
			}
		}
		if len(a.data) == 4 {
			fmt.Fprintf(sb, " u32=%d", a.asUint32())
		} else if printable(a.data) {
			fmt.Fprintf(sb, " str=%q", string(a.data))
		} else {
			fmt.Fprintf(sb, " hex=%x", a.data)
		}
	}
}

func isGroupedAVP(code uint32) bool {
	switch code {
	case avpVendorSpecificApplicationID, 480 /* Failed-AVP */ :
		return true
	}
	return false
}

func printable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

type server struct {
	originHost   string
	originRealm  string
	hostIP       string
	productName  string
	stateID      uint32
	requestCount atomic.Uint64
}

func (s *server) serve(conn net.Conn) {
	defer conn.Close()
	peer := conn.RemoteAddr().String()
	log.Printf("diampeer: connection from %s", peer)

	for {
		raw, err := readMessage(conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("diampeer: read from %s failed: %v", peer, err)
			}
			return
		}
		msg, err := parseMessage(raw)
		if err != nil {
			log.Printf("diampeer: dropping malformed message from %s: %v", peer, err)
			return
		}
		log.Printf("diampeer: <- %s%s%s", msg.String(), msg.describe(), msg.dumpAVPs())

		if msg.flags&flagRequest == 0 {
			// An answer to something we sent; we are purely reactive.
			continue
		}
		answer := s.answer(msg)
		if answer == nil {
			log.Printf("diampeer: no answer defined for %s", msg.String())
			continue
		}
		out := answer.marshal()
		if _, err := conn.Write(out); err != nil {
			log.Printf("diampeer: write to %s failed: %v", peer, err)
			return
		}
		log.Printf("diampeer: -> %s%s", answer.String(), answer.describe())

		if msg.command == cmdDisconnectPeer {
			return
		}
	}
}

// readMessage reads exactly one Diameter message, using the length in the
// header to find its end.
func readMessage(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	length := int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	if length < 20 || length > 65535 {
		return nil, fmt.Errorf("invalid message length %d", length)
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return append(header, body...), nil
}

func (s *server) answer(req *message) *message {
	// Session-Id must be the very first AVP: the Diameter dictionary rules mark
	// it RULE_FIXED_HEAD, and an answer that puts anything before it is rejected
	// as "failed the dictionary / rules parsing".
	base := []avp{}
	if sid, ok := findAVP(req.avps, avpSessionID); ok {
		base = append(base, newAVP(avpSessionID, sid.data))
	}
	base = append(base,
		newAVP(avpOriginHost, []byte(s.originHost)),
		newAVP(avpOriginRealm, []byte(s.originRealm)),
		// Auth-Application-Id is required in both directions for the 3GPP
		// applications and must match the application the request used.
		newAVP(avpAuthApplicationID, uint32AVP(req.applicationID)),
	)

	// Answers are returned without the Request bit and without the retransmit
	// hint, but stay proxiable (RFC 6733 section 3).
	flags := req.flags & flagProxiable

	switch req.command {
	case cmdCapabilitiesExchange:
		return &message{
			flags:         0,
			command:       cmdCapabilitiesExchange,
			applicationID: 0,
			hopByHop:      req.hopByHop,
			endToEnd:      req.endToEnd,
			avps: []avp{
				newAVP(avpOriginHost, []byte(s.originHost)),
				newAVP(avpOriginRealm, []byte(s.originRealm)),
				newAVP(avpResultCode, uint32AVP(resultCodeSuccess)),
				newAVP(avpHostIPAddress, s.hostIPAVP()),
				// Vendor-Id is a base AVP: the vendor id is the value, the V bit
				// stays clear (RFC 6733 section 5.3.3).
				newAVP(avpVendorID, uint32AVP(vendor3GPP)),
				newAVP(avpProductName, []byte(s.productName)),
				// Gx and S6b are 3GPP applications, so they are advertised as
				// vendor specific applications. Gy is deliberately not
				// advertised, which keeps the SMF's charging interface disabled
				// in its "auto" mode.
				newAVP(avpVendorSpecificApplicationID, marshalAVPs([]avp{
					newAVP(avpVendorID, uint32AVP(vendor3GPP)),
					newAVP(avpAuthApplicationID, uint32AVP(appGx)),
				})),
				newAVP(avpVendorSpecificApplicationID, marshalAVPs([]avp{
					newAVP(avpVendorID, uint32AVP(vendor3GPP)),
					newAVP(avpAuthApplicationID, uint32AVP(appS6b)),
				})),
				newAVP(avpOriginStateID, uint32AVP(s.stateID)),
			},
		}
	case cmdDeviceWatchdog:
		return &message{
			flags:         0,
			command:       cmdDeviceWatchdog,
			applicationID: req.applicationID,
			hopByHop:      req.hopByHop,
			endToEnd:      req.endToEnd,
			avps: append(base,
				newAVP(avpResultCode, uint32AVP(resultCodeSuccess)),
				newAVP(avpOriginStateID, uint32AVP(s.stateID)),
			),
		}
	case cmdDisconnectPeer:
		return &message{
			flags:         0,
			command:       cmdDisconnectPeer,
			applicationID: 0,
			hopByHop:      req.hopByHop,
			endToEnd:      req.endToEnd,
			avps: []avp{
				newAVP(avpOriginHost, []byte(s.originHost)),
				newAVP(avpOriginRealm, []byte(s.originRealm)),
				newAVP(avpResultCode, uint32AVP(resultCodeSuccess)),
			},
		}
	case cmdCreditControl: // Gx
		s.requestCount.Add(1)
		// CC-Request-Type and CC-Request-Number must be echoed (RFC 4006
		// section 3.1, profiled by 3GPP TS 29.212 for Gx).
		extra := []avp{}
		if v, ok := findAVP(req.avps, avpCCRequestType); ok {
			extra = append(extra, newAVP(avpCCRequestType, v.data))
		}
		if v, ok := findAVP(req.avps, avpCCRequestNumber); ok {
			extra = append(extra, newAVP(avpCCRequestNumber, v.data))
		}
		extra = append(extra,
			// Default-EPS-Bearer-QoS is a grouped AVP whose members are all
			// 4-octet types, and Allocation-Retention-Priority is itself grouped
			// (3GPP TS 29.212 section 5.3.x).
			newVendorAVP(avpDefaultEPSBearerQoS, vendor3GPP, marshalAVPs([]avp{
				newVendorAVP(avpQoSClassIdentifier, vendor3GPP, uint32AVP(9)),
				newVendorAVP(avpAllocationRetentionPriority, vendor3GPP, marshalAVPs([]avp{
					newVendorAVP(avpPriorityLevel, vendor3GPP, uint32AVP(1)),
					newVendorAVP(avpPreemptionCapability, vendor3GPP, uint32AVP(0)),
					newVendorAVP(avpPreemptionVulnerability, vendor3GPP, uint32AVP(1)),
				})),
			})),
			newVendorAVP(avpAPNAggregateMaxBitRateUL, vendor3GPP, uint32AVP(100000)),
			newVendorAVP(avpAPNAggregateMaxBitRateDL, vendor3GPP, uint32AVP(100000)),
		)
		return &message{
			flags:         flags,
			command:       cmdCreditControl,
			applicationID: req.applicationID,
			hopByHop:      req.hopByHop,
			endToEnd:      req.endToEnd,
			avps: append(base,
				append([]avp{newAVP(avpResultCode, uint32AVP(resultCodeSuccess))}, extra...)...,
			),
		}
	case cmdAA: // S6b AAR
		s.requestCount.Add(1)
		// The S6b AA-Answer must echo Auth-Request-Type and carry
		// Auth-Application-Id (3GPP TS 29.273 section 12.2.5.1).
		extra := []avp{}
		if v, ok := findAVP(req.avps, avpAuthRequestType); ok {
			extra = append(extra, newAVP(avpAuthRequestType, v.data))
		}
		return &message{
			flags:         flags,
			command:       cmdAA,
			applicationID: req.applicationID,
			hopByHop:      req.hopByHop,
			endToEnd:      req.endToEnd,
			avps: append(base,
				append([]avp{newAVP(avpResultCode, uint32AVP(resultCodeSuccess))}, extra...)...,
			),
		}
	case cmdSessionTermination, cmdAbortSession, cmdReAuth:
		return &message{
			flags:         flags,
			command:       req.command,
			applicationID: req.applicationID,
			hopByHop:      req.hopByHop,
			endToEnd:      req.endToEnd,
			avps: append(base,
				newAVP(avpResultCode, uint32AVP(resultCodeSuccess)),
			),
		}
	default:
		return nil
	}
}

func uint32AVP(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

// hostIPAVP renders the Host-IP-Address value: an Address type is a two octet
// AddressFamily followed by the address itself (RFC 6733 section 4.3.1).
func (s *server) hostIPAVP() []byte {
	ip := net.ParseIP(s.hostIP).To4()
	if ip == nil {
		ip = net.IPv4(127, 0, 0, 1).To4()
	}
	return append([]byte{0x00, 0x01}, ip...)
}

func main() {
	listen := flag.String("listen", "127.0.0.10:3868", "address to listen on")
	originHost := flag.String("origin-host", "aaa.localdomain", "Diameter identity to advertise")
	originRealm := flag.String("origin-realm", "localdomain", "Diameter realm to advertise")
	hostIP := flag.String("host-ip", "127.0.0.10", "address advertised in Host-IP-Address")
	flag.Parse()

	srv := &server{
		originHost:  *originHost,
		originRealm: *originRealm,
		hostIP:      *hostIP,
		productName: "epdg-diampeer",
		stateID:     1,
	}

	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("diampeer: cannot listen on %s: %v", *listen, err)
	}
	log.Printf("diampeer: listening on %s as %s (realm %s)", listener.Addr(), srv.originHost, srv.originRealm)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatalf("diampeer: accept failed: %v", err)
		}
		go srv.serve(conn)
	}
}
