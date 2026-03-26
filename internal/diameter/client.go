package diameter

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	commandCapabilitiesExchange = 257
	commandWatchdog             = 280
	commandDiameterEAP          = 268

	applicationBase  = 0
	applicationEAP   = 5
	applicationRelay = 0xFFFFFFFF

	avpSessionID         = 263
	avpOriginHost        = 264
	avpOriginRealm       = 296
	avpDestinationRealm  = 283
	avpDestinationHost   = 293
	avpResultCode        = 268
	avpAuthApplicationID = 258
	avpVendorID          = 266
	avpProductName       = 269
	avpHostIPAddress     = 257
	avpUserName          = 1
	avpEAPPayload        = 462

	resultSuccess        = 2001
	resultMultiRoundAuth = 1001
)

func CommandCapabilitiesExchange() uint32 { return commandCapabilitiesExchange }
func CommandWatchdog() uint32             { return commandWatchdog }
func CommandDiameterEAP() uint32          { return commandDiameterEAP }
func ApplicationBase() uint32             { return applicationBase }
func ApplicationEAP() uint32              { return applicationEAP }
func AVPSessionID() uint32                { return avpSessionID }
func AVPOriginHost() uint32               { return avpOriginHost }
func AVPOriginRealm() uint32              { return avpOriginRealm }
func AVPDestinationRealm() uint32         { return avpDestinationRealm }
func AVPDestinationHost() uint32          { return avpDestinationHost }
func AVPResultCode() uint32               { return avpResultCode }
func AVPAuthApplicationID() uint32        { return avpAuthApplicationID }
func AVPVendorID() uint32                 { return avpVendorID }
func AVPProductName() uint32              { return avpProductName }
func AVPHostIPAddress() uint32            { return avpHostIPAddress }
func AVPUserName() uint32                 { return avpUserName }
func AVPEAPPayload() uint32               { return avpEAPPayload }
func ResultSuccess() uint32               { return resultSuccess }
func ResultMultiRoundAuth() uint32        { return resultMultiRoundAuth }

func BuildEAPIdentity(imsi string) []byte {
	return buildEAPIdentity(imsi)
}

type Config struct {
	PeerHost         string
	PeerPort         int
	OriginHost       string
	OriginRealm      string
	DestinationRealm string
	DestinationHost  string
	Timeout          time.Duration
}

type Client struct {
	cfg       Config
	mu        sync.Mutex
	conn      net.Conn
	connected bool
}

type EAPResponder interface {
	Respond(challenge []byte) ([]byte, error)
}

func New(cfg Config) *Client {
	return &Client{cfg: cfg}
}

func (c *Client) Ping() error {
	if _, err := c.connect(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.setDeadlineLocked(); err != nil {
		c.resetLocked()
		return err
	}
	if !c.connected {
		if err := c.handshakeLocked(); err != nil {
			c.resetLocked()
			return err
		}
	}
	return nil
}

func (c *Client) SendDER(imsi string) error {
	return c.ExchangeEAP(imsi, nil, 1)
}

func (c *Client) ExchangeEAP(imsi string, responder EAPResponder, maxRounds int) error {
	if imsi == "" {
		return fmt.Errorf("imsi required")
	}
	if maxRounds <= 0 {
		maxRounds = 4
	}

	conn, err := c.connect()
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.setDeadlineLocked(); err != nil {
		c.resetLocked()
		return err
	}
	if !c.connected {
		if err := c.handshakeLocked(); err != nil {
			c.resetLocked()
			return err
		}
	}
	sessionID := fmt.Sprintf("%s;%d", c.cfg.OriginHost, time.Now().UnixNano())
	eapPayload := buildEAPIdentity(imsi)

	for round := 0; round < maxRounds; round++ {
		if err := c.sendDERMessage(conn, sessionID, imsi, eapPayload); err != nil {
			return err
		}
		dea, err := c.readDEA(conn)
		if err != nil {
			c.resetLocked()
			return err
		}
		if dea.CommandCode != commandDiameterEAP || dea.IsRequest {
			return fmt.Errorf("unexpected DEA message: code=%d req=%v", dea.CommandCode, dea.IsRequest)
		}
		rc, ok := dea.ResultCode()
		if !ok {
			return fmt.Errorf("DEA missing Result-Code")
		}
		if rc == resultSuccess {
			return nil
		}
		if rc != resultMultiRoundAuth {
			return fmt.Errorf("DEA rejected Result-Code=%d", rc)
		}
		challenge, ok := dea.AVPBytes(avpEAPPayload)
		if !ok || len(challenge) == 0 {
			return fmt.Errorf("DEA multi-round without EAP-Payload")
		}
		if responder == nil {
			return fmt.Errorf("EAP challenge received but no responder configured")
		}
		eapPayload, err = responder.Respond(challenge)
		if err != nil {
			return fmt.Errorf("build eap response failed: %w", err)
		}
		if len(eapPayload) == 0 {
			return fmt.Errorf("empty eap response payload")
		}
	}
	return fmt.Errorf("EAP auth not completed in %d rounds", maxRounds)
}

func (c *Client) readDEA(conn net.Conn) (Message, error) {
	for i := 0; i < 8; i++ {
		msg, err := readMessage(conn)
		if err != nil {
			return Message{}, err
		}
		if msg.IsRequest && msg.CommandCode == 280 {
			if err := c.sendDWA(conn, msg); err != nil {
				return Message{}, err
			}
			continue
		}
		return msg, nil
	}
	return Message{}, fmt.Errorf("too many interleaved messages before DEA")
}

func (c *Client) dial() (net.Conn, error) {
	if c.cfg.PeerHost == "" || c.cfg.PeerPort == 0 {
		return nil, fmt.Errorf("diameter peer is not configured")
	}
	timeout := c.cfg.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	address := net.JoinHostPort(c.cfg.PeerHost, fmt.Sprintf("%d", c.cfg.PeerPort))
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil, fmt.Errorf("connect diameter peer failed: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	return conn, nil
}

func (c *Client) connect() (net.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn, nil
	}
	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	c.conn = conn
	c.connected = false
	return c.conn, nil
}

func (c *Client) setDeadlineLocked() error {
	if c.conn == nil {
		return fmt.Errorf("diameter conn is nil")
	}
	timeout := c.cfg.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return c.conn.SetDeadline(time.Now().Add(timeout))
}

func (c *Client) handshakeLocked() error {
	if err := c.sendCER(c.conn); err != nil {
		return err
	}
	msg, err := readMessage(c.conn)
	if err != nil {
		return err
	}
	if msg.CommandCode != commandCapabilitiesExchange || msg.IsRequest {
		return fmt.Errorf("unexpected CEA message: code=%d req=%v", msg.CommandCode, msg.IsRequest)
	}
	rc, ok := msg.ResultCode()
	if !ok {
		return fmt.Errorf("CEA missing Result-Code")
	}
	if rc != resultSuccess {
		return fmt.Errorf("CEA rejected Result-Code=%d", rc)
	}
	c.connected = true
	return nil
}

func (c *Client) resetLocked() {
	if c.conn != nil {
		_ = c.conn.Close()
	}
	c.conn = nil
	c.connected = false
}

func (c *Client) sendCER(w io.Writer) error {
	hostIP := net.ParseIP("127.0.0.1").To4()
	if hostIP == nil {
		hostIP = []byte{127, 0, 0, 1}
	}
	avps := []AVP{
		NewUTF8AVP(avpOriginHost, false, c.cfg.OriginHost),
		NewUTF8AVP(avpOriginRealm, false, c.cfg.OriginRealm),
		NewAddressAVP(avpHostIPAddress, hostIP),
		NewUnsigned32AVP(avpVendorID, false, 10415),
		NewUTF8AVP(avpProductName, false, "epdgd"),
		NewUnsigned32AVP(avpAuthApplicationID, false, applicationRelay),
		NewUnsigned32AVP(avpAuthApplicationID, false, applicationEAP),
	}
	msg := NewMessage(commandCapabilitiesExchange, applicationBase, true, avps)
	data, err := msg.Marshal()
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func (c *Client) sendDERMessage(w io.Writer, sessionID, imsi string, eapPayload []byte) error {
	avps := []AVP{
		NewUTF8AVP(avpSessionID, false, sessionID),
		NewUnsigned32AVP(avpAuthApplicationID, false, applicationEAP),
		NewUTF8AVP(avpOriginHost, false, c.cfg.OriginHost),
		NewUTF8AVP(avpOriginRealm, false, c.cfg.OriginRealm),
		NewUTF8AVP(avpDestinationRealm, false, c.cfg.DestinationRealm),
		NewUTF8AVP(avpUserName, false, imsi),
		NewOctetsAVP(avpEAPPayload, false, eapPayload),
	}
	if c.cfg.DestinationHost != "" {
		avps = append(avps, NewUTF8AVP(avpDestinationHost, false, c.cfg.DestinationHost))
	}
	msg := NewMessage(commandDiameterEAP, applicationEAP, true, avps)
	data, err := msg.Marshal()
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func (c *Client) sendDWA(w io.Writer, req Message) error {
	avps := []AVP{
		NewUnsigned32AVP(avpResultCode, true, resultSuccess),
		NewUTF8AVP(avpOriginHost, true, c.cfg.OriginHost),
		NewUTF8AVP(avpOriginRealm, true, c.cfg.OriginRealm),
	}
	msg := Message{
		CommandCode: commandWatchdog,
		Application: applicationBase,
		HopByHop:    req.HopByHop,
		EndToEnd:    req.EndToEnd,
		IsRequest:   false,
		AVPs:        avps,
	}
	data, err := msg.Marshal()
	if err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func buildEAPIdentity(imsi string) []byte {
	eapIdentity := []byte{0x02, 0x01, 0x00, 0x09, 0x01}
	eapIdentity = append(eapIdentity, []byte(imsi)...)
	binary.BigEndian.PutUint16(eapIdentity[2:4], uint16(len(eapIdentity)))
	return eapIdentity
}
