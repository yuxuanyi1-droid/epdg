package diameter

import (
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

type Handler interface {
	Handle(Message) (Message, bool, error)
}

type ServerConfig struct {
	Listen      string
	OriginHost  string
	OriginRealm string
	ProductName string
	ReadTimeout time.Duration
}

type Server struct {
	cfg     ServerConfig
	handler Handler
	logger  *log.Logger
}

func NewServer(cfg ServerConfig, handler Handler, logger *log.Logger) *Server {
	if cfg.ProductName == "" {
		cfg.ProductName = "swm-aaad"
	}
	if logger == nil {
		logger = log.Default()
	}
	return &Server{cfg: cfg, handler: handler, logger: logger}
}

func (s *Server) ListenAndServe() error {
	if s.cfg.Listen == "" {
		return fmt.Errorf("listen address required")
	}
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	defer ln.Close()

	s.logger.Printf("diameter server listening on %s", s.cfg.Listen)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.serveConn(conn)
	}
}

func (s *Server) serveConn(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	for {
		if s.cfg.ReadTimeout > 0 {
			_ = conn.SetDeadline(time.Now().Add(s.cfg.ReadTimeout))
		} else {
			_ = conn.SetDeadline(time.Time{})
		}
		msg, err := readMessage(conn)
		if err != nil {
			if err == io.EOF {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				return
			}
			s.logger.Printf("diameter read from %s failed: %v", remote, err)
			return
		}
		resp, handled, err := s.handleMessage(msg)
		if err != nil {
			s.logger.Printf("diameter handle from %s failed: %v", remote, err)
			return
		}
		if !handled {
			s.logger.Printf("diameter ignoring unsupported command=%d app=%d from %s", msg.CommandCode, msg.Application, remote)
			continue
		}
		s.logger.Printf("diameter handled command=%d app=%d req=%v from %s", msg.CommandCode, msg.Application, msg.IsRequest, remote)
		data, err := resp.Marshal()
		if err != nil {
			s.logger.Printf("diameter marshal response failed: %v", err)
			return
		}
		if _, err := conn.Write(data); err != nil {
			s.logger.Printf("diameter write to %s failed: %v", remote, err)
			return
		}
	}
}

func (s *Server) handleMessage(msg Message) (Message, bool, error) {
	switch {
	case msg.IsRequest && msg.CommandCode == commandCapabilitiesExchange:
		return s.newCEA(msg), true, nil
	case msg.IsRequest && msg.CommandCode == commandWatchdog:
		return s.newDWA(msg), true, nil
	default:
		if s.handler == nil {
			return Message{}, false, nil
		}
		return s.handler.Handle(msg)
	}
}

func (s *Server) newCEA(req Message) Message {
	hostIP := net.ParseIP("127.0.0.19").To4()
	if hostIP == nil {
		hostIP = []byte{127, 0, 0, 19}
	}
	return Message{
		CommandCode: commandCapabilitiesExchange,
		Application: applicationBase,
		HopByHop:    req.HopByHop,
		EndToEnd:    req.EndToEnd,
		IsRequest:   false,
		AVPs: []AVP{
			NewUnsigned32AVP(avpResultCode, true, resultSuccess),
			NewUTF8AVP(avpOriginHost, true, s.cfg.OriginHost),
			NewUTF8AVP(avpOriginRealm, true, s.cfg.OriginRealm),
			NewAddressAVP(avpHostIPAddress, hostIP),
			NewUnsigned32AVP(avpVendorID, false, 10415),
			NewUTF8AVP(avpProductName, false, s.cfg.ProductName),
			NewUnsigned32AVP(avpAuthApplicationID, false, applicationEAP),
		},
	}
}

func (s *Server) newDWA(req Message) Message {
	return Message{
		CommandCode: commandWatchdog,
		Application: applicationBase,
		HopByHop:    req.HopByHop,
		EndToEnd:    req.EndToEnd,
		IsRequest:   false,
		AVPs: []AVP{
			NewUnsigned32AVP(avpResultCode, true, resultSuccess),
			NewUTF8AVP(avpOriginHost, true, s.cfg.OriginHost),
			NewUTF8AVP(avpOriginRealm, true, s.cfg.OriginRealm),
		},
	}
}
