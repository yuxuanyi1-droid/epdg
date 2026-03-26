package diameter

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	flagRequest = 0x80
	flagAVP     = 0x40
)

type Message struct {
	CommandCode uint32
	Application uint32
	HopByHop    uint32
	EndToEnd    uint32
	IsRequest   bool
	AVPs        []AVP
}

func NewMessage(commandCode, app uint32, request bool, avps []AVP) Message {
	flags := false
	if request {
		flags = true
	}
	return Message{
		CommandCode: commandCode,
		Application: app,
		IsRequest:   flags,
		HopByHop:    uint32(nextID()),
		EndToEnd:    uint32(nextID()),
		AVPs:        avps,
	}
}

func (m Message) Marshal() ([]byte, error) {
	avpBytes := make([]byte, 0, 256)
	for _, avp := range m.AVPs {
		data, err := avp.Marshal()
		if err != nil {
			return nil, err
		}
		avpBytes = append(avpBytes, data...)
	}

	totalLen := 20 + len(avpBytes)
	out := make([]byte, totalLen)
	out[0] = 1
	putUint24(out[1:4], uint32(totalLen))
	if m.IsRequest {
		out[4] = flagRequest
	}
	putUint24(out[5:8], m.CommandCode)
	binary.BigEndian.PutUint32(out[8:12], m.Application)
	binary.BigEndian.PutUint32(out[12:16], m.HopByHop)
	binary.BigEndian.PutUint32(out[16:20], m.EndToEnd)
	copy(out[20:], avpBytes)
	return out, nil
}

func readMessage(r io.Reader) (Message, error) {
	header := make([]byte, 20)
	if _, err := io.ReadFull(r, header); err != nil {
		return Message{}, fmt.Errorf("read diameter header failed: %w", err)
	}
	if header[0] != 1 {
		return Message{}, fmt.Errorf("unsupported diameter version: %d", header[0])
	}
	msgLen := int(readUint24(header[1:4]))
	if msgLen < 20 {
		return Message{}, fmt.Errorf("invalid diameter length: %d", msgLen)
	}
	body := make([]byte, msgLen-20)
	if _, err := io.ReadFull(r, body); err != nil {
		return Message{}, fmt.Errorf("read diameter body failed: %w", err)
	}
	avps, err := parseAVPs(body)
	if err != nil {
		return Message{}, err
	}
	return Message{
		CommandCode: readUint24(header[5:8]),
		Application: binary.BigEndian.Uint32(header[8:12]),
		HopByHop:    binary.BigEndian.Uint32(header[12:16]),
		EndToEnd:    binary.BigEndian.Uint32(header[16:20]),
		IsRequest:   (header[4] & flagRequest) != 0,
		AVPs:        avps,
	}, nil
}

func (m Message) ResultCode() (uint32, bool) {
	for _, avp := range m.AVPs {
		if avp.Code == avpResultCode && len(avp.Data) >= 4 {
			return binary.BigEndian.Uint32(avp.Data[:4]), true
		}
	}
	return 0, false
}

func (m Message) AVPBytes(code uint32) ([]byte, bool) {
	for _, avp := range m.AVPs {
		if avp.Code == code {
			data := make([]byte, len(avp.Data))
			copy(data, avp.Data)
			return data, true
		}
	}
	return nil, false
}

func (m Message) AVPString(code uint32) (string, bool) {
	data, ok := m.AVPBytes(code)
	if !ok {
		return "", false
	}
	return string(data), true
}

func putUint24(dst []byte, value uint32) {
	dst[0] = byte((value >> 16) & 0xFF)
	dst[1] = byte((value >> 8) & 0xFF)
	dst[2] = byte(value & 0xFF)
}

func readUint24(src []byte) uint32 {
	return uint32(src[0])<<16 | uint32(src[1])<<8 | uint32(src[2])
}
