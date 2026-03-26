package diameter

import (
	"encoding/binary"
	"fmt"
	"sync/atomic"
)

var idCounter uint32 = 1000

func nextID() uint32 {
	return atomic.AddUint32(&idCounter, 1)
}

type AVP struct {
	Code      uint32
	Mandatory bool
	VendorID  uint32
	Data      []byte
}

func NewUTF8AVP(code uint32, mandatory bool, value string) AVP {
	return AVP{Code: code, Mandatory: mandatory, Data: []byte(value)}
}

func NewOctetsAVP(code uint32, mandatory bool, value []byte) AVP {
	return AVP{Code: code, Mandatory: mandatory, Data: value}
}

func NewUnsigned32AVP(code uint32, mandatory bool, value uint32) AVP {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, value)
	return AVP{Code: code, Mandatory: mandatory, Data: data}
}

func NewAddressAVP(code uint32, ip []byte) AVP {
	addr := make([]byte, 2+len(ip))
	addr[0] = 0
	addr[1] = 1
	copy(addr[2:], ip)
	return AVP{Code: code, Mandatory: false, Data: addr}
}

func (a AVP) Marshal() ([]byte, error) {
	baseLen := 8 + len(a.Data)
	flags := byte(0)
	if a.Mandatory {
		flags |= flagAVP
	}

	if a.VendorID != 0 {
		flags |= 0x80
		baseLen += 4
	}

	padLen := (4 - (baseLen % 4)) % 4
	out := make([]byte, baseLen+padLen)
	binary.BigEndian.PutUint32(out[0:4], a.Code)
	out[4] = flags
	putUint24(out[5:8], uint32(baseLen))

	offset := 8
	if a.VendorID != 0 {
		binary.BigEndian.PutUint32(out[offset:offset+4], a.VendorID)
		offset += 4
	}
	copy(out[offset:offset+len(a.Data)], a.Data)
	return out, nil
}

func parseAVPs(body []byte) ([]AVP, error) {
	avps := make([]AVP, 0, 8)
	offset := 0
	for offset < len(body) {
		if len(body[offset:]) < 8 {
			return nil, fmt.Errorf("invalid avp header at offset %d", offset)
		}
		code := binary.BigEndian.Uint32(body[offset : offset+4])
		flags := body[offset+4]
		length := int(readUint24(body[offset+5 : offset+8]))
		if length < 8 || offset+length > len(body) {
			return nil, fmt.Errorf("invalid avp length at offset %d", offset)
		}
		cursor := offset + 8
		vendorID := uint32(0)
		if (flags & 0x80) != 0 {
			if length < 12 {
				return nil, fmt.Errorf("invalid vendor avp length at offset %d", offset)
			}
			vendorID = binary.BigEndian.Uint32(body[cursor : cursor+4])
			cursor += 4
		}
		data := make([]byte, offset+length-cursor)
		copy(data, body[cursor:offset+length])
		avps = append(avps, AVP{
			Code:      code,
			Mandatory: (flags & flagAVP) != 0,
			VendorID:  vendorID,
			Data:      data,
		})
		offset += length
		if rem := offset % 4; rem != 0 {
			offset += 4 - rem
		}
	}
	return avps, nil
}
