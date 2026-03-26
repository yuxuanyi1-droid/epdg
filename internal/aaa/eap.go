package aaa

import "fmt"

type EAPResponder interface {
	Respond(challenge []byte) ([]byte, error)
}

type UnsupportedEAPResponder struct{}

func (UnsupportedEAPResponder) Respond(_ []byte) ([]byte, error) {
	return nil, fmt.Errorf("eap-aka' responder not configured")
}

type NAKOnlyEAPResponder struct{}

func (NAKOnlyEAPResponder) Respond(challenge []byte) ([]byte, error) {
	if len(challenge) < 2 {
		return nil, fmt.Errorf("invalid eap challenge")
	}
	id := challenge[1]
	desiredMethod := byte(50)
	return []byte{
		0x02,
		id,
		0x00, 0x06,
		0x03,
		desiredMethod,
	}, nil
}
