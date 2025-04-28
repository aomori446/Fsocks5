package fsocks5

import (
	"errors"
	"io"
)

type Request struct {
	cmd  byte
	atyp byte
	addr Address
}

func NewRequest(r io.Reader) (*Request, error) {
	read, err := readN(r, 4)
	if err != nil {
		return nil, err
	}
	if read[0] != 0x05 || read[2] != 0x00 {
		return nil, VersionErr
	}

	req := &Request{
		cmd:  read[1],
		atyp: read[3],
	}

	switch req.atyp {
	case 0x01: // IPv4
		req.addr, err = readAddress(r, 4+2)
		if err != nil {
			return nil, err
		}

	case 0x03: // Domain
		req.addr, err = readAddress(r, 0)
		if err != nil {
			return nil, err
		}

	case 0x04: // IPv6
		req.addr, err = readAddress(r, 16+2)
		if err != nil {
			return nil, err
		}

	default:
		return nil, errors.New("unsupported addr type")
	}

	return req, nil
}
