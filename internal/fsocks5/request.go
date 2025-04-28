package fsocks5

import (
	"errors"
	"io"
	"log/slog"
)

type Request struct {
	cmd     byte
	atyp    byte
	address Address
}

func NewRequest(rw io.Reader, logger *slog.Logger) (*Request, error) {
	read, err := readN(rw, 4)
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
		read, err = readN(rw, 4+2)
		if err != nil {
			return nil, err
		}
		req.address = IPAddr{Ip: read[:4], Port: read[4:]}

	case 0x03: // Domain
		read, err = readN(rw, 1)
		if err != nil {
			return nil, err
		}
		addrLen := read[0]
		read, err = readN(rw, addrLen+2)
		if err != nil {
			return nil, err
		}
		req.address = NewDomainNameAddr(read)

	case 0x04: // IPv6
		read, err = readN(rw, 16+2)
		if err != nil {
			return nil, err
		}
		req.address = IPAddr{Ip: read[:16], Port: read[16:]}

	default:
		return nil, errors.New("unsupported address type")
	}

	logger.Info("created new request", "cmd", req.cmd, "atyp", req.atyp, "address", req.address.ToString())
	return req, nil
}
