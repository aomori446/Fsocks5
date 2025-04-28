package fsocks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

func readN(r io.Reader, n byte) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("invalid read length: %d", n)
	}

	buf := make([]byte, n)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func parseHostPort(hostPort string) (IP []byte, Port []byte, ATYP byte, err error) {
	host, p, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, nil, 0, err
	}

	parsedIP := net.ParseIP(host)
	if parsedIP == nil {
		return nil, nil, 0, errors.New("invalid IP")
	}
	if ip4 := parsedIP.To4(); ip4 != nil {
		IP = ip4
		ATYP = 0x01
	} else {
		IP = parsedIP.To16()
		ATYP = 0x04
	}

	pp, err := strconv.Atoi(p)
	if err != nil {
		return nil, nil, 0, err
	}
	Port = make([]byte, 2)
	binary.BigEndian.PutUint16(Port, uint16(pp))

	return
}

func reply(w io.Writer, message []byte) error {
	_, err := w.Write(message)
	if err != nil {
		return fmt.Errorf("failed to write response: %w", err)
	}
	return nil
}

func readAddress(r io.Reader, n byte) (Address, error) {
	switch n {
	case 4 + 2: // IPv4
		read, err := readN(r, n)
		if err != nil {
			return nil, err
		}
		return IPAddr{Ip: read[:4], Port: read[4:]}, nil

	case 16 + 2: // IPv6
		read, err := readN(r, n)
		if err != nil {
			return nil, err
		}
		return IPAddr{Ip: read[:16], Port: read[16:]}, nil

	default: // Domain
		read, err := readN(r, 1)
		if err != nil {
			return nil, err
		}
		addrLen := read[0]
		read, err = readN(r, addrLen+2)
		if err != nil {
			return nil, err
		}
		return NewDomainNameAddr(read), nil
	}
}
