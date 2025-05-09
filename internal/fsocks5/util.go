package fsocks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

func ReadN(r io.Reader, n byte) ([]byte, error) {
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

func Parse(hostPort string) (ip []byte, port []byte, atyp byte, err error) {
	host, p, err := net.SplitHostPort(hostPort)
	if err != nil {
		return nil, nil, 0, err
	}

	parsedIP := net.ParseIP(host)
	if parsedIP == nil {
		return nil, nil, 0, errors.New("invalid ip")
	}
	if ip4 := parsedIP.To4(); ip4 != nil {
		ip = ip4
		atyp = 0x01
	} else {
		ip = parsedIP.To16()
		atyp = 0x04
	}

	pp, err := strconv.Atoi(p)
	if err != nil {
		return nil, nil, 0, err
	}
	port = make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(pp))

	return
}

func ReplyTo(w io.Writer, message []byte) error {
	_, err := w.Write(message)
	if err != nil {
		return fmt.Errorf("failed to write response: %w", err)
	}
	return nil
}
