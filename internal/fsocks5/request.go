package fsocks5

import (
	"context"
	"net"
)

type Request struct {
	cmd    byte
	client Addr
	proxy  Addr
	remote Addr
	cancel context.CancelFunc // Cancel UDP context when TCP connection is closed
}

// NewRequest Parse SOCKS5 request from TCP connection
func NewRequest(conn *net.TCPConn) (*Request, error) {
	data, err := ReadN(conn, 4)
	if err != nil {
		return nil, err
	}
	if data[0] != 0x05 || data[2] != 0x00 {
		return nil, ErrVersion
	}

	req := &Request{
		cmd: data[1],
	}
	req.client, err = resolveIPAddr(conn.RemoteAddr().Network())
	if err != nil {
		return nil, err
	}

	req.proxy, err = resolveIPAddr(conn.LocalAddr().Network())
	if err != nil {
		return nil, err
	}

	switch data[3] {
	case 0x01: // IPv4
		data, err = ReadN(conn, 4+2)
		if err != nil {
			return nil, err
		}
		req.remote = ipAddr{ip: data[:4], port: data[4:], atyp: 0x01}

	case 0x03: // Domain
		data, err = ReadN(conn, 1)
		if err != nil {
			return nil, err
		}
		addrLen := data[0]
		data, err = ReadN(conn, addrLen+2)
		if err != nil {
			return nil, err
		}
		req.remote = resolveDomainAddr(data)

	case 0x04: // IPv6
		data, err = ReadN(conn, 16+2)
		if err != nil {
			return nil, err
		}
		req.remote = ipAddr{ip: data[:16], port: data[16:], atyp: 0x04}

	default:
		return nil, ErrAddr
	}

	return req, nil
}
