package fsocks5

import (
	"encoding/binary"
	"net"
	"strconv"
)

var AddrZero = ipAddr{
	ip:   net.IPv4zero,
	port: make([]byte, 2),
	atyp: 0x01,
}

type Addr interface {
	String() string
	Bytes() []byte
	ATYP() byte
}

type ipAddr struct {
	ip   []byte
	port []byte
	atyp byte
}

func resolveIPAddr(hostPort string) (Addr, error) {
	ip, port, atyp, err := Parse(hostPort)
	if err != nil {
		return nil, err
	}

	return &ipAddr{ip: ip, port: port, atyp: atyp}, nil
}

func (i ipAddr) String() string {
	port := binary.BigEndian.Uint16(i.port)
	return net.JoinHostPort(net.IP(i.ip).String(), strconv.Itoa(int(port)))
}

func (i ipAddr) Bytes() []byte {
	return append(i.ip, i.port...)
}

func (i ipAddr) ATYP() byte {
	return i.atyp
}

type domainAddr struct {
	domain []byte //without prefix length
	port   []byte
	atyp   byte
}

func resolveDomainAddr(domain []byte) Addr {
	return &domainAddr{
		domain: domain[:len(domain)-2],
		port:   domain[len(domain)-2:],
		atyp:   0x03,
	}
}

func (d domainAddr) String() string {
	port := binary.BigEndian.Uint16(d.port)
	return net.JoinHostPort(string(d.domain), strconv.Itoa(int(port)))
}

// Bytes with prefix length
func (d domainAddr) Bytes() []byte {
	return append([]byte{byte(len(d.domain))}, append(d.domain, d.port...)...)
}

func (d domainAddr) ATYP() byte {
	return d.atyp
}

func resolveUDPAddr(addr net.Addr) (Addr, error) {
	return resolveIPAddr(addr.String())
}
