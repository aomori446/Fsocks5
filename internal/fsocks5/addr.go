package fsocks5

import (
	"encoding/binary"
	"net"
	"strconv"
)

// AddrZero represents an IPv4 zero address (0.0.0.0:0)
var AddrZero = ipAddr{
	ip:   net.IPv4zero,
	port: make([]byte, 2),
	atyp: 0x01,
}

// Addr defines a common interface for SOCKS5 address types
type Addr interface {
	String() string
	Bytes() []byte
	ATYP() byte
}

// ipAddr represents an IPv4 address with port
type ipAddr struct {
	ip   []byte
	port []byte
	atyp byte
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

// domainAddr represents a domain name address with port
type domainAddr struct {
	domain []byte // domain without length prefix
	port   []byte
	atyp   byte
}

func (d domainAddr) String() string {
	port := binary.BigEndian.Uint16(d.port)
	return net.JoinHostPort(string(d.domain), strconv.Itoa(int(port)))
}

// Bytes returns the address in [len][domain][port] format
func (d domainAddr) Bytes() []byte {
	return append([]byte{byte(len(d.domain))}, append(d.domain, d.port...)...)
}

func (d domainAddr) ATYP() byte {
	return d.atyp
}

// ResolveIPAddr parses a host:port string into an ipAddr
func ResolveIPAddr(hostPort string) (Addr, error) {
	ip, port, atyp, err := Parse(hostPort)
	if err != nil {
		return nil, err
	}
	return &ipAddr{ip: ip, port: port, atyp: atyp}, nil
}

// ResolveDomainAddr constructs a domainAddr from raw bytes [domain][port]
func ResolveDomainAddr(domain []byte) Addr {
	return &domainAddr{
		domain: domain[:len(domain)-2],
		port:   domain[len(domain)-2:],
		atyp:   0x03,
	}
}

// ResolveUDPAddr converts a net.Addr to an Addr
func ResolveUDPAddr(addr net.Addr) (Addr, error) {
	return ResolveIPAddr(addr.String())
}
