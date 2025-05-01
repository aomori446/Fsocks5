package fsocks5

import (
	"encoding/binary"
	"net"
	"strconv"
)

type Address interface {
	String() string
	Bytes() []byte
	Atyp() byte
}

type IPAddr struct {
	ip   []byte
	port []byte
	atyp byte
}

func NewIPAddr(hostPort string) (*IPAddr, error) {
	ip, port, atyp, err := parseHostPort(hostPort)
	if err != nil {
		return nil, err
	}

	return &IPAddr{ip: ip, port: port, atyp: atyp}, nil
}

func (i IPAddr) String() string {
	port := binary.BigEndian.Uint16(i.port)
	return net.JoinHostPort(net.IP(i.ip).String(), strconv.Itoa(int(port)))
}

func (i IPAddr) Bytes() []byte {
	return append(i.ip, i.port...)
}

func (i IPAddr) Atyp() byte {
	return i.atyp
}

type DomainNameAddr struct {
	Domain []byte //without prefix length
	Port   []byte
	ATYP   byte
}

func NewDomainNameAddr(address []byte) *DomainNameAddr {
	return &DomainNameAddr{
		Domain: address[:len(address)-2],
		Port:   address[len(address)-2:],
		ATYP:   0x03,
	}
}

func (d DomainNameAddr) String() string {
	port := binary.BigEndian.Uint16(d.Port)
	return net.JoinHostPort(string(d.Domain), strconv.Itoa(int(port)))
}

// Bytes with prefix length
func (d DomainNameAddr) Bytes() []byte {
	return append([]byte{byte(len(d.Domain))}, append(d.Domain, d.Port...)...)
}

func (d DomainNameAddr) Atyp() byte {
	return d.ATYP
}
