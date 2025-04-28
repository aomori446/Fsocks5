package fsocks5

import (
	"encoding/binary"
	"net"
	"strconv"
)

type Address interface {
	ToString() string
	ToSlice() []byte
	GetATYP() byte
}

type IPAddr struct {
	Ip   []byte
	Port []byte
	ATYP byte
}

func NewIPAddr(hostPort string) (*IPAddr, error) {
	ip, port, atyp, err := parseHostPort(hostPort)
	if err != nil {
		return nil, err
	}

	return &IPAddr{Ip: ip, Port: port, ATYP: atyp}, nil
}

func (i IPAddr) ToString() string {
	port := binary.BigEndian.Uint16(i.Port)
	return net.JoinHostPort(net.IP(i.Ip).String(), strconv.Itoa(int(port)))
}

func (i IPAddr) ToSlice() []byte {
	return append(i.Ip, i.Port...)
}

func (i IPAddr) GetATYP() byte {
	return i.ATYP
}

type DomainNameAddr struct {
	Domain []byte //without prefix length
	Port   []byte
	ATYP   byte
}

func NewDomainNameAddr(address []byte) DomainNameAddr {
	return DomainNameAddr{
		Domain: address[:len(address)-2],
		Port:   address[len(address)-2:],
		ATYP:   0x03,
	}
}

func (d DomainNameAddr) ToString() string {
	port := binary.BigEndian.Uint16(d.Port)
	return net.JoinHostPort(string(d.Domain), strconv.Itoa(int(port)))
}

// ToSlice with prefix length
func (d DomainNameAddr) ToSlice() []byte {
	return append([]byte{byte(len(d.Domain))}, append(d.Domain, d.Port...)...)
}

func (d DomainNameAddr) GetATYP() byte {
	return d.ATYP
}
