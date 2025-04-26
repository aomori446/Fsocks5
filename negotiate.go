package main

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
)

type Address interface {
	ToString() string
	ToSlice() []byte
	ATYP() byte
}

type IPAddr struct {
	Ip   []byte
	Port []byte
}

func IPAddrFormString(hostPort string) (IPAddr, error) {
	ipAddr := IPAddr{}
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return ipAddr, err
	}
	parsedIP := net.ParseIP(host)
	if parsedIP == nil {
		return ipAddr, errors.New("invalid IP")
	}
	if ip4 := parsedIP.To4(); ip4 != nil {
		ipAddr.Ip = ip4
	} else {
		ipAddr.Ip = parsedIP.To16()
	}

	ipAddr.Port = make([]byte, 2)
	pp, _ := strconv.Atoi(port)

	binary.BigEndian.PutUint16(ipAddr.Port, uint16(pp))
	return ipAddr, nil
}

func (i IPAddr) ToString() string {
	port := binary.BigEndian.Uint16(i.Port)
	return net.JoinHostPort(net.IP(i.Ip).String(), strconv.Itoa(int(port)))
}

func (i IPAddr) ToSlice() []byte {
	return append(i.Ip, i.Port...)
}

func (i IPAddr) ATYP() byte {
	if len(i.Ip) == 16 {
		return 0x04
	}
	return 0x01
}

type DomainNameAddr struct {
	Domain []byte
	Port   []byte
}

func (d DomainNameAddr) ToString() string {
	port := binary.BigEndian.Uint16(d.Port)
	return net.JoinHostPort(string(d.Domain), strconv.Itoa(int(port)))
}

func (d DomainNameAddr) ToSlice() []byte {
	return append([]byte{byte(len(d.Domain))}, append(d.Domain, d.Port...)...)
}

func (d DomainNameAddr) ATYP() byte {
	return 0x03
}

type Request struct {
	cmd     byte
	atyp    byte
	address Address
}

func ParseRequest(rw io.Reader) (*Request, error) {
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
		req.address = DomainNameAddr{Domain: read[:addrLen], Port: read[addrLen:]}

	case 0x04: // IPv6
		read, err = readN(rw, 16+2)
		if err != nil {
			return nil, err
		}
		req.address = IPAddr{Ip: read[:16], Port: read[16:]}

	default:
		return nil, errors.New("unsupported address type")
	}
	return req, nil
}

func (r *Request) ServeCMD(coon1 net.Conn) error {
	switch r.cmd {
	case 0x01:
		return r.serveConnect(coon1)
	case 0x02:
		return r.serveBind()
	case 0x03:
		return r.serveUDPAssociate()
	default:
		return errors.New("unsupported command")
	}
}

func (r *Request) serveConnect(conn1 net.Conn) error {
	conn2, err := net.Dial("tcp", r.address.ToString())
	if err != nil {
		resp := &Response{
			rep:  hostUnreachable,
			atyp: 0x01,
			address: IPAddr{
				Ip:   net.IPv4zero,
				Port: []byte{0x00, 0x00},
			},
		}
		_ = resp.Reply(conn1)
		return err
	}

	ipAddr, err := IPAddrFormString(conn2.LocalAddr().String())
	if err != nil {
		conn2.Close()
		return err
	}

	resp := &Response{rep: succeeded, atyp: ipAddr.ATYP(), address: ipAddr}
	if err := resp.Reply(conn1); err != nil {
		conn2.Close()
		return err
	}

	go func() {
		defer conn1.Close()
		defer conn2.Close()
		io.Copy(conn1, conn2)
	}()

	go func() {
		defer conn1.Close()
		defer conn2.Close()
		io.Copy(conn2, conn1)
	}()

	return nil
}

func (r *Request) serveBind() error {
	panic("TODO: serveBind()")
}

func (r *Request) serveUDPAssociate() error {
	panic("TODO: serveUDPAssociate()")
}

const (
	succeeded                     byte = 0x00
	generalSOCKSServerFailure          = 0x01
	connectionNotAllowedByRuleset      = 0x02
	networkUnreachable                 = 0x03
	hostUnreachable                    = 0x04
	connectionRefused                  = 0x05
	TTLExpired                         = 0x06
	commandNotSupported                = 0x07
	addressTypeNotSupported            = 0x08
)

type Response struct {
	rep     byte
	atyp    byte
	address Address
}

func (r *Response) Bytes() []byte {
	return append([]byte{0x05, r.rep, 0x00, r.atyp}, r.address.ToSlice()...)
}

func (r *Response) Reply(w io.Writer) error {
	_, err := w.Write(r.Bytes())
	return err
}
