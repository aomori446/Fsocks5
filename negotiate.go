package Fsocks5

import (
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
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

func NewIPAddr(hostPort string, logger *slog.Logger) (IPAddr, error) {
	ipAddr := IPAddr{}
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		logger.Error("failed to split host and port", "hostPort", hostPort, "err", err)
		return ipAddr, err
	}
	parsedIP := net.ParseIP(host)
	if parsedIP == nil {
		logger.Error("invalid IP address", "host", host)
		return ipAddr, errors.New("invalid IP")
	}
	if ip4 := parsedIP.To4(); ip4 != nil {
		ipAddr.Ip = ip4
	} else {
		ipAddr.Ip = parsedIP.To16()
	}

	ipAddr.Port = make([]byte, 2)
	pp, err := strconv.Atoi(port)
	if err != nil {
		logger.Error("invalid port", "port", port, "err", err)
		return ipAddr, err
	}

	binary.BigEndian.PutUint16(ipAddr.Port, uint16(pp))
	logger.Debug("created IPAddr", "ip", ipAddr.Ip, "port", ipAddr.Port)
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

func NewDomainNameAddr(address []byte, logger *slog.Logger) DomainNameAddr {
	domainAddr := DomainNameAddr{
		Domain: address[:len(address)-2],
		Port:   address[len(address)-2:],
	}
	logger.Debug("created DomainNameAddr", "domain", string(domainAddr.Domain), "port", domainAddr.Port)
	return domainAddr
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

func NewRequest(rw io.Reader, logger *slog.Logger) (*Request, error) {
	read, err := readN(rw, 4)
	if err != nil {
		logger.Error("failed to read initial request bytes", "err", err)
		return nil, err
	}
	if read[0] != 0x05 || read[2] != 0x00 {
		logger.Error("invalid version or reserved field", "version", read[0], "reserved", read[2])
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
			logger.Error("failed to read IPv4 address and port", "err", err)
			return nil, err
		}
		req.address = IPAddr{Ip: read[:4], Port: read[4:]}

	case 0x03: // Domain
		read, err = readN(rw, 1)
		if err != nil {
			logger.Error("failed to read domain length", "err", err)
			return nil, err
		}
		addrLen := read[0]
		read, err = readN(rw, addrLen+2)
		if err != nil {
			logger.Error("failed to read domain name and port", "err", err)
			return nil, err
		}
		req.address = NewDomainNameAddr(read, logger)

	case 0x04: // IPv6
		read, err = readN(rw, 16+2)
		if err != nil {
			logger.Error("failed to read IPv6 address and port", "err", err)
			return nil, err
		}
		req.address = IPAddr{Ip: read[:16], Port: read[16:]}

	default:
		logger.Error("unsupported address type", "atyp", req.atyp)
		return nil, errors.New("unsupported address type")
	}

	logger.Info("created new request", "cmd", req.cmd, "atyp", req.atyp, "address", req.address.ToString())
	return req, nil
}

func (r *Request) serveConnect(s *Server, conn1 net.Conn) error {
	conn2, err := net.Dial("tcp", r.address.ToString())
	if err != nil {
		s.config.Logger.Error("failed to connect to target", "target", r.address.ToString(), "err", err)
		resp := &Response{
			rep:  hostUnreachable,
			atyp: 0x01,
			address: IPAddr{
				Ip:   net.IPv4zero,
				Port: []byte{0x00, 0x00},
			},
		}
		_ = resp.reply(conn1)
		return err
	}

	ipAddr, err := NewIPAddr(conn2.LocalAddr().String(), s.config.Logger)
	if err != nil {
		s.config.Logger.Error("failed to get local address", "err", err)
		conn2.Close()
		return err
	}

	resp := &Response{rep: succeeded, atyp: ipAddr.ATYP(), address: ipAddr}
	if err := resp.reply(conn1); err != nil {
		s.config.Logger.Error("failed to reply success to client", "err", err)
		conn2.Close()
		return err
	}

	s.config.Logger.Info("proxying connection", "client", conn1.RemoteAddr().String(), "target", r.address.ToString())

	go func() {
		defer conn1.Close()
		defer conn2.Close()
		_, err := io.Copy(conn1, conn2)
		if err != nil {
			s.config.Logger.Warn("error copying from target to client", "err", err)
		}
	}()

	go func() {
		defer conn1.Close()
		defer conn2.Close()
		_, err := io.Copy(conn2, conn1)
		if err != nil {
			s.config.Logger.Warn("error copying from client to target", "err", err)
		}
	}()

	return nil
}

func (r *Request) serveBind() error {
	panic("TODO: serveBind()")
}

func (r *Request) serveUDPAssociate() error {
	panic("TODO: serveUDPAssociate()")
}

func (s *Server) handleRequest(r *Request, conn net.Conn) error {
	s.config.Logger.Info("handling request", "cmd", r.cmd)
	switch r.cmd {
	case 0x01:
		return r.serveConnect(s, conn)
	case 0x02:
		return r.serveBind()
	case 0x03:
		return r.serveUDPAssociate()
	default:
		s.config.Logger.Error("unsupported command", "cmd", r.cmd)
		return errors.New("unsupported command")
	}
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

func (r *Response) bytes() []byte {
	return append([]byte{0x05, r.rep, 0x00, r.atyp}, r.address.ToSlice()...)
}

func (r *Response) reply(w io.Writer) error {
	_, err := w.Write(r.bytes())
	return err
}
