package fsocks5

import (
	"context"
	"io"
	"net"
)

func (r *Request) serveConnect(s *Server, conn1 net.Conn) error {
	conn2, err := net.Dial("tcp", r.address.ToString())
	if err != nil {
		s.config.Logger.Error("failed to connect to target", "target", r.address.ToString(), "err", err)
		resp := &Response{
			rep: hostUnreachable,
			address: IPAddr{
				Ip:   net.IPv4zero,
				Port: []byte{0x00, 0x00},
			},
		}
		_ = reply(conn1, resp.bytes())
		return err
	}

	ipAddr, err := NewIPAddr(conn2.LocalAddr().String())
	if err != nil {
		s.config.Logger.Error("failed to get local address", "err", err)
		conn2.Close()
		return err
	}

	resp := &Response{rep: succeeded, address: ipAddr}
	if err := reply(conn1, resp.bytes()); err != nil {
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

func (r *Request) serveUDPAssociate(s *Server, conn1 net.Conn) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// listen on local IP random port
	udpConn, err := net.ListenUDP("UDP", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return err
	}

	ipAddr, err := NewIPAddr(udpConn.LocalAddr().String())
	if err != nil {
		s.config.Logger.Error("failed to get local address", "err", err)
		udpConn.Close()
		return err
	}

	resp := &Response{rep: succeeded, address: ipAddr}
	if err = reply(conn1, resp.bytes()); err != nil {
		s.config.Logger.Error("failed to reply success to client", "err", err)
		udpConn.Close()
		return err
	}

	panic(ctx)
}
