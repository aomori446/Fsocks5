package fsocks5

import (
	"context"
	"io"
	"net"
	"sync"
)

func serveConnect(r *Request, clientConn net.Conn) (err error) {
	remoteConn, err := net.Dial("tcp", r.addr.ToString())
	if err != nil {
		_ = reply(clientConn, UnreachableResponse.bytes())
		return
	}
	// only close remote connection here.
	defer remoteConn.Close()

	resp, err := NewResponse(succeeded, remoteConn.LocalAddr().String())
	if err != nil {
		return
	}
	_ = reply(clientConn, resp.bytes())

	wg := &sync.WaitGroup{}
	wg.Add(1)

	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		_, err = io.Copy(clientConn, remoteConn)
	}(wg)

	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		defer wg.Done()
		_, err = io.Copy(remoteConn, clientConn)
	}(wg)

	wg.Wait()
	return
}

func (r *Request) serveBind(s *Server, conn1 net.Conn) error {
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
		s.config.Logger.Error("failed to get local addr", "err", err)
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
