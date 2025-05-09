package fsocks5

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

type Server struct{}

// NewServer Create a new server instance with optional logging configuration
func NewServer() *Server {
	return &Server{}
}

// ListenAndServe Start listening on the given TCP address
func (s *Server) ListenAndServe(address string) error {
	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return err
	}

	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	slog.Info("Start listening", "addr", addr.String())
	defer slog.Info("Stop listening", "addr", addr.String())

	return s.serve(listener)
}

// Accept and handle incoming TCP connections
func (s *Server) serve(listener *net.TCPListener) error {
	for {
		tcpConn, err := listener.AcceptTCP()
		if err != nil {
			slog.Warn("Failed to accept connection", "err", err)
			continue
		}

		slog.Debug("New connection", "clientAddr", tcpConn.RemoteAddr().String())

		go func(conn *net.TCPConn) {
			defer conn.Close() // Always close client connection at the end

			if err := s.serveConn(conn); err != nil {
				slog.Error("Disconnected", "remoteAddr", conn.RemoteAddr().String(), "err", err)
			}
		}(tcpConn)
	}
}

// Handle a single client connection
func (s *Server) serveConn(conn *net.TCPConn) error {
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return err
	}

	if err := Auth(conn); err != nil {
		return err
	}

	req, err := NewRequest(conn)
	if err != nil {
		return err
	}

	switch req.cmd {
	case 0x01:
		defer func() {
			if req.cancel != nil {
				req.cancel()
			}
		}()
		return serveConnect(conn, req)
	case 0x02:
		return serveBind()
	case 0x03:
		return serveUDPAssociate(conn, req)
	default:
		return ErrCMD
	}
}

// Handle TCP CONNECT command
func serveConnect(conn net.Conn, req *Request) error {
	remoteConn, err := net.Dial("tcp", req.remote.String())
	if err != nil {
		return ReplyTo(conn, NewResponse(generalSOCKSServerFailure, AddrZero).Bytes())
	}
	defer remoteConn.Close()

	if err = ReplyTo(conn, NewResponse(succeeded, req.proxy).Bytes()); err != nil {
		return err
	}

	wg := &sync.WaitGroup{}
	wg.Add(2)

	// Pipe client -> remote
	go func() {
		defer wg.Done()
		io.Copy(remoteConn, conn)
	}()

	// Pipe remote -> client
	go func() {
		defer wg.Done()
		io.Copy(conn, remoteConn)
	}()

	wg.Wait()
	return nil
}

// Handle BIND command (not implemented yet)
func serveBind() error {
	return errors.New("TODO: serveBind()")
}

// Handle UDP ASSOCIATE command
func serveUDPAssociate(conn net.Conn, req *Request) error {
	// 1. Create a local UDP socket on a random port
	localConn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return err
	}
	defer localConn.Close()

	// 2. Send a reply to the client indicating the UDP relay is ready
	localAddr, err := resolveUDPAddr(localConn.LocalAddr())
	if err != nil {
		return err
	}
	if err = ReplyTo(conn, NewResponse(succeeded, localAddr).Bytes()); err != nil {
		return err
	}

	// 3. Set up a context to stop UDP handling when the TCP control connection closes
	ctx, cancel := context.WithCancel(context.Background())
	req.cancel = cancel

	buffer := make([]byte, 1500)
	for {
		select {

		case <-ctx.Done():
			return nil

		default:
			// 4. Read incoming UDP packet from the client
			n, clientAddr, err := localConn.ReadFromUDP(buffer)
			if err != nil {
				slog.Error("read from client UDP failed", "err", err)
				continue
			}

			// // 5. Verify the client's source address if specified in the request
			if req.client.String() != "0.0.0.0:0" && req.client.String() != clientAddr.String() {
				slog.Warn("received UDP from unexpected client", "client", clientAddr.String())
				continue
			}

			// 6. Parse the SOCKS5 UDP datagram
			dg, err := ResolveDatagram(buffer[:n])
			if err != nil {
				slog.Error("failed to Parse datagram", "err", err)
				continue
			}

			// 7. Resolve the target address and forward the payload
			remoteAddr, err := net.ResolveUDPAddr("udp", dg.addr.String())
			if err != nil {
				slog.Error("failed to resolve remote addr", "err", err)
				continue
			}

			_, err = localConn.WriteTo(dg.data, remoteAddr)
			if err != nil {
				slog.Error("failed to send to remote", "err", err)
				continue
			}

			// 8. Read response from the remote server
			n, _, err = localConn.ReadFrom(buffer)
			if err != nil {
				slog.Error("failed to read from remote", "err", err)
				continue
			}

			// 9. Wrap the response in a SOCKS5 datagram
			response := &Datagram{
				addr: dg.addr,
				data: buffer[:n],
			}

			// 10. Send it back to the original client
			_, err = localConn.WriteTo(response.Bytes(), clientAddr)
			if err != nil {
				slog.Error("failed to write back to client", "err", err)
				continue
			}
		}
	}
}
