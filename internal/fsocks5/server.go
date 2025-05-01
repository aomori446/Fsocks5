package fsocks5

import (
	"log/slog"
	"net"
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

	request, err := NewRequest(conn)
	if err != nil {
		return err
	}

	return s.handleRequest(request)
}

// Dispatch request to appropriate handler based on command
func (s *Server) handleRequest(request *Request) error {
	switch request.cmd {
	case 0x01: // CONNECT
		defer func() {
			if request.cancel != nil {
				request.cancel()
			}
		}()
		return request.serveConnect()

	case 0x02: // BIND
		return request.serveBind()

	case 0x03: // UDP ASSOCIATE
		return request.serveUDPAssociate()

	default:
		return CMDErr
	}
}
