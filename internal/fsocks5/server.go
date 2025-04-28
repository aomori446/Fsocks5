package fsocks5

import (
	"errors"
	"log/slog"
	"net"
	"os"
	"time"
)

type Config struct {
	Logger *slog.Logger
}

type Server struct {
	config *Config
}

func NewServer(config *Config) *Server {
	if config == nil {
		config = &Config{}
	}
	if config.Logger == nil {
		config.Logger = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	}

	return &Server{
		config: config,
	}
}

func (s *Server) ListenAndServe(address string) error {
	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return err
	}

	listener, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}

	s.config.Logger.Info("start listening", "addr", addr.String())
	defer s.config.Logger.Info("stop listening", "addr", addr.String())

	s.Serve(listener)

	return nil
}

func (s *Server) Serve(listener *net.TCPListener) {
	for {
		tcpConn, err := listener.AcceptTCP()
		if err != nil {
			continue
		}

		s.config.Logger.Info("new connection", "remoteAddr", tcpConn.RemoteAddr().String())

		go func(conn *net.TCPConn) {
			if err := s.ServeConn(conn); err != nil {
				remoteAddr := conn.RemoteAddr().String()
				s.config.Logger.Error("disconnect from", "remoteAddr", remoteAddr, "err", err)

				//only close client connection here.
				_ = conn.Close()
			}
		}(tcpConn)
	}
}

func (s *Server) ServeConn(conn *net.TCPConn) error {
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

	return s.handleRequest(req, conn)
}

func (s *Server) handleRequest(r *Request, conn net.Conn) error {
	switch r.cmd {
	case 0x01:
		return serveConnect(r, conn)
	case 0x02:
		return r.serveBind(s, conn)
	case 0x03:
		return r.serveUDPAssociate(s, conn)
	default:
		return errors.New("unsupported command")
	}
}
