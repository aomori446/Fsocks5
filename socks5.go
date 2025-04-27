package Fsocks5

import (
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

func (s *Server) ListenAndServe(addr *net.TCPAddr) error {
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
			s.config.Logger.Error("connect failed", "remoteAddr", tcpConn.RemoteAddr().String())
			continue
		}

		s.config.Logger.Info("new connection", "remoteAddr", tcpConn.RemoteAddr().String())

		go func(conn *net.TCPConn) {
			if err := s.ServeConn(conn); err != nil {
				remoteAddr := conn.RemoteAddr().String()
				s.config.Logger.Error("disconnect from", "remoteAddr", remoteAddr, "err", err)

				if closeErr := conn.Close(); closeErr != nil {
					s.config.Logger.Error("unable to close conn", "remoteAddr", remoteAddr, "err", closeErr)
				}
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

	req, err := NewRequest(conn, s.config.Logger)
	if err != nil {
		return err
	}

	return s.handleRequest(req, conn)
}
