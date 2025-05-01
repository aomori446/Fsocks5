package fsocks5

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
)

type Request struct {
	cmd    byte
	addr   Address
	conn   *net.TCPConn
	cancel context.CancelFunc // Cancel UDP context when TCP connection is closed
}

// NewRequest Parse SOCKS5 request from TCP connection
func NewRequest(conn *net.TCPConn) (*Request, error) {
	read, err := readN(conn, 4)
	if err != nil {
		return nil, err
	}
	if read[0] != 0x05 || read[2] != 0x00 {
		return nil, VersionErr
	}

	req := &Request{
		cmd:  read[1],
		conn: conn,
	}

	switch read[3] {
	case 0x01: // IPv4
		read, err = readN(conn, 4+2)
		if err != nil {
			return nil, err
		}
		req.addr = IPAddr{ip: read[:4], port: read[4:], atyp: 0x01}

	case 0x03: // Domain
		read, err = readN(conn, 1)
		if err != nil {
			return nil, err
		}
		addrLen := read[0]
		read, err = readN(conn, addrLen+2)
		if err != nil {
			return nil, err
		}
		req.addr = NewDomainNameAddr(read)

	case 0x04: // IPv6
		read, err = readN(conn, 16+2)
		if err != nil {
			return nil, err
		}
		req.addr = IPAddr{ip: read[:16], port: read[16:], atyp: 0x04}

	default:
		return nil, AddrErr
	}

	return req, nil
}

// Send a SOCKS5 reply to the client
func (request *Request) reply(response *Response) error {
	return reply(request.conn, response.bytes())
}

// Handle TCP CONNECT command
func (request *Request) serveConnect() (err error) {
	remoteConn, err := net.Dial("tcp", request.addr.String())
	if err != nil {
		return request.reply(failedResponseWithReason(hostUnreachable))
	}
	defer remoteConn.Close()

	if err = request.reply(SucceededResponse(remoteConn.LocalAddr().String())); err != nil {
		return err
	}

	wg := &sync.WaitGroup{}
	wg.Add(2)

	// Pipe client -> remote
	go func() {
		defer wg.Done()
		io.Copy(remoteConn, request.conn)
	}()

	// Pipe remote -> client
	go func() {
		defer wg.Done()
		io.Copy(request.conn, remoteConn)
	}()

	wg.Wait()
	return nil
}

// Handle BIND command (not implemented yet)
func (request *Request) serveBind() error {
	return errors.New("TODO: serveBind()")
}

// Handle UDP ASSOCIATE command
func (request *Request) serveUDPAssociate() error {
	// 1. Create a local UDP socket on a random port
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: nil, Port: 0})
	if err != nil {
		return err
	}
	defer udpConn.Close()

	// 2. Send a reply to the client indicating the UDP relay is ready
	realPort := udpConn.LocalAddr().(*net.UDPAddr).Port
	realIP := request.conn.LocalAddr().(*net.TCPAddr).IP
	udpAddr := &net.UDPAddr{
		IP:   realIP,
		Port: realPort,
	}
	if err = request.reply(SucceededResponse(udpAddr.String())); err != nil {
		return err
	}

	// 3. Set up a context to stop UDP handling when the TCP control connection closes
	ctx, cancel := context.WithCancel(context.Background())
	request.cancel = cancel

	buffer := make([]byte, 0xFFFF)

	for {
		select {
		case <-ctx.Done():
			return nil

		default:
			// 4. Read incoming UDP packet from the client
			n, clientAddr, err := udpConn.ReadFromUDP(buffer)
			if err != nil {
				slog.Error("read from client UDP failed", "err", err)
				continue
			}

			// 5. Verify the client's source address if specified in the request
			if request.addr.String() != "0.0.0.0:0" && clientAddr.String() != request.addr.String() {
				slog.Warn("received UDP from unexpected client", "client", clientAddr.String())
				continue
			}

			// 6. Parse the SOCKS5 UDP datagram
			dgram, err := ReadDatagramFrom(buffer[:n])
			if err != nil {
				slog.Error("failed to parse datagram", "err", err)
				continue
			}

			// 7. Resolve the target address and forward the payload
			remoteAddr, err := net.ResolveUDPAddr("udp", dgram.addr.String())
			if err != nil {
				slog.Error("failed to resolve remote addr", "err", err)
				continue
			}

			_, err = udpConn.WriteTo(dgram.data, remoteAddr)
			if err != nil {
				slog.Error("failed to send to remote", "err", err)
				continue
			}

			// 8. Read response from the remote server
			n, _, err = udpConn.ReadFrom(buffer)
			if err != nil {
				slog.Error("failed to read from remote", "err", err)
				continue
			}

			// 9. Wrap the response in a SOCKS5 datagram
			response := &Datagram{
				addr: dgram.addr,
				data: buffer[:n],
			}
			wrapped := response.Bytes()

			// 10. Send it back to the original client
			_, err = udpConn.WriteTo(wrapped, clientAddr)
			if err != nil {
				slog.Error("failed to write back to client", "err", err)
				continue
			}
		}
	}
}
