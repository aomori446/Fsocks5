package fsocks5

import "net"

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

var failedResponseWithReason = func(reason byte) *Response {
	return &Response{
		rep: reason,
		address: IPAddr{
			ip:   net.IPv4zero,
			port: []byte{0x00, 0x00},
		},
	}
}

var SucceededResponse = func(hostPort string) *Response {
	ipAddr, _ := NewIPAddr(hostPort)
	return &Response{
		rep:     succeeded,
		address: ipAddr,
	}
}

type Response struct {
	rep     byte
	address Address
}

func (r *Response) bytes() []byte {
	return append([]byte{0x05, r.rep, 0x00, r.address.Atyp()}, r.address.Bytes()...)
}
