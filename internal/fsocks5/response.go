package fsocks5

const (
	succeeded                     = byte(0x00)
	generalSOCKSServerFailure     = byte(0x01)
	connectionNotAllowedByRuleset = byte(0x02)
	networkUnreachable            = byte(0x03)
	hostUnreachable               = byte(0x04)
	connectionRefused             = byte(0x05)
	ttlExpired                    = byte(0x06)
	commandNotSupported           = byte(0x07)
	addressTypeNotSupported       = byte(0x08)
)

type Response struct {
	rep  byte
	addr Addr
}

func NewResponse(rep byte, addr Addr) Response {
	return Response{rep: rep, addr: addr}
}

func (r Response) Bytes() []byte {
	return append([]byte{0x05, r.rep, 0x00, r.addr.ATYP()}, r.addr.Bytes()...)
}
