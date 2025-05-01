package fsocks5

import "errors"

var (
	FormatErr  = errors.New("format is wrong")
	VersionErr = errors.New("unsupported SOCKS version")
	AddrErr    = errors.New("unsupported addr type")
	CMDErr     = errors.New("unsupported command")
)
