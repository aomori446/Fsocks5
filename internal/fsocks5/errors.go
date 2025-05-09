package fsocks5

import "errors"

var (
	ErrFormat  = errors.New("unsupported format")
	ErrVersion = errors.New("unsupported SOCKS version")
	ErrAddr    = errors.New("unsupported addr type")
	ErrCMD     = errors.New("unsupported command")
)
