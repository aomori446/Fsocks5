package fsocks5

import "errors"

var (
	FormatErr  = errors.New("format is wrong")
	VersionErr = errors.New("unsupported SOCKS version")
)
