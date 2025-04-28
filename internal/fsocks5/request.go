package fsocks5

import (
	"io"
)

type Request struct {
	cmd  byte
	atyp byte
	addr Address
}

func NewRequest(r io.Reader) (*Request, error) {
	read, err := readN(r, 4)
	if err != nil {
		return nil, err
	}
	if read[0] != 0x05 || read[2] != 0x00 {
		return nil, VersionErr
	}

	req := &Request{
		cmd:  read[1],
		atyp: read[3],
	}

	if err = setRequestAddress(r, req); err != nil {
		return nil, err
	}

	return req, nil
}
