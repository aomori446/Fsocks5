package main

import (
	"errors"
	"fmt"
	"io"
)

var (
	FormatErr  = errors.New("format is wrong")
	VersionErr = errors.New("unsupported SOCKS version")
)

var (
	NoAuth   byte = 0x00
	GSSAPI   byte = 0x01
	NamePwd  byte = 0x02
	NoAccept byte = 0xFF
)

func Auth(rw io.ReadWriter) error {
	read, err := readN(rw, 2)
	if err != nil {
		return err
	}

	switch {
	case read[0] != 0x05:
		return VersionErr

	case read[1] < 1:
		return FormatErr

	default:
		read, err = readN(rw, read[1])
		if err != nil {
			return FormatErr
		}
		return subNegotiate(rw, read)
	}
}

func reply(w io.Writer, message []byte) error {
	_, err := w.Write(message)
	if err != nil {
		return fmt.Errorf("failed to write response: %w", err)
	}
	return nil
}

func authNoAuth(rw io.ReadWriter) error {
	return reply(rw, []byte{0x05, NoAuth}) // No authentication required
}

func authGSSAPI(rw io.ReadWriter) error {
	// TODO: Implement GSSAPI authentication
	// As a placeholder, reject GSSAPI authentication for now
	return reply(rw, []byte{0x05, NoAccept})
}

func authNamePwd(rw io.ReadWriter) error {
	if err := reply(rw, []byte{0x05, NamePwd}); err != nil {
		return err
	}

	read, err := readN(rw, 2)
	if err != nil {
		return err
	}

	var username, password string

	switch {
	case read[0] != 0x01, read[1] == 0:
		return FormatErr

	default:
		read, err = readN(rw, read[1]+1)
		if err != nil {
			return err
		}
		username = string(read[:len(read)-1])

		switch {
		case username == "", read[len(read)-1] == 0:
			return FormatErr

		default:
			read, err = readN(rw, read[len(read)-1])
			password = string(read)
			if HasUser(username, password) {
				return reply(rw, []byte{0x01, 0x00})
			}
			return reply(rw, []byte{0x01, 0xFF})
		}
	}
}

var authMethods = map[byte]func(io.ReadWriter) error{
	NoAuth:  authNoAuth,
	GSSAPI:  authGSSAPI,
	NamePwd: authNamePwd,
}

func subNegotiate(rw io.ReadWriter, ms []byte) error {
	// Select appropriate authentication method
	for _, method := range ms {
		if authFunc, ok := authMethods[method]; ok {
			return authFunc(rw)
		}
	}
	// If no supported method is found, reject with NoAccept
	return reply(rw, []byte{0x05, NoAccept})
}
