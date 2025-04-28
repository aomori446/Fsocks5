package fsocks5

import (
	"io"
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
		return auth(rw, read)
	}
}

func auth(rw io.ReadWriter, ms []byte) error {
	for _, method := range ms {
		if authFunc, ok := authMethods[method]; ok {
			return authFunc(rw)
		}
	}
	// If no supported method is found, reject with NoAccept
	return reply(rw, []byte{0x05, NoAccept})
}

var authMethods = map[byte]func(io.ReadWriter) error{
	NoAuth:  authNoAuth,
	GSSAPI:  authGSSAPI,
	NamePwd: authNamePwd,
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
			if hasUser(username, password) {
				return reply(rw, []byte{0x01, 0x00})
			}
			return reply(rw, []byte{0x01, 0xFF})
		}
	}
}

func hasUser(username string, password string) bool {
	// TODO check database
	if username == "admin" && password == "password" {
		return true
	}
	return false
}
