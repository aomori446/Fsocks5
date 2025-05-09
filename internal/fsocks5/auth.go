package fsocks5

import (
	"io"
)

var (
	NoAuth   = byte(0x00)
	GSSAPI   = byte(0x01)
	NamePwd  = byte(0x02)
	NoAccept = byte(0xFF)
)

func Auth(rw io.ReadWriter) error {
	data, err := ReadN(rw, 2)
	if err != nil {
		return err
	}

	switch {
	case data[0] != 0x05:
		return ErrVersion

	case data[1] < 1:
		return ErrFormat

	default:
		data, err = ReadN(rw, data[1])
		if err != nil {
			return ErrFormat
		}
		return auth(rw, data)
	}
}

func auth(rw io.ReadWriter, ms []byte) error {
	for _, m := range ms {
		if authFunc, ok := authMethods[m]; ok {
			return authFunc(rw)
		}
	}
	// If no supported method is found, reject with NoAccept
	return ReplyTo(rw, []byte{0x05, NoAccept})
}

var authMethods = map[byte]func(io.ReadWriter) error{
	NoAuth:  authNoAuth,
	GSSAPI:  authGSSAPI,
	NamePwd: authNamePwd,
}

func authNoAuth(rw io.ReadWriter) error {
	return ReplyTo(rw, []byte{0x05, NoAuth}) // No authentication required
}

func authGSSAPI(rw io.ReadWriter) error {
	// TODO: Implement GSSAPI authentication
	// As a placeholder, reject GSSAPI authentication for now
	return ReplyTo(rw, []byte{0x05, NoAccept})
}

func authNamePwd(rw io.ReadWriter) error {
	if err := ReplyTo(rw, []byte{0x05, NamePwd}); err != nil {
		return err
	}

	data, err := ReadN(rw, 2)
	if err != nil {
		return err
	}

	var username, password string

	switch {
	case data[0] != 0x01, data[1] == 0:
		return ErrFormat

	default:
		data, err = ReadN(rw, data[1]+1)
		if err != nil {
			return err
		}
		username = string(data[:len(data)-1])

		switch {
		case username == "", data[len(data)-1] == 0:
			return ErrFormat

		default:
			data, err = ReadN(rw, data[len(data)-1])
			if err != nil {
				return err
			}

			password = string(data)
			if hasUser(username, password) {
				return ReplyTo(rw, []byte{0x01, 0x00})
			}
			return ReplyTo(rw, []byte{0x01, 0xFF})
		}
	}
}

func hasUser(username string, password string) bool {
	if username == "admin" && password == "password" {
		return true
	}
	return false
}
