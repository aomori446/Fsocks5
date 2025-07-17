package fsocks5

import (
	"errors"
	"io"
	"slices"
)

var (
	ErrNoAcceptableMethods = errors.New("no acceptable methods")
)

func Auth(conn io.ReadWriter) error {
	message, err := ReadExact(conn, 2)
	if err != nil {
		return err
	}

	version := message[0]
	numOfMethods := message[1]

	switch {
	case version != 0x05: //直接關閉連結，不返回錯誤訊息給客戶端
		return ErrVersion

	case numOfMethods < 1: //直接關閉連結，不返回錯誤訊息給客戶端
		return ErrAuthFormat

	default:
		methods, err := ReadExact(conn, numOfMethods)
		if err != nil { //直接關閉連結，不返回錯誤訊息給客戶端
			return ErrAuthFormat
		}
		// 若發生錯誤，返回錯誤訊息給客戶端
		return auth(conn, methods)
	}
}

func auth(rw io.ReadWriter, methods []byte) error {
	supported, err := AuthMethods.supported(methods)
	if err != nil {
		// 沒有支援的認證方法，主動回應 0xFF
		if replyErr := ReplyTo(rw, []byte{0x05, 0xFF}); replyErr != nil {
			return errors.Join(err, replyErr)
		}
		return err
	}

	// 找到支援的方法才交給該方法去回應 (它會送出 0x00, 0x02 等)
	return AuthMethods[supported](rw)
}

var AuthMethods = authMethods{}

type authMethods map[byte]func(io.ReadWriter) error

func (a authMethods) supported(methods []byte) (byte, error) {
	for m := range a {
		if slices.Contains(methods, m) {
			return m, nil
		}
	}
	return 0, ErrNoAcceptableMethods
}

func (a authMethods) SupportNoAuth() {
	a[0x00] = func(rw io.ReadWriter) error {
		return ReplyTo(rw, []byte{0x05, 0x00})
	}
}

func (a authMethods) SupportGSSAPI() {
	a[0x01] = func(rw io.ReadWriter) error {
		return ReplyTo(rw, []byte{0x05, 0xFF}) //暫時先不支持
	}
}

func (a authMethods) SupportUsernamePassword(hasUser func(name, password string) bool) {
	a[0x02] = func(rw io.ReadWriter) error {
		if err := ReplyTo(rw, []byte{0x05, 0x02}); err != nil {
			return err
		}
		data, err := ReadExact(rw, 2)
		if err != nil {
			return err
		}

		if data[0] != 0x01 {
			return ErrFormat
		}

		ulen := int(data[1])
		uname, err := ReadExact(rw, byte(ulen))
		if err != nil {
			return err
		}

		plenBuf := make([]byte, 1)
		if _, err := io.ReadFull(rw, plenBuf); err != nil {
			return err
		}
		plen := int(plenBuf[0])

		passwd, err := ReadExact(rw, byte(plen))
		if err != nil {
			return err
		}

		username := string(uname)
		password := string(passwd)

		if hasUser(username, password) {
			return ReplyTo(rw, []byte{0x01, 0x00}) // success
		}
		return ReplyTo(rw, []byte{0x01, 0xFF}) // failure
	}
}
