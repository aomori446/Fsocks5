package fsocks5

import (
	"Fsocks5"
	"errors"
	"net"
)

/*
+----+------+------+----------+----------+----------+
|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |  DATA    |
+----+------+------+----------+----------+----------+
| 2  |  1   |  1   | Variable |    2     | Variable |
+----+------+------+----------+----------+----------+
*/

type Datagram struct {
	Address Fsocks5.Address
	Data    []byte
}

func ReadOneDatagram(conn *net.UDPConn) (*Datagram, error) {
	buf := make([]byte, 65536)
	n, clientAddr, err := conn.ReadFrom(buf)
	if err != nil {
		return nil, err
	}
	if buf[0] != 0x00 && buf[1] != 0x00 {
		return nil, Fsocks5.FormatErr
	}

	//not support fragmentation, drop any datagram whose FRAG field is other than X'00'.
	if buf[2] != 0x00 {
		return nil, errors.New("not support fragmentation")
	}

	var address Fsocks5.Address
	switch buf[3] {
	case 0x01:

	}
}
