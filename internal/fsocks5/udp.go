package fsocks5

import (
	"bytes"
	"slices"
)

/*
+----+------+------+----------+----------+----------+
|RSV | FRAG | atyp | DST.ADDR | DST.PORT |  DATA    |
+----+------+------+----------+----------+----------+
| 2  |  1   |  1   | Variable |    2     | Variable |
+----+------+------+----------+----------+----------+
*/

type Datagram struct {
	addr Address
	data []byte
}

func ReadDatagramFrom(buffer []byte) (*Datagram, error) {
	// read [RSV FRAG atyp]
	reader := bytes.NewReader(buffer)
	read, err := readN(reader, 4)
	if err != nil {
		return nil, err
	}

	if !slices.Equal(read[:2], []byte{0x00, 0x00}) || read[2] != 0x00 {
		return nil, FormatErr
	}

	reader = bytes.NewReader(buffer[4:])
	datagram := &Datagram{}
	switch read[3] {
	case 0x01: // IPv4
		read, err = readN(reader, 4+2)
		if err != nil {
			return nil, err
		}
		datagram.addr = IPAddr{ip: read[:4], port: read[4:], atyp: 0x01}
		datagram.data = buffer[4+4+2:]

	case 0x03: // Domain
		read, err = readN(reader, 1)
		if err != nil {
			return nil, err
		}
		addrLen := read[0]
		read, err = readN(reader, addrLen+2)
		if err != nil {
			return nil, err
		}
		datagram.addr = NewDomainNameAddr(read)
		datagram.data = buffer[4+1+addrLen+2:]

	case 0x04: // IPv6
		read, err = readN(reader, 16+2)
		if err != nil {
			return nil, err
		}
		datagram.addr = IPAddr{ip: read[:16], port: read[16:], atyp: 0x04}
		datagram.data = buffer[4+16+2:]

	default:
		return nil, AddrErr
	}
	return datagram, nil
}

func (d *Datagram) Bytes() []byte {
	return append(append([]byte{
		0x00,           // RSV
		0x00,           // RSV
		0x00,           // FRAG
		d.addr.Atyp()}, // ATYP
		d.addr.Bytes()...), // DST.ADDR + DST.PORT
		d.data...) // DATA
}
