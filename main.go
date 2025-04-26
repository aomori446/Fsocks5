package main

import (
	"log"
	"net"
	"time"
)

func main() {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{Port: 9999})
	if err != nil {
		log.Fatal(err)
	}

	defer listener.Close()

	for {
		tcpConn, err := listener.AcceptTCP()
		if err != nil {
			log.Println(err)
			continue
		}

		go func(){
			if err := withTcpConn(tcpConn); err != nil {
				log.Println(err)
			}
		}()
	}
}

func withTcpConn(conn *net.TCPConn) error {
	if err := conn.SetReadDeadline(time.Now().Add(time.Second * 30)); err != nil {
		log.Println(err)
		return conn.Close()
	}

	if err := Auth(conn); err != nil {
		log.Println(err)
		return conn.Close()
	}

	req, err := ParseRequest(conn)
	if err != nil {
		log.Println(err)
		return conn.Close()
	}

	return req.ServeCMD(conn)
}
