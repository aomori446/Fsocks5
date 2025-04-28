package main

import (
	"Fsocks5/internal/fsocks5"
	"log"
)

func main() {
	server := fsocks5.NewServer(nil)
	log.Fatal(server.ListenAndServe(":9999"))
}
