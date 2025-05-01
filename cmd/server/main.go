package main

import (
	"Fsocks5/internal/fsocks5"
	"log"
	"os"
)

func main() {
	server := fsocks5.NewServer()
	log.Fatal(server.ListenAndServe(os.Args[1]))
}
