# Fsocks5

A socks5 server

## Feature
* Support TCP/UDP and IPv4/IPv6
* Support for the CONNECT command
* Support for the ASSOCIATE command

## Useage
```go
func main() {
	server := fsocks5.NewServer()
	log.Fatal(server.ListenAndServe(":9999"))
}
```

## TODO
* Support for the BIND command

## Reference
* [rfc1928](https://www.ietf.org/rfc/rfc1928.txt)

## License

This project is under MIT License. See the [LICENSE](https://github.com/aomori446/Fangks?tab=MIT-1-ov-file#) file for the full license text.
