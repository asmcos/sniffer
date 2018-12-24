
httpdump: *.go
	go build -v -o httpdump main.go db_orm.go http_parse.go server.go reader_bytes.go
clean:
	rm -f httpdump httpdump.db
