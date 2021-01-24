sniffer: *.go
	sudo go run sniffer.go assembly.go reader_sniffer.go -i en0

httpdump: *.go
	go build -v -o httpdump main.go db_orm.go http_parse.go server.go reader_bytes.go
clean:
	rm -f httpdump httpdump.db
