sniffer: *.go
	go build sniffer.go db_orm.go server.go

clean:
	rm -f sniffer httpdump.db
