sniffer: *.go
	go build  sniffer.go db_orm.go server.go config.go

clean:
	rm -f sniffer httpdump.db
