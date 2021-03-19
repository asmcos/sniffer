sniffer: *.go
	go build  sniffer.go config.go

clean:
	rm -f sniffer httpdump.db
