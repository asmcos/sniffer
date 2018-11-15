# httpdump

Httpdump capture http packet in gopacket(libpcap).

# install libpcap
for ubuntu/debian:

	sudo aptitude install libcap-dev

for centos/redhat/fedora:

	sudo yum install libpcap-devel


#depend

```
go get github.com/gin-gonic/gin
go get github.com/jinzhu/gorm
go get github.com/jinzhu/gorm/dialects/sqlite
```

# make
```
make
```

# run

```
nohup ./httpdump -i eth0 &
```
