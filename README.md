# httpdump

Httpdump capture http packet in gopacket(libpcap).

The httpdump project captures packets through pcap and parses the http protocol. 
The fetched results will be stored in the database. 
He also provides a webserver interface to view packet capture results.

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
nohup ./sniffer -i eth0 &
```

# capture example:
```
192.168.10.110->175.27.0.201:54893->80

extshort.weixin.qq.com
POST /mmtls/1d70cf00 HTTP/1.1 
Connection :[close]
Content-Length :[542]
Content-Type :[application/octet-stream]
Upgrade :[mmtls]
User-Agent :[MicroMessenger Client]
Accept :[*/*]
Cache-Control :[no-cache]

175.27.0.201->192.168.10.110:80->54893

HTTP/1.1 200 OK
Content-Type :[application/octet-stream]
Content-Length :[229]

```

# View results through webserver
```
http://127.0.0.1:8080/html
```
![image](http://www.zhanluejia.net.cn/static/uploads/a4711c853304a81c3cb7936eaf92166e.png)

