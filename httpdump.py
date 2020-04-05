import dpkt, pcap
import re
import socket
import time
from struct import unpack

pc = pcap.pcap('en0',immediate=True)
pc.setfilter("port 80")
tracker={}
for ts, pkt in pc:
    try:
        ethernet=dpkt.ethernet.Ethernet(pkt)
        ip=ethernet.data
        tcp=ip.data
        data=tcp.data
        dst=socket.inet_ntoa(ip.dst)
        src=socket.inet_ntoa(ip.src)
    except socket.error:
        continue
    ltuple=(src,tcp.sport,dst,tcp.dport)
    rtuple=(dst,tcp.dport,src,tcp.sport)
    try:
        tracker[ltuple]
        try:
            tracker[ltuple]['out']+=data
        except KeyError:
            tracker[ltuple]['out']=data
        tracker[ltuple]['lastseen']=time.time()
    except KeyError:
        try:
            tracker[rtuple]
            tracker[rtuple]['in']+=data
        except KeyError:
            tracker[rtuple]={
                'in'        : data,
                'complete'  : False,
                'firstseen' : time.time()
                }
        tracker[rtuple]['lastseen']=time.time()

    for connection in tracker.keys():
        if time.time()-tracker[connection]['lastseen']>600:
            del tracker[connection]
            continue
        if tracker[connection]['complete']==True:
            if time.time()-tracker[connection]['lastseen']>60:
                del tracker[connection]
            continue
        try:
            if tracker[connection]['in'] and tracker[connection]['out']:
                data=tracker[connection]['in'] 
                data+=tracker[connection]['out']
                data = str(data)
                uri=re.search("(GET|POST) ([^\r\n]*)",data,re.IGNORECASE)
                host=re.search("Host: ([^\r\n]*)",data,re.IGNORECASE)
                response=re.search("(HTTP/[\d\.]+) (\d+) ([^\r\n]+)",data,re.IGNORECASE)
                if uri and host and response:
                    print ("%-8d [%16s:%-6d => %16s:%-6d ] \n [ %s %s %-16s ] \n%6s  http://%s%s" % (
                        len(tracker),
                        connection[0],
                        connection[1],
                        connection[2],
                        connection[3],
                        response.group(1),
                        response.group(2),
                        response.group(3),
                        uri.group(1),
                        host.group(1),
                        uri.group(2)
                        ))
                    tracker[connection]['complete']=True
        except KeyError:
           pass
