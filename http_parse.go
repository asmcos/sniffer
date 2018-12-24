/* Build a HTTP request parser using tcpassembly.StreamFactory and tcpassembly.Stream interfaces
 * http header,
 * request,
 * response
 * Author: asmcos
 */

package main

import (
	"bufio"
	"io"
	"log"
	"fmt"
	"time"
	"bytes"
	_"strconv"
	"strings"
	"net/http"
	"net/textproto"


	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct{}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	id             uint

}




func (h *httpStream)GetIpPort()(SrcIp string,DstIp string,SrcPort string,DstPort string){
    sip,dip := h.net.Endpoints()
    sport,dport := h.transport.Endpoints()

    return fmt.Sprintf("%v",sip),fmt.Sprintf("%v",dip),fmt.Sprintf("%v",sport),fmt.Sprintf("%v",dport)
}

// every packet call once New
func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}


	// src,dst := transport.Endpoints()
    go hstream.ReadData()

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
    return &hstream.r
}

func (h *httpStream) ReadData(){


	data := make([]byte, int32(*snaplen))
	var ReadHttp ReaderBytes

	for {
		l, err := h.r.Read(data)
		if err == io.EOF {
			if ReadHttp.initiated {
				ReadHttp.ReassemblyComplete()
			}
			return
		}
		if l > 10 && isResponse(data[:10]) {
			if ReadHttp.initiated {
				ReadHttp.ReassemblyComplete()
			}
			ReadHttp = NewReaderBytes()
			go h.runResponse(ReadHttp)
		}else if l > 10 && isRequest(data[:10]) {
			if ReadHttp.initiated {
				ReadHttp.ReassemblyComplete()
			}
			ReadHttp = NewReaderBytes()
			go h.runRequest(ReadHttp)
		}

		//[]Bytes
		if ReadHttp.initiated {
			ReadHttp.Reassembled([]Bytes{Bytes{Bytes: data[:l]}})
		}

	}



}



func (h *httpStream) runResponse(readhttp ReaderBytes) {

	fmt.Println("\n\r2->",h.net,h.transport)

	sip,dip,sport,dport := h.GetIpPort()

 	buf := bufio.NewReader(&readhttp)


	resp, err := http.ReadResponse(buf,nil)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		// We must read until we see an EOF... very important!
		return
	} else if err != nil {
		log.Println("Error reading stream", h.net, h.transport, ":", err)
	} else {
		// write database
		req := FindRequestFirst(db,sip,sport,dip,dport)
		//wait for 5 second
		for i:= 5; i > 0; i-- {
			fmt.Println("***-->",req,i)
			if req.ID == 0 {
				time.Sleep(1 * time.Second)
				req = FindRequestFirst(db,sip,sport,dip,dport)
			} else {
				break
			}
		}
		firstline := fmt.Sprintf("%s %s",resp.Proto, resp.Status)

		id := InsertResponseData(db,&ResponseTable{FirstLine:firstline,
			  StatusCode:resp.StatusCode,
			  SrcIp:sip,SrcPort:sport,
			  DstIp:dip,DstPort:dport},&req)
		h.id = id
		// type 1 is request, 2 is response
		HeaderToDB(resp.Header,2,h.id)

		printResponse(resp,h)

		bodyBytes := buf.Buffered() + DiscardBytesToEOF(&readhttp)
		log.Println("Body length",bodyBytes)

	}

}
func (h *httpStream) runRequest(readhttp ReaderBytes) {


	sip,dip,sport,dport := h.GetIpPort()

	buf := bufio.NewReader(&readhttp)


	req, err := http.ReadRequest(buf)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		// We must read until we see an EOF... very important!
		return
	} else if err != nil {
		log.Println("Error reading stream", h.net, h.transport, ":", err)
	} else {
		fmt.Println("\n\r1->",h.net,h.transport)


		firstline := fmt.Sprintf("%s %s %s",req.Method, req.RequestURI, req.Proto)

		id := InsertRequestData(db,&RequestTable{FirstLine:firstline,
			  Host:req.Host,
			  RequestURI:req.RequestURI,
			  SrcIp:sip,SrcPort:sport,
			  DstIp:dip,DstPort:dport})

		h.id = id

		// type 1 is request, 2 is response
		HeaderToDB(req.Header,1,h.id)

		bodyBytes := buf.Buffered() + DiscardBytesToEOF(&readhttp)

		printRequest(req,h,bodyBytes)


	}
}

func HeaderToDB(h http.Header,t uint,id uint){


	for n,v :=range h{
		val := strings.Join(v,", ")

		InsertHeaders(db,n ,val ,t ,id )
	}
}

func printHeader(h http.Header){
	for k,v := range h{
		fmt.Println(k,v)
	}
}

func printRequest(req *http.Request,h *httpStream,bodyBytes int){



	fmt.Println("\n\r\n\r")

	fmt.Println("\n\r")
    fmt.Println(req.Host)
	fmt.Println(req.Method, req.RequestURI, req.Proto)
	printHeader(req.Header)

}

func printResponse(resp *http.Response,h *httpStream){

	fmt.Println("\n\r")
	fmt.Println(resp.Proto, resp.Status)
	printHeader(resp.Header)
}


func isRequest(data []byte) bool {
	buf := bytes.NewBuffer(data)
	reader := bufio.NewReader(buf)
	tp := textproto.NewReader(reader)

	firstLine, _ := tp.ReadLine()
	arr := strings.Split(firstLine, " ")

	switch strings.TrimSpace(arr[0]) {
	case "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT":
		return true
	default:
		return false
	}
}

func  isResponse(data []byte) bool {
	buf := bytes.NewBuffer(data)
	reader := bufio.NewReader(buf)
	tp := textproto.NewReader(reader)

	firstLine, _ := tp.ReadLine()
	return strings.HasPrefix(strings.TrimSpace(firstLine), "HTTP/")
}
