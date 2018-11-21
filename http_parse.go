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
	"bytes"
	"strings"
	"io/ioutil"
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

      buf := bufio.NewReader(&h.r)
	  defer tcpreader.DiscardBytesToEOF(buf)

      data,err := buf.Peek(10)

	  if err !=nil{
		return
	  }

      if isRequest(data){
        h.runRequest(buf)
      }

      if isResponse(data){
        h.runResponse(buf)
      }


}

func ReadAll(resp *http.Response) []byte {

    defer resp.Body.Close()

    var Body = resp.Body

    content, err := ioutil.ReadAll(Body)
    if err != nil {
        return nil
    }

    return content
}

func (h *httpStream) runResponse(buf * bufio.Reader) {


	for {
		resp, err := http.ReadResponse(buf,nil)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading stream", h.net, h.transport, ":", err)
			return
		} else {
			bodyBytes := ReadAll(resp)
			printResponse(resp,h,bodyBytes)
		}
	}
}
func (h *httpStream) runRequest(buf *bufio.Reader) {

	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading stream", h.net, h.transport, ":", err)
		} else {
			bodyBytes := tcpreader.DiscardBytesToEOF(req.Body)
			req.Body.Close()
			printRequest(req,h,bodyBytes)

		}
	}
}

func printHeader(h http.Header){
	for k,v := range h{
		fmt.Println(k,v)
	}
}

func printRequest(req *http.Request,h *httpStream,bodyBytes int){

	fmt.Println("\n\r\n\r")

    sip,dip,sport,dport := h.GetIpPort()

    InsertData(db,&RequestTable{RequestURI:req.RequestURI,
      Host:req.Host,
      SrcIp:sip,SrcPort:sport,
      DstIp:dip,DstPort:dport})

	fmt.Println(h.net,h.transport)

	fmt.Println("\n\r")
    fmt.Println(req.Host)
	fmt.Println(req.Method, req.RequestURI, req.Proto)
	printHeader(req.Header)

}

func printResponse(resp *http.Response,h *httpStream,bodyBytes []byte){

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
