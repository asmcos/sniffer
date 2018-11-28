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
	"strconv"
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


func (h *httpStream) runResponse(buf * bufio.Reader) {

	fmt.Println("\n\r2->",h.net,h.transport)

	sip,dip,sport,dport := h.GetIpPort()

	req := FindRequest(db,sip,sport,dip,dport)

	id := InsertResponseData(db,&ResponseTable{
      SrcIp:sip,SrcPort:sport,
      DstIp:dip,DstPort:dport},&req)
	h.id = id

	for {
		resp, err := ReadResponse(buf)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading stream", h.net, h.transport, ":", err)
			return
		} else {
			firstline := fmt.Sprintf("%s %s",resp.Proto, resp.Status)
			UpdateResponseData(db,&ResponseTable{FirstLine:firstline,
				StatusCode:resp.StatusCode},&req,h.id)

			// type 1 is request, 2 is response
			HeaderToDB(resp.Header,2,h.id)

			printResponse(resp,h)
			tcpreader.DiscardBytesToEOF(buf)

		}
	}
}
func (h *httpStream) runRequest(buf *bufio.Reader) {


	sip,dip,sport,dport := h.GetIpPort()

	id :=InsertRequestData(db,&RequestTable{
	      SrcIp:sip,SrcPort:sport,
	      DstIp:dip,DstPort:dport})

	h.id = id

	for {
		req, err := http.ReadRequest(buf)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading stream", h.net, h.transport, ":", err)
		} else {
			fmt.Println("\n\r1->",h.net,h.transport)

			firstline := fmt.Sprintf("%s %s %s",req.Method, req.RequestURI, req.Proto)

			UpdateRequestData(db,&RequestTable{FirstLine:firstline,
				  Host:req.Host,
				  RequestURI:req.RequestURI,
			      SrcIp:sip,SrcPort:sport,
			      DstIp:dip,DstPort:dport},h.id)

			// type 1 is request, 2 is response
			HeaderToDB(req.Header,1,h.id)

			bodyBytes := tcpreader.DiscardBytesToEOF(req.Body)
			//tcpreader.DiscardBytesToEOF(req.Body)
			req.Body.Close()
			printRequest(req,h,bodyBytes)



		}
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


/****** code from net /http / response.go ******/

func ReadResponse(r *bufio.Reader) (*http.Response, error) {
	tp := textproto.NewReader(r)
	resp := &http.Response{
	}

	// Parse the first line of the response.
	line, err := tp.ReadLine()
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	if i := strings.IndexByte(line, ' '); i == -1 {
		return nil, &badStringError{"malformed HTTP response", line}
	} else {
		resp.Proto = line[:i]
		resp.Status = strings.TrimLeft(line[i+1:], " ")
	}
	statusCode := resp.Status
	if i := strings.IndexByte(resp.Status, ' '); i != -1 {
		statusCode = resp.Status[:i]
	}
	if len(statusCode) != 3 {
		return nil, &badStringError{"malformed HTTP status code", statusCode}
	}
	resp.StatusCode, err = strconv.Atoi(statusCode)
	if err != nil || resp.StatusCode < 0 {
		return nil, &badStringError{"malformed HTTP status code", statusCode}
	}
	var ok bool
	if resp.ProtoMajor, resp.ProtoMinor, ok = http.ParseHTTPVersion(resp.Proto); !ok {
		return nil, &badStringError{"malformed HTTP version", resp.Proto}
	}

	// Parse the response headers.
	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	resp.Header = http.Header(mimeHeader)

	fixPragmaCacheControl(resp.Header)

	return resp, nil
}

// RFC 7234, section 5.4: Should treat
//	Pragma: no-cache
// like
//	Cache-Control: no-cache
func fixPragmaCacheControl(header http.Header) {
	if hp, ok := header["Pragma"]; ok && len(hp) > 0 && hp[0] == "no-cache" {
		if _, presentcc := header["Cache-Control"]; !presentcc {
			header["Cache-Control"] = []string{"no-cache"}
		}
	}
}
// from net/http/request.go
type badStringError struct {
	what string
	str  string
}

func (e *badStringError) Error() string { return fmt.Sprintf("%s %q", e.what, e.str) }
