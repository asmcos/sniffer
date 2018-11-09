/*
 * http header,
 * request,
 * response
 */

package main

import (
	"bufio"

	"io"
	"log"
	"net/http"

	"fmt"

	"github.com/google/gopacket"

	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)


// Build a simple HTTP request parser using tcpassembly.StreamFactory and tcpassembly.Stream interfaces

// httpStreamFactory implements tcpassembly.StreamFactory
type httpStreamFactory struct{}

// httpStream will handle the actual decoding of http requests.
type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
}

func (h *httpStreamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	hstream := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
	}


	src,dst := transport.Endpoints()
	if fmt.Sprintf("%v",src) == "80"{
		go hstream.runResponse() // Important... we must guarantee that data from the reader stream is read.
	} else
	if fmt.Sprintf("%v",dst) == "80"{
		go hstream.runRequest() // Important... we must guarantee that data from the reader stream is read.
	} else
	if fmt.Sprintf("%v",dst) == "443" {
		go hstream.runRequests()
	} else {
		go hstream.run()
	}

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.r
}

func (h * httpStream) runRequests(){
	reader := bufio.NewReader(&h.r)

	defer tcpreader.DiscardBytesToEOF(reader)

	log.Println(h.net, h.transport)

	for {
		data := make([]byte,1600)
		n,err := reader.Read(data)
		if err == io.EOF{
			return
		}
		log.Printf("[% x]",data[:n])
	}
}

func (h *httpStream) run(){
	reader := bufio.NewReader(&h.r)
	defer tcpreader.DiscardBytesToEOF(reader)

	log.Println(h.net, h.transport)
	for {
		data := make([]byte,1600)
		n,err := reader.Read(data)
		if err == io.EOF{
			return
		}
		log.Printf("[% x]",data[:n])
	}

}

func (h *httpStream) runResponse() {

	buf := bufio.NewReader(&h.r)
	defer tcpreader.DiscardBytesToEOF(buf)
	for {
		resp, err := http.ReadResponse(buf,nil)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			// We must read until we see an EOF... very important!
			return
		} else if err != nil {
			log.Println("Error reading stream", h.net, h.transport, ":", err)
			return
		} else {
			bodyBytes := tcpreader.DiscardBytesToEOF(resp.Body)
			resp.Body.Close()
			printResponse(resp,h,bodyBytes)
			// log.Println("Received response from stream", h.net, h.transport, ":", resp, "with", bodyBytes, "bytes in response body")
		}
	}
}
func (h *httpStream) runRequest() {

	buf := bufio.NewReader(&h.r)
	defer tcpreader.DiscardBytesToEOF(buf)
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
			// log.Println("Received request from stream", h.net, h.transport, ":", req, "with", bodyBytes, "bytes in request body")
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
	fmt.Println(h.net,h.transport)
	fmt.Println("\n\r")
	fmt.Println(req.Method, req.RequestURI, req.Proto)
	printHeader(req.Header)

}

func printResponse(resp *http.Response,h *httpStream,bodyBytes int){

	fmt.Println("\n\r")
	fmt.Println(resp.Proto, resp.Status)
	printHeader(resp.Header)
}
