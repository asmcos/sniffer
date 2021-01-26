/* http: layers for gopacket,http layer only support request header And response header
 * Author: asmcos
 * Date: 2021-01-25
 */

package main

import (
	"bytes"
	_"encoding/binary"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"strings"
	"bufio"
	"net/textproto"
	"net/http"
	_"net/url"
	_"sync"
	_"io"
)


type HTTP struct {
	layers.BaseLayer
	HasHTTPHeader bool
}

//https://github.com/google/gopacket/blob/master/layers/layertypes.go
var LayerTypeHTTP = gopacket.RegisterLayerType(1000, gopacket.LayerTypeMetadata{
	Name: "HTTP", Decoder: gopacket.DecodeFunc(decodeHTTP),
})


func (h *HTTP) LayerType() gopacket.LayerType { return LayerTypeHTTP }




var GENERAL_HEADERS []string = []string{
    "Cache-Control",
    "Connection",
    "Permanent",
    "Content-Length",
    "Content-MD5",
    "Content-Type",
    "Date",
    "Keep-Alive",
    "Pragma",
    "Upgrade",
    "Via",
    "Warning"}


var COMMON_UNSTANDARD_GENERAL_HEADERS []string=[]string {
    "X-Request-ID",
    "X-Correlation-ID"}

var REQUEST_HEADERS[]string = []string{
    "A-IM",
    "Accept",
    "Accept-Charset",
    "Accept-Encoding",
    "Accept-Language",
    "Accept-Datetime",
    "Access-Control-Request-Method",
    "Access-Control-Request-Headers",
    "Authorization",
    "Cookie",
    "Expect",
    "Forwarded",
    "From",
    "Host",
    "HTTP2-Settings",
    "If-Match",
    "If-Modified-Since",
    "If-None-Match",
    "If-Range",
    "If-Unmodified-Since",
    "Max-Forwards",
    "Origin",
    "Proxy-Authorization",
    "Range",
    "Referer",
    "TE",
    "User-Agent"}

var COMMON_UNSTANDARD_REQUEST_HEADERS []string=[]string{
    "Upgrade-Insecure-Requests",
    "X-Requested-With",
    "DNT",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Forwarded-Proto",
    "Front-End-Https",
    "X-Http-Method-Override",
    "X-ATT-DeviceId",
    "X-Wap-Profile",
    "Proxy-Connection",
    "X-UIDH",
    "X-Csrf-Token",
    "Save-Data"}

var RESPONSE_HEADERS []string=[]string{
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Credentials",
    "Access-Control-Expose-Headers",
    "Access-Control-Max-Age",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers",
    "Accept-Patch",
    "Accept-Ranges",
    "Age",
    "Allow",
    "Alt-Svc",
    "Content-Disposition",
    "Content-Encoding",
    "Content-Language",
    "Content-Location",
    "Content-Range",
    "Delta-Base",
    "ETag",
    "Expires",
    "IM",
    "Last-Modified",
    "Link",
    "Location",
    "P3P",
    "Proxy-Authenticate",
    "Public-Key-Pins",
    "Retry-After",
    "Server",
    "Set-Cookie",
    "Strict-Transport-Security",
    "Trailer",
    "Transfer-Encoding",
    "Tk",
    "Vary",
    "WWW-Authenticate",
    "X-Frame-Options"}

var COMMON_UNSTANDARD_RESPONSE_HEADERS []string=[]string{
    "Content-Security-Policy",
    "X-Content-Security-Policy",
    "X-WebKit-CSP",
    "Refresh",
    "Status",
    "Timing-Allow-Origin",
    "X-Content-Duration",
    "X-Content-Type-Options",
    "X-Powered-By",
    "X-UA-Compatible",
    "X-XSS-Protection"}
/*****************************************
 request
*****************************************/

func readRequest(data []byte ) (req *http.Request, err error) {

	buf := bytes.NewBuffer(data)
    b := bufio.NewReader(buf)

	req, err = http.ReadRequest(b)

	return req, nil
}

func readResponse(data []byte ) (resp *http.Response, err error) {

	buf := bytes.NewBuffer(data)
    b := bufio.NewReader(buf)

	resp, err = http.ReadResponse(b,new(http.Request))

	return resp, nil
}



/*****************************************
 request  end
*****************************************/
func isRequest(firstLine string) bool{
    arr := strings.Split(firstLine, " ")

    switch strings.TrimSpace(arr[0]) {
    case "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT":
        return true
    default:
        return false
    }

}

func  isResponse(firstLine string)  bool{

    if (strings.HasPrefix(strings.TrimSpace(firstLine), "HTTP/")){
		return  true
    }
	return false
}

//http body
func (h *HTTP) Payload() []byte {

	return nil
}

func (h *HTTP) CanDecode() gopacket.LayerClass {
	return LayerTypeHTTP
}

// NextLayerType returns gopacket.LayerTypePayload.
func (h *HTTP) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}


func (h *HTTP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {

	buf := bytes.NewBuffer(data)
    reader := bufio.NewReader(buf)
    tp := textproto.NewReader(reader)

    firstLine, _ := tp.ReadLine()

	if (isRequest(firstLine)){

		req,err := readRequest(data)
		fmt.Println(req,err)

		h.HasHTTPHeader = true
		return nil

	} else if(isResponse(firstLine)){

		resp,err := readResponse(data)
		fmt.Println(resp,err)
		h.HasHTTPHeader = true
		return nil
	} else {
		return fmt.Errorf("Invalid HTTP data")
	}

}

func decodeHTTP(data []byte, p gopacket.PacketBuilder) error {
	h := new(HTTP)

	err := h.DecodeFromBytes(data, p)

	p.AddLayer(h)
	p.SetApplicationLayer(h)

	// have error
	if err != nil {
		return err
	}

	return p.NextDecoder(gopacket.LayerTypePayload)
}
