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


/*****************************************
 request
*****************************************/

const (
	defaultMaxMemory = 32 << 20 // 32 MB
)

func readRequest(data []byte ) (req *http.Request, err error) {

	buf := bytes.NewBuffer(data)
    b := bufio.NewReader(buf)

	req, err = http.ReadRequest(b)

	req.ParseMultipartForm(defaultMaxMemory)

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

		req,_ := readRequest(data)


		fmt.Println(req,req.Body)

		h.HasHTTPHeader = true
		return nil

	} else if(isResponse(firstLine)){

		resp,_ := readResponse(data)
		fmt.Println(resp)
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
