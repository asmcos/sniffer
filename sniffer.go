// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// The pcapdump binary implements a tcpdump-like command line tool with gopacket
// using pcap as a backend data collection mechanism.
// 
// Use tcpassembly.go in the gpacket reassembly directory instead of the tcpassembly directory.
// HTTP protocol analysis, the request and response start flags need to be detected to prevent packet leakage.
// Author: asmcos
// Date: 2018
//
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"net/textproto"
	"os"
	"os/signal"
	"runtime/pprof"
	"strings"
	"sync"
	"time"
	"encoding/json"

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers" // pulls in all layers decoders
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/reassembly"

    "github.com/asmcos/requests"

    //_ "net/http/pprof"
)

var maxcount = flag.Int("c", -1, "Only grab this many packets, then exit")
var statsevery = flag.Int("stats", 1000, "Output statistics every N packets")
var lazy = flag.Bool("lazy", false, "If true, do lazy decoding")
var nodefrag = flag.Bool("nodefrag", false, "If true, do not do IPv4 defrag")
var checksum = flag.Bool("checksum", false, "Check TCP checksum")
var nooptcheck = flag.Bool("nooptcheck", false, "Do not check TCP options (useful to ignore MSS on captures with TSO)")
var ignorefsmerr = flag.Bool("ignorefsmerr", false, "Ignore TCP FSM errors")
var allowmissinginit = flag.Bool("allowmissinginit", true, "Support streams without SYN/SYN+ACK/ACK sequence")
var verbose = flag.Bool("verbose", false, "Be verbose")
var debug = flag.Bool("debug", false, "Display debug information")
var quiet = flag.Bool("quiet", false, "Be quiet regarding errors")

// http
var nohttp = flag.Bool("nohttp", false, "Disable HTTP parsing")
var output = flag.String("output", "", "Path to create file for HTTP 200 OK responses")
var writeincomplete = flag.Bool("writeincomplete", false, "Write incomplete response")

var hexdump = flag.Bool("dump", false, "Dump HTTP request/response as hex")
var hexdumppkt = flag.Bool("dumppkt", false, "Dump packet as hex")

var djslen = flag.Int("dumpjs",0,"Display response javascript format length")
var dhtmllen = flag.Int("dumphtml",0,"Display response html format length")

var danystr = flag.String("dumpanystr","text/plain","Display response ContentType,e.g. text/html")
var danylen = flag.Int("dumpanylen",0,"Display response dumpanystr format length")

// capture
var iface = flag.String("i", "eth0", "Interface to read packets from")
var port = flag.Int("p", 80, "Interface to read packets from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")
var snaplen = flag.Int("s", 65536, "Snap length (number of bytes max to read per packet")
var tstype = flag.String("timestamp_type", "", "Type of timestamps to use")
var promisc = flag.Bool("promisc", true, "Set promiscuous mode")

var memprofile = flag.String("memprofile", "", "Write memory profile")
var serverurl = flag.String("serverurl", "", "save data to remote server: http://www.cpython.org/httpdata/")

var signalChan chan os.Signal
var sysexit bool = false

const (
	defaultMaxMemory = 32 << 20 // 32 MB
)

//var db *gorm.DB

// t is type 1:request,2:response
func HeaderToDB(session * requests.Request,h http.Header,t string,pid string) ([]requests.Datas){

    var d []requests.Datas

    for n,v :=range h{
        val := strings.Join(v,", ")

        d = append(d,requests.Datas{"type":t,
        "parentid":pid,
        "name":n,
        "values":val,
        })
    }
    return d
}

func FormToDB(session *requests.Request,val url.Values,t string,pid string)([]requests.Datas){


    var d []requests.Datas
    for n,v :=range val{
        content := strings.Join(v,", ")

        d = append(d,requests.Datas{"type":t,
        "parentid":pid,
        "name":n,
        "values":content,
        })
    }
    return d
}


var stats struct {
	ipdefrag            int
	missedBytes         int
	pkt                 int
	sz                  int
	totalsz             int
	rejectFsm           int
	rejectOpt           int
	rejectConnFsm       int
	reassembled         int
	outOfOrderBytes     int
	outOfOrderPackets   int
	biggestChunkBytes   int
	biggestChunkPackets int
	overlapBytes        int
	overlapPackets      int
}

//const closeTimeout time.Duration = time.Hour * 24 // Closing inactive: TODO: from CLI
const closeTimeout time.Duration = time.Minute * 5 // Closing inactive: TODO: from CLI
const timeout time.Duration = time.Minute * 3     // Pending bytes: TODO: from CLI

/*
 * HTTP part
 */

type httpGroup struct {
    req          *http.Request
    reqFirstLine string
    reqTimeStamp int64
    reqFlag      int //0=new,1=found,2=finish

    resp          *http.Response
    respFirstLine string
    respTimeStamp int64
    respFlag      int //0=new,1=found,2=finish
}


type httpReader struct {
	ident     string
	isClient  bool
	bytes     chan []byte
    timeStamp chan int64
	data      []byte
	hexdump   bool
	parent    *tcpStream
	logbuf    string
	srcip     string
	dstip     string
	srcport   string
	dstport   string
    httpstart int // 0 = new,1=find, 2 = old and find new
}

func (h *httpReader) Read(p []byte) (int, error) {
	ok := true
	for ok && len(h.data) == 0 {
		h.data, ok = <-h.bytes
	}
	if !ok || len(h.data) == 0 {
		return 0, io.EOF
	}

    ishttp,_ := detectHttp(h.data)

    if ishttp {
        switch h.httpstart {
            case 0: // run read,only copy 
                h.httpstart = 1
	            l := copy(p, h.data)
                return l,nil

            case 1: //http read
                h.httpstart = 2
	            l := copy(p, h.data)
	            h.data = h.data[l:]
	            return l, nil

            case 2: //http read
                h.httpstart = 0
		        return 0, io.EOF
        }
    }


	l := copy(p, h.data)
	h.data = h.data[l:]
	return l, nil
}

func (h *httpReader) Print() {

	fmt.Println(h.logbuf)

}

var outputLevel int
var errorsMap map[string]uint
var errorsMapMutex sync.Mutex
var errors uint

// Too bad for perf that a... is evaluated
func Error(t string, s string, a ...interface{}) {
	errorsMapMutex.Lock()
	errors++
	nb, _ := errorsMap[t]
	errorsMap[t] = nb + 1
	errorsMapMutex.Unlock()
	if outputLevel >= 0 {
		fmt.Printf(s, a...)
	}
}
func Info(s string, a ...interface{}) {
	if outputLevel >= 1 {
		fmt.Printf(s, a...)
	}
}
func Debug(s string, a ...interface{}) {
	if outputLevel >= 2 {
		fmt.Printf(s, a...)
	}
}


func printHeader(h http.Header)string{
	var logbuf string

    for k,v := range h{
        logbuf += fmt.Sprintf("%s :%s\n",k,v)
    }
	return logbuf
}

// url.Values map[string][]string

func printForm(v url.Values)string{
    var logbuf string

    logbuf += fmt.Sprint("\n**************\n")
    for k,data := range v{
        logbuf += fmt.Sprint(k,":")
        for _,d := range data{
            logbuf += fmt.Sprintf("%s",d)
        }
        logbuf += "\n"
    }
    logbuf += fmt.Sprint("**************\n")

    return logbuf
}

func printRequest(req *http.Request)string{

    logbuf := fmt.Sprintf("\n")
    logbuf += fmt.Sprintf("%s\n",req.Host)
    logbuf += fmt.Sprintf("%s %s %s \n",req.Method, req.RequestURI, req.Proto)
    logbuf += printHeader(req.Header)
    logbuf += printForm(req.Form)
    logbuf += printForm(req.PostForm)
    if req.MultipartForm != nil {
        logbuf += printForm(url.Values(req.MultipartForm.Value))
    }
    logbuf += fmt.Sprintf("\n")
	return logbuf
}

func printResponse(resp *http.Response)string{

    logbuf := fmt.Sprintf("\n")
    logbuf += fmt.Sprintf("%s %s\n",resp.Proto, resp.Status)
    logbuf += printHeader(resp.Header)
    logbuf += fmt.Sprintf("\n")
	return logbuf
}

// detect http infomation
// isRequest isResponse

func isRequest(data []byte) (bool,string) {
    buf := bytes.NewBuffer(data)
    reader := bufio.NewReader(buf)
    tp := textproto.NewReader(reader)

    firstLine, _ := tp.ReadLine()
    arr := strings.Split(firstLine, " ")

    switch strings.TrimSpace(arr[0]) {
    case "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT":
        return true,firstLine
    default:
        return false,firstLine
    }
}


//server to client
func  isResponse(data []byte) (bool,string) {
    buf := bytes.NewBuffer(data)
    reader := bufio.NewReader(buf)
    tp := textproto.NewReader(reader)

    firstLine, _:= tp.ReadLine()
    return strings.HasPrefix(strings.TrimSpace(firstLine), "HTTP/"),firstLine
}


// 0 = response
// 1 = request

func detectHttp(data []byte) (bool ,int){

	ishttp,_ := isResponse(data)
	if ishttp{
		return true,0
	}

	ishttp,_ = isRequest(data)
	if ishttp{
		return true,1 //request
	}

	return false,2
}



func (h *httpReader) DecompressBody(header http.Header, reader io.ReadCloser) (io.ReadCloser, bool) {
	contentEncoding := header.Get("Content-Encoding")
	var nr io.ReadCloser
	var err error
	if contentEncoding == "" {
		// do nothing
		return reader, false
	} else if strings.Contains(contentEncoding, "gzip") {
		nr, err = gzip.NewReader(reader)
		if err != nil {
			return reader, false
		}
		return nr, true
	} else if strings.Contains(contentEncoding, "deflate") {
		nr, err = zlib.NewReader(reader)
		if err != nil {
			return reader, false
		}
		return nr, true
	} else {
		return reader, false
	}
}






func (h * httpReader) HandleRequest (timeStamp int64,firstline string) {

	b := bufio.NewReader(h)

    req, err := http.ReadRequest(b)
    h.parent.UpdateReq(req,timeStamp,firstline)

    if err == io.EOF || err == io.ErrUnexpectedEOF {
        return
    } else if err != nil {
        Error("HTTP-request", "HTTP Request error: %s (%v,%+v)\n", err, err, err)

    } else {

	    req.ParseMultipartForm(defaultMaxMemory)

        r,ok := h.DecompressBody(req.Header,req.Body)
		if ok {
			defer r.Close()
		}
		contentType := req.Header.Get("Content-Type")
		logbuf := fmt.Sprintf("%v->%v:%v->%v\n",h.srcip,h.dstip,h.srcport,h.dstport)
		logbuf += printRequest(req)

		if strings.Contains(contentType,"application/json"){

			bodydata, err := ioutil.ReadAll(r)
			if err == nil {
				var jsonValue interface{}
				err = json.Unmarshal([]byte(bodydata), &jsonValue)
				if err == nil {
					logbuf += fmt.Sprintf("%#v\n",jsonValue)
				}
			}
		}

	   fmt.Printf("%s",logbuf)
	}

}

func (h *httpReader) runClient(wg *sync.WaitGroup) {
	defer wg.Done()

	var p  = make([]byte,1900)

	for {

        h.httpstart = 0
		l,err := h.Read(p)
		if (err == io.EOF){
			return
		}
		if( l > 8 ){
			isReq,firstLine := isRequest(p)
			if(isReq){ //start new request
                timeStamp := <-h.timeStamp

			    h.HandleRequest(timeStamp,firstLine)
		    }
        }
	}

}

func (h * httpReader) HandleResponse (timeStamp int64,firstline string) {


    b := bufio.NewReader(h)

    resp, err := http.ReadResponse(b, nil)
    h.parent.UpdateResp(resp,timeStamp,firstline)

    if err == io.EOF || err == io.ErrUnexpectedEOF {
        return
    } else if err != nil {
        Error("HTTP-reponse", "HTTP Response error: %s (%v,%+v)\n", err, err, err)

    } else {

        r,ok := h.DecompressBody(resp.Header,resp.Body)
		if ok {
			defer r.Close()
		}
		contentType := resp.Header.Get("Content-Type")
		logbuf := fmt.Sprintf("%v->%v:%v->%v\n",h.srcip,h.dstip,h.srcport,h.dstport)
		logbuf += printResponse(resp)

		if strings.Contains(contentType,"application/json"){

			bodydata, err := ioutil.ReadAll(r)
			if err == nil {
				var jsonValue interface{}
				err = json.Unmarshal([]byte(bodydata), &jsonValue)
				if err == nil {
					logbuf += fmt.Sprintf("%#v\n",jsonValue)
				}
			}
		} else if strings.Contains(contentType,"application/javascript"){
            bodydata, err := ioutil.ReadAll(r)
            bodylen := len(bodydata)

            if bodylen < *djslen{
                *djslen = bodylen
            }
            if err == nil {

                logbuf += fmt.Sprintf("%s\n",string(bodydata[:*djslen]))
            }
		} else if strings.Contains(contentType,"text/html"){
            bodydata, err := ioutil.ReadAll(r)
            bodylen := len(bodydata)

            if bodylen < *dhtmllen{
                *dhtmllen = bodylen
            }
            if err == nil {

                logbuf += fmt.Sprintf("%s\n",string(bodydata[:*dhtmllen]))
            }
		} else if strings.Contains(contentType,*danystr){ //default text/plain
            bodydata, err := ioutil.ReadAll(r)
            bodylen := len(bodydata)

            if bodylen < *danylen{
                *danylen = bodylen
            }
            if err == nil {

                logbuf += fmt.Sprintf("%s\n",string(bodydata[:*danylen]))
            }
        }



	   fmt.Printf("%s",logbuf)
	}


}



// response
func (h *httpReader) runServer(wg *sync.WaitGroup) {
    defer wg.Done()

	var p  = make([]byte,1900)

    for {
        h.httpstart = 0
        l,err := h.Read(p)
        if (err == io.EOF){
            return
        }
        if( l > 8 ){
            isResp,firstLine := isResponse(p)
            if(isResp){ //start new response
                timeStamp := <-h.timeStamp

                h.HandleResponse(timeStamp,firstLine)

            }
        }
    }



}



/*
 * The TCP factory: returns a new Stream
 */
type tcpStreamFactory struct {
	wg     sync.WaitGroup
	doHTTP bool
}

func (factory *tcpStreamFactory) New(net, transport gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	Debug("* NEW: %s %s\n", net, transport)
	sip,dip := net.Endpoints()
	srcip := fmt.Sprintf("%s",sip)
	dstip := fmt.Sprintf("%s",dip)

	fsmOptions := reassembly.TCPSimpleFSMOptions{
		SupportMissingEstablishment: *allowmissinginit,
	}
	stream := &tcpStream{
		net:        net,
		transport:  transport,
		isHTTP:     (tcp.SrcPort == layers.TCPPort(*port) || tcp.DstPort == layers.TCPPort(*port)) && factory.doHTTP,
		reversed:   tcp.SrcPort == layers.TCPPort(*port),
		tcpstate:   reassembly.NewTCPSimpleFSM(fsmOptions),
		ident:      fmt.Sprintf("%s:%s", net, transport),
		optchecker: reassembly.NewTCPOptionCheck(),
	}
	if stream.isHTTP {
		stream.client = httpReader{
			bytes:    make(chan []byte),
			timeStamp:   make(chan int64),
			ident:    fmt.Sprintf("%s %s", net, transport),
			hexdump:  *hexdump,
			parent:   stream,
			isClient: true,
			srcport: fmt.Sprintf("%d",tcp.SrcPort),
			dstport: fmt.Sprintf("%d",tcp.DstPort),
			srcip: srcip,
			dstip: dstip,
            httpstart:0,
		}
		stream.server = httpReader{
			bytes:   make(chan []byte),
			timeStamp:   make(chan int64),
			ident:   fmt.Sprintf("%s %s", net.Reverse(), transport.Reverse()),
			hexdump: *hexdump,
			parent:  stream,
			dstport: fmt.Sprintf("%d",tcp.SrcPort),
			srcport: fmt.Sprintf("%d",tcp.DstPort),
			dstip: srcip,
			srcip: dstip,
            httpstart:0,
		}
		factory.wg.Add(2)
		go stream.client.runClient(&factory.wg)
		go stream.server.runServer(&factory.wg)
	}
	return stream
}

func (factory *tcpStreamFactory) WaitGoRoutines() {
	factory.wg.Wait()
}

/*
 * The assembler context
 */
type Context struct {
	CaptureInfo gopacket.CaptureInfo
}

func (c *Context) GetCaptureInfo() gopacket.CaptureInfo {
	return c.CaptureInfo
}

/*
 * TCP stream
 */

/* It's a connection (bidirectional) */
type tcpStream struct {
	tcpstate       *reassembly.TCPSimpleFSM
	fsmerr         bool
	optchecker     reassembly.TCPOptionCheck
	net, transport gopacket.Flow
	isHTTP         bool
	reversed       bool
	client         httpReader
	server         httpReader
	urls           []string
	ident          string
    all            []httpGroup
    hg             sync.Mutex
	sync.Mutex
}

//req = 1 is request
//req = 0 is response

func (t * tcpStream) NewhttpGroup(req int,timestamp int64) {

    t.hg.Lock()
    for _, hg := range  t.all {
           //exist same req
            if hg.reqTimeStamp == timestamp||hg.respTimeStamp == timestamp{
                fmt.Println("Have same ",req,timestamp)
                t.hg.Unlock()
                return
            }

    }

    if req == 1 {
        //try find response 
        for i, hg := range  t.all {
            if hg.respFlag > 0 && hg.reqFlag == 0{
                t.all[i].respFlag = 1
                t.all[i].respTimeStamp = timestamp
                t.hg.Unlock()
                return
            }
        }

        hg := httpGroup{
            reqFlag : 1,
            reqTimeStamp : timestamp,
            respFlag : 0,
        }
        t.all = append(t.all,hg)
        t.hg.Unlock()

    } else {
        //try find request
        for i, hg := range  t.all {
            if hg.reqFlag > 0 && hg.respFlag == 0{
                t.all[i].respFlag = 1
                t.all[i].respTimeStamp = timestamp
                t.hg.Unlock()
                return
            }
        }
        hg := httpGroup{
            respFlag :1,
            respTimeStamp :timestamp,
            reqFlag :0,
        }
        t.all = append(t.all,hg)
        t.hg.Unlock()
    }

}

func (t * tcpStream) UpdateReq(req * http.Request,timestamp int64,firstLine string) {

    t.hg.Lock()
    for i, hg := range  t.all {
         if hg.reqTimeStamp == timestamp {
                t.all[i].req = req
                t.all[i].reqFlag = 2
                t.all[i].reqFirstLine = firstLine
                if hg.respFlag == 2{
                    t.Save(&t.all[i])
                    if i < len(t.all){
                        t.all = append(t.all[:i],t.all[i+1:]...)
                    } else {
                        t.all = t.all[:i]
                    }
                }
         } //if timestramp

    }//for

    t.hg.Unlock()
}

func (t * tcpStream) UpdateResp(resp * http.Response,timestamp int64,firstLine string) {


    t.hg.Lock()
    for i, hg := range  t.all {
         if hg.respTimeStamp == timestamp {
                t.all[i].resp = resp
                t.all[i].respFlag = 2
                t.all[i].respFirstLine = firstLine
                if hg.reqFlag == 2{
                    t.Save(&t.all[i])
                    if i < len(t.all){
                        t.all = append(t.all[:i],t.all[i+1:]...)
                    } else {
                        t.all = t.all[:i]
                    }
                }
         } //if timestramp

    }//for

    t.hg.Unlock()
}


// save to database
func (t * tcpStream)Save(hg * httpGroup){


        req := hg.req
        resp := hg.resp
        if (req == nil || resp == nil || *serverurl==""){
            return
        }

        var h []requests.Datas
        var f []requests.Datas

        data := requests.Datas{
          "Host":req.Host,
          "RequestURI":req.RequestURI,
          "StatusCode":string(resp.StatusCode),
          "SrcIp":t.client.srcip,
          "SrcPort":t.client.srcport,
          "DstIp":t.client.dstip,
          "DstPort":t.client.dstport,
          "HostID":"1"}


        session := requests.Requests()
        ret,err := session.Post(*serverurl+"requests",requests.Header{"Connection": "close"},data)

        if err != nil {
            fmt.Println(err)
            return
        }

        var dataJson map[string]interface{}
        err =  ret.Json(&dataJson)
        if err != nil {
            fmt.Println(err)
            return
        }

        requestid := dataJson["id"]
        reqid := fmt.Sprintf("%.0f",requestid) 

        data = requests.Datas{
              "StatusCode":string(resp.StatusCode),
              "SrcIp":t.server.srcip,
              "SrcPort":t.server.srcport,
              "DstIp":t.server.dstip,
              "DstPort":t.server.dstport,
              "HostID":"1",
              "RequestID":reqid}

        ret,err = session.Post(*serverurl+"responses",data)

        if err != nil {
            fmt.Println(err)
            return
        }

        err =  ret.Json(&dataJson)
        if err != nil {
            fmt.Println(err)
            return
        }

        responseid := dataJson["id"]
        respid := fmt.Sprintf("%.0f",responseid)
        fmt.Println(requestid,responseid)

        h = append(h,HeaderToDB(session,req.Header,"1",reqid)...)

        f = append(f,FormToDB(session,req.Form,"1",reqid)...)
        f = append(f,FormToDB(session,req.PostForm,"1",reqid)...)
        if req.MultipartForm != nil {
            f = append(f,FormToDB(session,url.Values(req.MultipartForm.Value),"1",reqid)...)
        }

        h = append(h,HeaderToDB(session,resp.Header,"2",respid)...)

        if len(h) > 0{
            ret,err = session.PostJson(*serverurl+"headers?array=1",h)
        }
        if len(f) > 0{
            ret,err = session.PostJson(*serverurl+"forms?array=1",f)
        }
        fmt.Println(h,f)

}

func (t *tcpStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	// FSM

    var isReq int

	*start,isReq = detectHttp(tcp.Payload)


	if !t.tcpstate.CheckState(tcp, dir) {
		Error("FSM", "%s: Packet rejected by FSM (state:%s)\n", t.ident, t.tcpstate.String())
		stats.rejectFsm++
		if !t.fsmerr {
			t.fsmerr = true
			stats.rejectConnFsm++
		}
		if !*ignorefsmerr {
			return false
		}
	}
	// Options //skip mss check
	err := t.optchecker.Accept(tcp, ci, dir, nextSeq, start)
	if err != nil {
		// 重复的包，丢弃 drop
        // 调试发现此包为以前序号的包，并且出现过。
		// mss BUG,server mss通过路由拆解成mss要求的包尺寸，
		// 因此不能判断包大小大于mss为错包
		if strings.Contains(fmt.Sprintf("%s",err)," > mss "){
			//  > mss 包 不丢弃
		} else {

			Error("OptionChecker", "%v ->%v : Packet rejected by OptionChecker: %s\n",  t.net, t.transport, err)
			stats.rejectOpt++
			if !*nooptcheck {
				return false
			}
		}
	}

	// Checksum
	accept := true
	if *checksum {
		c, err := tcp.ComputeChecksum()
		if err != nil {
			Error("ChecksumCompute", "%s: Got error computing checksum: %s\n", t.ident, err)
			accept = false
		} else if c != 0x0 {
			Error("Checksum", "%s: Invalid checksum: 0x%x\n", t.ident, c)
			accept = false
		}
	}
	if !accept {
		stats.rejectOpt++
	}

    // create new httpgroup,wait request+response
    if *start {
        t.NewhttpGroup(isReq,ci.Timestamp.UnixNano())
    }

	return accept
}

func (t *tcpStream) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	dir, start, end, skip := sg.Info()
	length, saved := sg.Lengths()

	// update stats
	sgStats := sg.Stats()
	if skip > 0 {
		stats.missedBytes += skip
	}
	stats.sz += length - saved
	stats.pkt += sgStats.Packets
	if sgStats.Chunks > 1 {
		stats.reassembled++
	}
	stats.outOfOrderPackets += sgStats.QueuedPackets
	stats.outOfOrderBytes += sgStats.QueuedBytes
	if length > stats.biggestChunkBytes {
		stats.biggestChunkBytes = length
	}
	if sgStats.Packets > stats.biggestChunkPackets {
		stats.biggestChunkPackets = sgStats.Packets
	}
	if sgStats.OverlapBytes != 0 && sgStats.OverlapPackets == 0 {
		fmt.Printf("bytes:%d, pkts:%d\n", sgStats.OverlapBytes, sgStats.OverlapPackets)
		panic("Invalid overlap")
	}
	stats.overlapBytes += sgStats.OverlapBytes
	stats.overlapPackets += sgStats.OverlapPackets

	var ident string
	if dir == reassembly.TCPDirClientToServer {
		ident = fmt.Sprintf("%v %v(%s): ", t.net, t.transport, dir)
	} else {
		ident = fmt.Sprintf("%v %v(%s): ", t.net.Reverse(), t.transport.Reverse(), dir)
	}
	Debug("%s: SG reassembled packet with %d bytes (start:%v,end:%v,skip:%d,saved:%d,nb:%d,%d,overlap:%d,%d)\n", ident, length, start, end, skip, saved, sgStats.Packets, sgStats.Chunks, sgStats.OverlapBytes, sgStats.OverlapPackets)
	if skip == -1 && *allowmissinginit {
		// this is allowed
	} else if skip != 0 {
		// Missing bytes in stream: do not even try to parse it
		return
	}

    //use timeStamp as match flag
    timeStamp :=sg.CaptureInfo(0).Timestamp.UnixNano()
	data := sg.Fetch(length)
    if t.isHTTP {
		if length > 0 {
			if *hexdump {
				Debug("Feeding http with:\n%s", hex.Dump(data))
			}

            ok,_:=detectHttp(data)

			//if dir == reassembly.TCPDirClientToServer && !t.reversed {
			if dir == reassembly.TCPDirClientToServer {
				t.client.bytes <- data
				if ok {
                    t.client.timeStamp <- timeStamp
                }
			} else {
				t.server.bytes <- data
				if ok {
                    t.server.timeStamp <- timeStamp
                }
			}
		}
	}
}

func (t *tcpStream) ReassemblyComplete(ac reassembly.AssemblerContext) bool {
	Debug("%s: Connection closed\n", t.ident)
	if t.isHTTP {
		close(t.client.bytes)
		close(t.server.bytes)
	}
	// do not remove the connection to allow last ACK
	return false
}

func HandlerSig (){

    for {
        select {
        case <-signalChan:
            fmt.Fprintf(os.Stderr, "\nCaught SIGINT: aborting %v\n",sysexit)
            if sysexit == false{
                sysexit = true
            } else {
                os.Exit(1) //Second ctrl+c system exit
            }
        }
    }
}

func main() {
	defer util.Run()()
	var handle *pcap.Handle
	var err error
	if *debug {
		outputLevel = 2
	} else if *verbose {
		outputLevel = 1
	} else if *quiet {
		outputLevel = -1
	}
	log.SetOutput(os.Stdout)
	errorsMap = make(map[string]uint)

    loadConfig()


	if *fname != "" {
		if handle, err = pcap.OpenOffline(*fname); err != nil {
			log.Fatal("PCAP OpenOffline error:", err)
		}
	} else {
		// This is a little complicated because we want to allow all possible options
		// for creating the packet capture handle... instead of all this you can
		// just call pcap.OpenLive if you want a simple handle.
		inactive, err := pcap.NewInactiveHandle(*iface)
		if err != nil {
			log.Fatalf("could not create: %v", err)
		}
		defer inactive.CleanUp()
		if err = inactive.SetSnapLen(*snaplen); err != nil {
			log.Fatalf("could not set snap length: %v", err)
		} else if err = inactive.SetPromisc(*promisc); err != nil {
			log.Fatalf("could not set promisc mode: %v", err)
		} else if err = inactive.SetTimeout(time.Second); err != nil {
			log.Fatalf("could not set timeout: %v", err)
		}
		if *tstype != "" {
			if t, err := pcap.TimestampSourceFromString(*tstype); err != nil {
				log.Fatalf("Supported timestamp types: %v", inactive.SupportedTimestamps())
			} else if err := inactive.SetTimestampSource(t); err != nil {
				log.Fatalf("Supported timestamp types: %v", inactive.SupportedTimestamps())
			}
		}
		if handle, err = inactive.Activate(); err != nil {
			log.Fatal("PCAP Activate error:", err)
		}
		defer handle.Close()
	}
	if len(flag.Args()) > 0 {
		bpffilter := strings.Join(flag.Args(), " ")
		Info("Using BPF filter %q\n", bpffilter)
		if err = handle.SetBPFFilter(bpffilter); err != nil {
			log.Fatal("BPF filter error:", err)
		}
	} else {

		bpffilter := fmt.Sprintf("tcp and port %d",*port)
		if err = handle.SetBPFFilter(bpffilter); err != nil {
            log.Fatal("BPF filter error:", err)
        }

	}

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	source.Lazy = *lazy
	source.NoCopy = true
	Info("Starting to read packets\n")
	count := 0
	bytes := int64(0)
	start := time.Now()
	defragger := ip4defrag.NewIPv4Defragmenter()

	streamFactory := &tcpStreamFactory{doHTTP: !*nohttp}
	streamPool := reassembly.NewStreamPool(streamFactory)
	assembler := reassembly.NewAssembler(streamPool)

	signalChan = make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
    go HandlerSig()

	for packet := range source.Packets() {
		count++
		Debug("PACKET #%d\n", count)
		data := packet.Data()
		bytes += int64(len(data))
		if *hexdumppkt {
			Debug("Packet content (%d/0x%x)\n%s\n", len(data), len(data), hex.Dump(data))
		}

		// defrag the IPv4 packet if required
		if !*nodefrag {
			ip4Layer := packet.Layer(layers.LayerTypeIPv4)
			if ip4Layer == nil {
				continue
			}
			ip4 := ip4Layer.(*layers.IPv4)
			l := ip4.Length
			newip4, err := defragger.DefragIPv4(ip4)
			if err != nil {
				log.Fatalln("Error while de-fragmenting", err)
			} else if newip4 == nil {
				Debug("Fragment...\n")
				continue // packet fragment, we don't have whole packet yet.
			}
			if newip4.Length != l {
				stats.ipdefrag++
				Debug("Decoding re-assembled packet: %s\n", newip4.NextLayerType())
				pb, ok := packet.(gopacket.PacketBuilder)
				if !ok {
					panic("Not a PacketBuilder")
				}
				nextDecoder := newip4.NextLayerType()
				nextDecoder.Decode(newip4.Payload, pb)
			}
		}

		tcp := packet.Layer(layers.LayerTypeTCP)
		if tcp != nil {
			tcp := tcp.(*layers.TCP)
			if *checksum {
				err := tcp.SetNetworkLayerForChecksum(packet.NetworkLayer())
				if err != nil {
					log.Fatalf("Failed to set network layer for checksum: %s\n", err)
				}
			}
			c := Context{
				CaptureInfo: packet.Metadata().CaptureInfo,
			}
			stats.totalsz += len(tcp.Payload)

			assembler.AssembleWithContext(packet.NetworkLayer().NetworkFlow(), tcp, &c)
		}
		if count%*statsevery == 0 {
			ref := packet.Metadata().CaptureInfo.Timestamp
			flushed, closed := assembler.FlushWithOptions(reassembly.FlushOptions{T: ref.Add(-timeout), TC: ref.Add(-closeTimeout)})
			Debug("Forced flush: %d flushed, %d closed (%s)", flushed, closed, ref)
		}

		done := *maxcount > 0 && count >= *maxcount
		if count%*statsevery == 0 || done || sysexit {
			errorsMapMutex.Lock()
			errorMapLen := len(errorsMap)
			errorsMapMutex.Unlock()
			fmt.Fprintf(os.Stderr, "Processed %v packets (%v bytes) in %v (errors: %v, errTypes:%v)\n", count, bytes, time.Since(start), errors, errorMapLen)
		}
		if sysexit {
			break
		}
	}

	closed := assembler.FlushAll()
	Debug("Final flush: %d closed", closed)
	if outputLevel >= 2 {
		streamPool.Dump()
	}

	if *memprofile != "" {
		f, err := os.Create(*memprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.WriteHeapProfile(f)
		f.Close()
	}

	streamFactory.WaitGoRoutines()
	Debug("%s\n", assembler.Dump())
	if !*nodefrag {
		fmt.Printf("IPdefrag:\t\t%d\n", stats.ipdefrag)
	}
	fmt.Printf("TCP stats:\n")
	fmt.Printf(" missed bytes:\t\t%d\n", stats.missedBytes)
	fmt.Printf(" total packets:\t\t%d\n", stats.pkt)
	fmt.Printf(" rejected FSM:\t\t%d\n", stats.rejectFsm)
	fmt.Printf(" rejected Options:\t%d\n", stats.rejectOpt)
	fmt.Printf(" reassembled bytes:\t%d\n", stats.sz)
	fmt.Printf(" total TCP bytes:\t%d\n", stats.totalsz)
	fmt.Printf(" conn rejected FSM:\t%d\n", stats.rejectConnFsm)
	fmt.Printf(" reassembled chunks:\t%d\n", stats.reassembled)
	fmt.Printf(" out-of-order packets:\t%d\n", stats.outOfOrderPackets)
	fmt.Printf(" out-of-order bytes:\t%d\n", stats.outOfOrderBytes)
	fmt.Printf(" biggest-chunk packets:\t%d\n", stats.biggestChunkPackets)
	fmt.Printf(" biggest-chunk bytes:\t%d\n", stats.biggestChunkBytes)
	fmt.Printf(" overlap packets:\t%d\n", stats.overlapPackets)
	fmt.Printf(" overlap bytes:\t\t%d\n", stats.overlapBytes)
	fmt.Printf("Errors: %d\n", errors)
	for e, _ := range errorsMap {
		fmt.Printf(" %s:\t\t%d\n", e, errorsMap[e])
	}
}

