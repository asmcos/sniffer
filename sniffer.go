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

	"github.com/jinzhu/gorm"

)

var maxcount = flag.Int("c", -1, "Only grab this many packets, then exit")
var decoder = flag.String("decoder", "", "Name of the decoder to use (default: guess from capture)")
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

// capture
var iface = flag.String("i", "eth0", "Interface to read packets from")
var port = flag.Int("p", 80, "Interface to read packets from")
var fname = flag.String("r", "", "Filename to read from, overrides -i")
var snaplen = flag.Int("s", 65536, "Snap length (number of bytes max to read per packet")
var tstype = flag.String("timestamp_type", "", "Type of timestamps to use")
var promisc = flag.Bool("promisc", true, "Set promiscuous mode")

var memprofile = flag.String("memprofile", "", "Write memory profile")

const (
	defaultMaxMemory = 32 << 20 // 32 MB
)

var db *gorm.DB
func HeaderToDB(h http.Header,t uint,id uint){


    for n,v :=range h{
        val := strings.Join(v,", ")

        InsertHeaders(db,n ,val ,t ,id )
    }
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

const closeTimeout time.Duration = time.Hour * 24 // Closing inactive: TODO: from CLI
const timeout time.Duration = time.Minute * 5     // Pending bytes: TODO: from CLI

/*
 * HTTP part
 */

type httpReader struct {
	ident    string
	isClient bool
	bytes    chan []byte
	data     []byte
	hexdump  bool
	parent   *tcpStream
	logbuf   string
	srcip    string
	dstip    string
	srcport  string
	dstport  string
}

func (h *httpReader) Read(p []byte) (int, error) {
	ok := true
	for ok && len(h.data) == 0 {
		h.data, ok = <-h.bytes
	}
	if !ok || len(h.data) == 0 {
		return 0, io.EOF
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

func (h *httpRequest) DecompressBody(header http.Header, reader io.ReadCloser) (io.ReadCloser, bool) {
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




//server to client
func  isResponse(data []byte) (bool,string) {
    buf := bytes.NewBuffer(data)
    reader := bufio.NewReader(buf)
    tp := textproto.NewReader(reader)

    firstLine, _ := tp.ReadLine()
    return strings.HasPrefix(strings.TrimSpace(firstLine), "HTTP/"),firstLine
}


func printHeader(h http.Header)string{
	var logbuf string

    for k,v := range h{
        logbuf += fmt.Sprintf("%s :%s\n",k,v)
    }
	return logbuf
}

func printRequest(req *http.Request)string{

    logbuf := fmt.Sprintf("\n")
    logbuf += fmt.Sprintf("%s\n",req.Host)
    logbuf += fmt.Sprintf("%s %s %s \n",req.Method, req.RequestURI, req.Proto)
    logbuf += printHeader(req.Header)

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




var respCount = 0;
var reqCount = 0;
var lockCount sync.Mutex

func detectHttp(data []byte) bool {

	ishttp,_ := isResponse(data)
	if ishttp{
		return true
	}

	ishttp,_ = isRequest(data)
	if ishttp{
		return true
	}

	return false
}




func (h *httpReader) runServer(wg *sync.WaitGroup) {
	defer wg.Done()

	var p  = make([]byte,1900)

	for ;;{

		_,err := h.Read(p)
		if (err == io.EOF){
			return
		}
		isResp,firstLine:= isResponse(p)
		if(isResp){
			lockCount.Lock()
			respCount ++
			lockCount.Unlock()
			h.logbuf += fmt.Sprintf("%v->%v:%v->%v\n",h.srcip,h.dstip,h.srcport,h.dstport)
			h.logbuf += fmt.Sprintf("%s %d\n",firstLine,respCount)

			buf := bytes.NewBuffer(p)
			b := bufio.NewReader(buf)
			res, err := http.ReadResponse(b, nil)
			if err == nil{
				h.logbuf += printResponse(res)
			}

	        h.Print()
			h.logbuf = ""

			req := FindRequestFirst(db,h.srcip,h.srcport,h.dstip,h.dstport)

			id := InsertResponseData(db,&ResponseTable{FirstLine:firstLine,
              StatusCode:res.StatusCode,
              SrcIp:h.srcip,SrcPort:h.srcport,
              DstIp:h.dstip,DstPort:h.dstport},&req)

        	// type 1 is request, 2 is response
        	HeaderToDB(res.Header,2,id)
		}

	}

}

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

type httpRequest struct {
    bytes    chan []byte
    done     chan bool
	data     []byte
	start    bool
	parent   *httpReader
	firstline string
}


func (h *httpRequest) Read(p []byte) (int, error) {
	ok := true
	for ok && len(h.data) == 0 {
		h.data, ok = <-h.bytes
	}
	if !ok || len(h.data) == 0 {
		h.done <- true
		return 0, io.EOF
	}

	l := copy(p, h.data)
	h.data = h.data[l:]
	return l, nil
}



func (hreq * httpRequest) HandleRequest () {

	var p  = make([]byte,1900)
	b := bufio.NewReader(hreq)

    req, err := http.ReadRequest(b)
    if err == io.EOF || err == io.ErrUnexpectedEOF {
        return
    } else if err != nil {
        Error("HTTP-request", "HTTP Request error: %s (%v,%+v)\n", err, err, err)

    } else {

	    req.ParseMultipartForm(defaultMaxMemory)

        r,ok := hreq.DecompressBody(req.Header,req.Body)
		if ok {
			defer r.Close()
		}
		contentType := req.Header.Get("Content-Type")
		logbuf := fmt.Sprintf("%v->%v:%v->%v\n",hreq.parent.srcip,hreq.parent.dstip,hreq.parent.srcport,hreq.parent.dstport)
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

	   id := InsertRequestData(db,&RequestTable{FirstLine:hreq.firstline,
              Host:req.Host,
              RequestURI:req.RequestURI,
              SrcIp:hreq.parent.srcip,SrcPort:hreq.parent.srcport,
              DstIp:hreq.parent.dstip,DstPort:hreq.parent.dstport})


        // type 1 is request, 2 is response
        HeaderToDB(req.Header,1,id)
	}

	//wait read all packet
	for{
		_,err = hreq.Read(p)
		if err == io.EOF{
			return
		}
	}

}

func (h *httpReader) runClient(wg *sync.WaitGroup) {
	defer wg.Done()

	var p  = make([]byte,1900)
	var req = httpRequest{
			bytes:   make(chan []byte),
			done:   make(chan bool),
			start:   false,
			parent:  h,
	}

	for {

		l,err := h.Read(p)
		if (err == io.EOF){
			return
		}
		if( l > 8 ){
			isReq,firstLine := isRequest(p)
			if(isReq){ //start new request
				lockCount.Lock()
				reqCount ++
				lockCount.Unlock()
				log.Println(firstLine,reqCount)

				if req.start { //如果存在正在处理的request，给request发结束通知，开始处理新的request 
					close(req.bytes)
					<-req.done //wait request parse done
				}

				//start new request parse
				req = httpRequest{
						bytes:   make(chan []byte),
						done:   make(chan bool),
						start:   true,
						parent: h,
						firstline:firstLine,
				}
				go req.HandleRequest()
				req.bytes <- p[:l]

			} else if req.start{ //other data

				req.bytes <- p[:l]
			}
		} else if req.start {
			req.bytes <- p[:l]
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
		isDNS:      tcp.SrcPort == 53 || tcp.DstPort == 53,
		isHTTP:     (tcp.SrcPort == layers.TCPPort(*port) || tcp.DstPort == layers.TCPPort(*port)) && factory.doHTTP,
		reversed:   tcp.SrcPort == layers.TCPPort(*port),
		tcpstate:   reassembly.NewTCPSimpleFSM(fsmOptions),
		ident:      fmt.Sprintf("%s:%s", net, transport),
		optchecker: reassembly.NewTCPOptionCheck(),
	}
	if stream.isHTTP {
		stream.client = httpReader{
			bytes:    make(chan []byte),
			ident:    fmt.Sprintf("%s %s", net, transport),
			hexdump:  *hexdump,
			parent:   stream,
			isClient: true,
			srcport: fmt.Sprintf("%d",tcp.SrcPort),
			dstport: fmt.Sprintf("%d",tcp.DstPort),
			srcip: srcip,
			dstip: dstip,
		}
		stream.server = httpReader{
			bytes:   make(chan []byte),
			ident:   fmt.Sprintf("%s %s", net.Reverse(), transport.Reverse()),
			hexdump: *hexdump,
			parent:  stream,
			dstport: fmt.Sprintf("%d",tcp.SrcPort),
			srcport: fmt.Sprintf("%d",tcp.DstPort),
			dstip: srcip,
			srcip: dstip,
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
	isDNS          bool
	isHTTP         bool
	reversed       bool
	client         httpReader
	server         httpReader
	urls           []string
	ident          string
	sync.Mutex
}

func (t *tcpStream) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	// FSM


	*start = detectHttp(tcp.Payload)

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
	data := sg.Fetch(length)
    if t.isHTTP {
		if length > 0 {
			if *hexdump {
				Debug("Feeding http with:\n%s", hex.Dump(data))
			}
			if dir == reassembly.TCPDirClientToServer && !t.reversed {
				t.client.bytes <- data
			} else {
				t.server.bytes <- data
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
	// initial database by gorm ;db_orm.go
	db = InitDB ()
	defer db.Close()

	go InitHdServer()

	var dec gopacket.Decoder
	var ok bool
	decoder_name := *decoder
	if decoder_name == "" {
		decoder_name = fmt.Sprintf("%s", handle.LinkType())
	}
	if dec, ok = gopacket.DecodersByLayerName[decoder_name]; !ok {
		log.Fatalln("No decoder named", decoder_name)
	}
	source := gopacket.NewPacketSource(handle, dec)
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

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)

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
		if count%*statsevery == 0 || done {
			errorsMapMutex.Lock()
			errorMapLen := len(errorsMap)
			errorsMapMutex.Unlock()
			fmt.Fprintf(os.Stderr, "Processed %v packets (%v bytes) in %v (errors: %v, errTypes:%v)\n", count, bytes, time.Since(start), errors, errorMapLen)
		}
		select {
		case <-signalChan:
			fmt.Fprintf(os.Stderr, "\nCaught SIGINT: aborting\n")
			done = true
		default:
			// NOP: continue
		}
		if done {
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

