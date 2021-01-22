/* http dump
 * Author:asmcos
 * 2018-
 * thank gopacket example
 */

package main

import (

	"flag"
	"log"
	"time"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/google/gopacket/tcpassembly"

	"bytes"
	"io"
	"bufio"
	"net/textproto"
	"strings"
)

var iface = flag.String("i", "lo0", "Interface to get packets from")
var snaplen = flag.Int("s", 1600, "SnapLen for pcap packet capture")
var filter = flag.String("f", "tcp and port 80", "BPF filter for pcap")
var logAllPackets = flag.Bool("v", true, "Logs every packet in great detail")
var help = flag.Bool("h", false, "this help")

var    colorReset = "\033[0m"

var    colorRed = "\033[31m"
var    colorGreen = "\033[32m"
var    colorYellow = "\033[33m"
var    colorBlue = "\033[34m"
var    colorPurple = "\033[35m"
var    colorCyan = "\033[36m"
var    colorWhite = "\033[37m"

var  match_http = 0

func Usage(){

    flag.PrintDefaults()

}


func isRequest(firstLine string)bool{
    arr := strings.Split(firstLine, " ")

    switch strings.TrimSpace(arr[0]) {
    case "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "CONNECT":
        return true
    default:
        return false
    }

}

func  isHttp(data []byte) bool{
    buf := bytes.NewBuffer(data)
    reader := bufio.NewReader(buf)
    tp := textproto.NewReader(reader)

    firstLine, _ := tp.ReadLine()

	if (isRequest(firstLine)){
		fmt.Println(string(colorPurple),firstLine,match_http)
		match_http += 1
	}
/*
	if (strings.HasPrefix(strings.TrimSpace(firstLine), "HTTP/")){
		log.Println(string(colorRed),firstLine,match_http)
		match_http -= 1
	}


	return strings.HasPrefix(strings.TrimSpace(firstLine), "HTTP/")||isRequest(firstLine)
*/
	return isRequest(firstLine)
}

/*************************/
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
	go hstream.run() // Important... we must guarantee that data from the reader stream is read.

	// ReaderStream implements tcpassembly.Stream, so we can return a pointer to it.
	return &hstream.r
}

func (h *httpStream) run() {
	buf := bufio.NewReader(&h.r)
	length := 0
	for {
		_,err := buf.ReadByte()
		if err == io.EOF {
			// We must read until we see an EOF... very important!
			//log.Println(string(colorYellow),"Received request from stream", h.net, h.transport, ":", "with", length, "bytes ")
			return
		}
		length ++
	}
}



/*************************/


func main() {

	var handle *pcap.Handle
	var err error

	flag.Usage = Usage
    flag.Parse()

    if *help == true {
      flag.Usage()
      return
    }
	// Set up pcap packet capture

	log.Printf("Starting capture on interface %q", *iface)
	handle, err = pcap.OpenLive(*iface, int32(*snaplen), true, pcap.BlockForever)

	if err != nil {
		log.Fatal(err)
	}

	if err := handle.SetBPFFilter(*filter); err != nil {
		log.Fatal(err)
	}


	log.Println("Reading in packets")
	// Read in packets, pass to assembler.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()
	ticker := time.Tick(time.Minute)


		// Set up assembly
	streamFactory := &httpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)


	for {
		select {
		case packet := <-packets:
			// A nil packet indicates the end of a pcap file.
			if packet == nil {
				return
			}

            if packet.NetworkLayer() == nil || packet.TransportLayer() == nil || packet.TransportLayer().LayerType() != layers.LayerTypeTCP {
                log.Println("Unusable packet")
                continue
            }


			//ether := packet.LinkLayer().(*layers.Ethernet)
			ip := packet.NetworkLayer().(*layers.IPv4)
			tcp := packet.TransportLayer().(*layers.TCP)
			http := isHttp(tcp.Payload)
			if *logAllPackets && http {
				//log.Printf("%s %#v",string(colorYellow),tcp)
				//log.Printf("%s %s",colorPurple,tcp.Payload)
				//log.Printf("%s -> %s ",ether.SrcMAC ,ether.DstMAC)
				fmt.Printf("%s:%s -> %s:%s ",ip.SrcIP,tcp.SrcPort ,ip.DstIP,tcp.DstPort)
				//log.Printf("Length %d",packet.Metadata().CaptureInfo.Length)
				//log.Print(packet.NetworkLayer().NetworkFlow(), packet.Metadata().Timestamp)
			}
			assembler.AssembleWithTimestamp(packet.NetworkLayer().NetworkFlow(), tcp, packet.Metadata().Timestamp)
		case <-ticker:
			// Every minute, flush connections that haven't seen activity in the past 2 minutes.
			assembler.FlushOlderThan(time.Now().Add(time.Minute * -2))
		}
	}

}
