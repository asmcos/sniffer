/* http dump
 * Author:asmcos
 * 2018-
 * thank gopacket example
 */

package main

import (

	"flag"
	"log"
	_"time"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	_"bytes"
	_"io"
	_"bufio"
	_"net/textproto"
	_"strings"
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

var  conn_count = 0

func Usage(){

    flag.PrintDefaults()

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


	layers.RegisterTCPPortLayerType(layers.TCPPort(80), LayerTypeHTTP)

	//	解析


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

			if (packet.NetworkLayer().LayerType() != layers.LayerTypeIPv4) {
				// skip ipv6
				continue
			}
			//ether := packet.LinkLayer().(*layers.Ethernet)
			ip := packet.NetworkLayer().(*layers.IPv4)
			tcp := packet.TransportLayer().(*layers.TCP)


			//http := packet.ApplicationLayer().(*HTTP)
			log.Println("AppLayer",packet.ApplicationLayer())
			if *logAllPackets {
				//log.Printf("%s %#v",string(colorYellow),tcp)
				//log.Printf("%s %s",colorPurple,tcp.Payload)
				//log.Printf("%s -> %s ",ether.SrcMAC ,ether.DstMAC)
				fmt.Printf("%s %s:%s -> %s:%s \n",packet.Metadata().Timestamp,ip.SrcIP,tcp.SrcPort ,ip.DstIP,tcp.DstPort )
				//log.Printf("Length %d",packet.Metadata().CaptureInfo.Length)
				//log.Print(packet.NetworkLayer().NetworkFlow(), packet.Metadata().Timestamp)
			}
			if tcp.SYN {
				conn_count ++
				log.Println(string(colorYellow),tcp.SYN,tcp.FIN,conn_count,string(colorReset))
			}
			if tcp.FIN {
				conn_count --
				log.Println(string(colorRed),tcp.SYN,tcp.FIN,conn_count,string(colorReset))
			}

		}
	}

}
