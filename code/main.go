package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type logWriter struct {
}

// [{'srcip': 'value', 'count': 0}, {'srcip': 'value', 'count': 0}]
type Connections struct {
	Address string
	Count   int
}

// make output match this -> 2021-04-28 15:28:05: New connection: 192.0.2.56:5973 -> 10.0.0.5:80
func (writer logWriter) Write(bytes []byte) (int, error) {
	return fmt.Print(time.Now().UTC().Format("2006-01-02 15:04:05: ") + string(bytes))
}

const (
	// The same default as tcpdump.
	defaultSnapLen = 262144
)

var iface string = "enp0s8"

// var bpfsyn string = "tcp[13] = 3"

func main() {

	// enforcing a specific time-date format for the log output

	log.SetFlags(0)
	log.SetOutput(new(logWriter))

	// make the struct for the connections
	c := Connections{}

	/*
		here I am opening a capture on a selected interface and filtering it with a BPF filter
		the bpf query is just a variable that we will default to tcp[13] = 3 to capture syn connections
		from the chosen interface
	*/

	handle, err := pcap.OpenLive(iface, defaultSnapLen, true,
		pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	// TODO: confirm correct set of filters for BPF for syn packets.
	if err := handle.SetBPFFilter("tcp"); err != nil {
		panic(err)
	}

	log.Println("Listening on", iface, "...")

	packets := gopacket.NewPacketSource(
		handle, handle.LinkType()).Packets()
	for pkt := range packets {

		packet := gopacket.NewPacket(pkt.Data(), layers.LayerTypeEthernet, gopacket.Default)
		tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		l2, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		addr := l2.SrcIP.String()

		if c.Address == addr {
			c.Count++
			log.Printf("Repeat Connection: %s has connected before %s times. \n", addr, c.Count)
		} else {
			c.Address = addr
			c.Count = 1
		}

		log.Printf("New Connection: %s:%s -> %s:%s\n", l2.SrcIP, tcp.SrcPort, l2.DstIP, tcp.DstPort)

	}

}
