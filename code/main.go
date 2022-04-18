package main

import (
	"fmt"

	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	// The same default as tcpdump.
	defaultSnapLen = 262144
)

func main() {
	handle, err := pcap.OpenLive("eth0", defaultSnapLen, true,
		pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter("tcp[13] = 3"); err != nil {
		panic(err)
	}

	packets := gopacket.NewPacketSource(
		handle, handle.LinkType()).Packets()
	for pkt := range packets {
		fmt.Println(pkt)
	}
}
