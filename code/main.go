package main

import (
	"fmt"
	"log"
	"time"

	"net/http"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type logWriter struct {
}

// [{'srcip': 'value', 'count': 0}, {'srcip': 'value', 'count': 0}]
type Connections struct {
	Address    string
	Count      int
	Ports      []int
	Timestamps []time.Time
}

type RepeatConnections struct {
	Address    string
	Count      int
	Timestamps []time.Time
}

// make output match this -> 2021-04-28 15:28:05: New connection: 192.0.2.56:5973 -> 10.0.0.5:80
func (writer logWriter) Write(bytes []byte) (int, error) {
	return fmt.Print(time.Now().UTC().Format("2006-01-02 15:04:05: ") + string(bytes))
}

const (
	// The same default as tcpdump.
	defaultSnapLen = 262144
)

var (
	connsProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "tcpcap_processed_conns_total",
		Help: "The total number of processed connections",
	})
)

var (
	blocksProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "tcpcap_processed_blocks_total",
		Help: "The total number of processed connections",
	})
)

// set your interface here

var iface string = "eth0"

// var bpfsyn string = "tcp[13] = 3"

func inTimeSpan(start, end, check time.Time) bool {
	if start.Before(end) {
		return !check.Before(start) && !check.After(end)
	}
	if start.Equal(end) {
		return check.Equal(start)
	}
	return !start.After(check) || !end.Before(check)
}

func stamper(address string, timestamps []time.Time) bool {

	end := time.Now()
	start := end.Add(-60 * time.Second)
	rc := RepeatConnections{}

	for _, t := range timestamps {
		span := inTimeSpan(start, end, t)
		if span {
			rc.Address = address
			rc.Timestamps = append(rc.Timestamps, t)
			fmt.Println("connectinons detected withing the last 60")
			return true
		} else if !span {
			fmt.Println("no connections in the last 60 seconds")
			return false
		}
	}
	var bool bool

	if len(rc.Timestamps) > 3 {
		bool = false
	} else if len(rc.Timestamps) < 3 {
		bool = true
	}

	return bool // not sure what to return here
}

func blockEm(address string) bool {

	chain := "INPUT"
	ipt, err := iptables.New()
	if err != nil {
		log.Fatal(err)
		return false
	}

	pend := ipt.AppendUnique("filter", chain, "-s", address, "-j", "DROP")
	blocksProcessed.Inc()
	log.Printf("BLOCK IP: %s", address)
	if pend != nil {
		log.Fatal(pend)
		return false
	}

	return true
}

func portCompare(newPort int, portArray []int) bool {
	var portsConnected int
	var toBlock bool

	for _, port := range portArray {
		if port != newPort {
			portsConnected++
		} else if port == newPort {
			log.Print("no new port connected")
		}
	}
	if portsConnected > 3 {
		toBlock = true
	} else if portsConnected < 3 {
		toBlock = false
	}
	return toBlock
}

func capMe() {
	/*
		here I am opening a capture on a selected interface and filtering it with a BPF filter
		the bpf query is just a variable that we will default to tcp[13] = 3 to capture syn connections
		from the chosen interface
	*/

	listener, err := pcap.OpenLive(iface, defaultSnapLen, true,
		pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	// enforcing a specific time-date format for the log output

	log.SetFlags(0)
	log.SetOutput(new(logWriter))

	// make the struct for the connections
	c := Connections{}

	// tcp and tcp[tcpflags] == tcp-syn or
	// TODO: confirm correct set of filters for BPF for syn packets.

	if err := listener.SetBPFFilter("tcp[tcpflags] == tcp-syn"); err != nil {
		panic(err)
	}

	log.Println("Listening on", iface, "...")

	packets := gopacket.NewPacketSource(
		listener, listener.LinkType()).Packets()

	// loop through new packets to see if they meet the criteria

	for pkt := range packets {
		log.Println(pkt)
		packet := gopacket.NewPacket(pkt.Data(), layers.LayerTypeEthernet, gopacket.Default)
		tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		l2, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		addr := l2.SrcIP.String()

		if c.Address != addr {
			c.Address = addr
			c.Count = 1
			c.Ports = append(c.Ports, int(tcp.DstPort))
			c.Timestamps = append(c.Timestamps, time.Now())
			connsProcessed.Inc()
		} else if c.Address == addr {

			c.Count++
			connsProcessed.Inc()

			ports := portCompare(int(tcp.SrcPort), c.Ports)

			if ports {
				err := stamper(addr, c.Timestamps)
				if err {
					log.Printf("Port scan detected: %s -> %s on ports %d", addr, l2.DstIP, c.Ports)
					blockEm(addr)
				} else {
					fmt.Println("no connections in the last 60 seconds")
				}

				c.Ports = append(c.Ports, int(tcp.DstPort))

				log.Printf("Repeat Connection: %s has connected before %d times.\n", addr, c.Count)

			}
			log.Printf("New Connection: %s:%s -> %s:%d", l2.SrcIP, tcp.SrcPort, l2.DstIP, tcp.DstPort)

		}
	}
}

func main() {

	go capMe()

	// prom setup

	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":2112", nil)

}
