package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

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

type Connection struct {
	Address    string
	Ports      []int
	Timestamps []time.Time
}

type ConnectionMap map[string]Connection

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

	blocksProcessed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "tcpcap_processed_blocks_total",
		Help: "The total number of processed connections",
	})
)

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if len(value) == 0 {
		return defaultValue
	}
	return value
}

// set the interface here

var iface string = getEnv("INTERFACE_NAME", "eth0")
var publicIp string = getEnv("PUBLIC_IP", "127.0.0.1")

var bpfsyn string = "tcp[tcpflags] == tcp-syn" // or "tcp[13] = 3"

// this function takes an array of timestamps associated with
func shouldBlock(address string, timestamps []time.Time) bool {

	// end := time.Now()
	start := time.Now().Add(-60 * time.Second)
	repeatConnections := 0

	for _, t := range timestamps {
		// span := inTimeSpan(start, end, t)
		inRange := t.After(start)
		if inRange {
			repeatConnections += 1
		} else {
			continue
		}
	}

	canConnect := repeatConnections >= 3

	return canConnect

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

func capMe() {

	/*
		here I am opening a capture on a selected interface and filtering it with a BPF filter
		the bpf query is just a variable that we will default to tcp[13] = 3 to capture syn connections
		from the chosen interface
	*/

	// init map
	conn := make(map[string]Connection)

	listener, err := pcap.OpenLive(iface, defaultSnapLen, true,
		pcap.BlockForever)
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	// enforcing a specific time-date format for the log output

	log.SetFlags(0)
	log.SetOutput(new(logWriter))

	// tcp[tcpflags] == tcp-syn
	// TODO: confirm correct set of filters for BPF for syn packets.

	if err := listener.SetBPFFilter(bpfsyn); err != nil {
		panic(err)
	}

	log.Println("Listening on", iface, "...")

	packets := gopacket.NewPacketSource(
		listener, listener.LinkType()).Packets()

	// loop through new packets to see if they meet the criteria

	for pkt := range packets {
		//fmt.Println("DEBUG: OPEN ", conn)

		packet := gopacket.NewPacket(pkt.Data(), layers.LayerTypeEthernet, gopacket.Default)
		tcp, _ := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		l2, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		addr := l2.SrcIP.String()

		// if the packet originates from host, ignore it and move on
		if addr == publicIp {
			continue // Ingore this packet

		} else {
			log.Printf("New Connection: %s:%d -> %s:%d\n", l2.SrcIP, tcp.SrcPort, l2.DstIP, tcp.DstPort)
			connsProcessed.Inc()
		}

		// check if the address is already in the map
		if foundConnection, ok := conn[addr]; ok {

			// Checking the following:
			// 1. entry in the map
			// 2. is the port already in the array
			// 3. if it isn't then your add it to the array

			newPort := int(tcp.DstPort)
			portFound := false
			for _, port := range foundConnection.Ports {
				if port == newPort {
					portFound = true
					break
				}
			}

			if !portFound {
				foundConnection.Ports = append(foundConnection.Ports, newPort)
				foundConnection.Timestamps = append(foundConnection.Timestamps, time.Now())

				// TODO(memory usage): If more than 3 then remove from front

			}

			// This is an address that exists
			if shouldBlock(addr, foundConnection.Timestamps) {
				trimmed := strings.Trim(fmt.Sprint(foundConnection.Ports), "[]")
				fmted := strings.Replace(trimmed, " ", ",", -1)
				log.Printf("Port scan detected: %s -> %s on ports %v\n", l2.SrcIP, l2.DstIP, fmted)
				if !blockEm(addr) {
					fmt.Printf("Blocking failed %s\n", addr)
				}
			}

			// debug comment fmt.Println(foundConnection)

			conn[addr] = foundConnection

		} else {
			// if it is not, create a new connection
			conn[addr] = Connection{
				Address: addr,
				Ports:   []int{int(tcp.DstPort)},
				Timestamps: []time.Time{
					time.Now(),
				},
			}
		}

		// TODO(memory usage): If there's an old connection where all the timestamps are old then remove it

	}

}

func main() {

	go capMe()

	// prom setup

	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":2112", nil)

}
