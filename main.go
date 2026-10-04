package main

import (
	"fmt"
	"log"

	"github.com/Azizbenhammouda/Argus/capture"
	"github.com/Azizbenhammouda/Argus/detect"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// listing network interfaces in the machine
	ifcs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	for _, ifc := range ifcs {
		fmt.Printf("Name: %v\n", ifc.Name)
		fmt.Printf("Description: %v\n", ifc.Description)
		for _, address := range ifc.Addresses {
			fmt.Println("  IP:      ", address.IP)
			fmt.Println("  Netmask: ", address.Netmask)
		}
	}
	src, handler, err := capture.StartCapture("eth0")
	if err != nil {
		log.Fatal(err)
	}
	defer handler.Close()
	for packet := range src.Packets() {
		//return the tcp layer of the packet
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		// not handlind UDP or ICMP.. rn
		if tcpLayer == nil {
			continue
		}
		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			continue
		}
		suspicious, reason := detect.IsNullScan(tcp)
		if suspicious {
			fmt.Printf("%s: %v -> %v\n", reason, tcp.SrcPort, tcp.DstPort)
		}
	}
}
