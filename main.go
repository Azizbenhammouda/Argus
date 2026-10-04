package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
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
	//connecting to the live packet stream (raw pcap connection)
	handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	//decoding raw bytes into gopacket.Packet objects
	//Linktype is for the method to know if its ethernet wifi wala loopback
	packsrc := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packsrc.Packets() {
		fmt.Println(packet)
	}
}
