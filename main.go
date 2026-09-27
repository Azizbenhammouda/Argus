package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket/pcap"
)

func main() {
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
}
