package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/Azizbenhammouda/Argus/alerts"
	"github.com/Azizbenhammouda/Argus/capture"
	"github.com/Azizbenhammouda/Argus/detect"
	"github.com/google/gopacket/pcap"
)

func main() {
	device := flag.String("i", "", "network interface to listen on (e.g. eth0)")
	logPath := flag.String("log", "argus.log", "path to write alert log")
	flag.Parse()

	ifcs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	if *device == "" {
		fmt.Println("No interface given. Available interfaces:")
		for _, ifc := range ifcs {
			fmt.Printf("  %-10s %s\n", ifc.Name, ifc.Description)
			for _, addr := range ifc.Addresses {
				fmt.Printf("      IP: %-15v Netmask: %v\n", addr.IP, addr.Netmask)
			}
		}
		fmt.Println("\nUsage: sudo ./argus -i <interface>")
		return
	}

	al := alerts.New(*logPath)
	defer al.Close()

	engine := detect.NewEngine(al)

	src, handler, err := capture.StartCapture(*device)
	if err != nil {
		log.Fatal(err)
	}
	defer handler.Close()

	fmt.Printf("Argus NIDS listening on %s (alerts -> stdout + %s). Ctrl+C to stop.\n", *device, *logPath)

	for packet := range src.Packets() {
		engine.Inspect(packet)
	}
}
