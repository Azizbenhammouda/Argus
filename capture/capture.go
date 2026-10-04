package capture

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func StartCapture(device string) (*gopacket.PacketSource, *pcap.Handle, error) {
	//connecting to the live packet stream (raw pcap connection)
	handler, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, nil, err
	}
	//decoding raw bytes into gopacket.Packet objects
	//Linktype is for the method to know if its ethernet wifi wala loopback
	src := gopacket.NewPacketSource(handler, handler.LinkType())
	return src, handler, nil
}
