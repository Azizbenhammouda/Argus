package capture

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func StartCapture(device string) (*gopacket.PacketSource, *pcap.Handle, error) {
	const (
		snaplen = 1600
		promisc = true
	)

	handle, err := pcap.OpenLive(device, snaplen, promisc, pcap.BlockForever)
	if err != nil {
		return nil, nil, err
	}

	src := gopacket.NewPacketSource(handle, handle.LinkType())
	return src, handle, nil
}
