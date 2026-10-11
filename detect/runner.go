package detect

import (
	"fmt"
	"net"
	"time"

	"github.com/Azizbenhammouda/Argus/alerts"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Engine struct {
	alerter   *alerts.Alerter
	portScans *portScanTracker
}

func NewEngine(a *alerts.Alerter) *Engine {
	return &Engine{
		alerter:   a,
		portScans: newPortScanTracker(10*time.Second, 15),
	}
}

func (e *Engine) Inspect(packet gopacket.Packet) {
	var srcIP, dstIP net.IP
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		if ip, ok := ipLayer.(*layers.IPv4); ok {
			srcIP = ip.SrcIP
			dstIP = ip.DstIP
		}
	}
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return
	}
	if srcIP != nil {
		if fired, count := e.portScans.record(srcIP, uint16(tcp.DstPort)); fired {
			e.alerter.Fire(alerts.Event{
				Rule:   "PORT_SCAN",
				SrcIP:  srcIP.String(),
				Detail: fmt.Sprintf("%d distinct destination ports contacted within 10s window", count),
			})
		}
	}
	for _, rule := range tcpRules {
		matched, name, detail := rule(tcp)
		if !matched {
			continue
		}
		e.alerter.Fire(alerts.Event{
			Rule:    name,
			SrcIP:   ipOrEmpty(srcIP),
			DstIP:   ipOrEmpty(dstIP),
			SrcPort: fmt.Sprintf("%d", tcp.SrcPort),
			DstPort: fmt.Sprintf("%d", tcp.DstPort),
			Detail:  detail,
		})
	}
}

func ipOrEmpty(ip net.IP) string {
	if ip == nil {
		return "?"
	}
	return ip.String()
}
