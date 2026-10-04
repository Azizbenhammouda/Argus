package detect

import "github.com/google/gopacket/layers"

func IsNullScan(tcp *layers.TCP) (bool, string) {
	if !tcp.SYN && !tcp.ACK && !tcp.FIN && !tcp.RST && !tcp.PSH && !tcp.URG {
		return true, "NULL Scan detected"
	}
	return false, ""
}
