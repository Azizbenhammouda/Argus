package detect

import "github.com/google/gopacket/layers"

type tcpRule func(tcp *layers.TCP) (matched bool, name string, detail string)

func isNullScan(tcp *layers.TCP) (bool, string, string) {
	if !tcp.SYN && !tcp.ACK && !tcp.FIN && !tcp.RST && !tcp.PSH && !tcp.URG {
		return true, "NULL_SCAN", "no TCP flags set — not a legitimate TCP state"
	}
	return false, "", ""
}

func isXmasScan(tcp *layers.TCP) (bool, string, string) {
	if tcp.FIN && tcp.PSH && tcp.URG && !tcp.SYN && !tcp.ACK && !tcp.RST {
		return true, "XMAS_SCAN", "FIN+PSH+URG set together — classic Xmas scan pattern"
	}
	return false, "", ""
}

func isFinScan(tcp *layers.TCP) (bool, string, string) {
	if tcp.FIN && !tcp.ACK && !tcp.SYN && !tcp.RST && !tcp.PSH && !tcp.URG {
		return true, "FIN_SCAN", "bare FIN with no ACK — not a real connection teardown"
	}
	return false, "", ""
}
func isSynFinScan(tcp *layers.TCP) (bool, string, string) {
	if tcp.SYN && tcp.FIN {
		return true, "SYN_FIN_SCAN", "SYN and FIN set simultaneously — mutually exclusive flags, always forged"
	}
	return false, "", ""
}

var tcpRules = []tcpRule{
	isNullScan,
	isXmasScan,
	isFinScan,
	isSynFinScan,
}
