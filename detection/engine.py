from capture.sniffer import start_sniffing
from detection.rules import analyze_packet


def engine_packet_handler(packet):
    alerts = analyze_packet(packet)

    for alert in alerts:
        print(alert)


def start_engine(interface=None):
    print("[*] IDS Engine started")
    start_sniffing(interface=interface, callback=engine_packet_handler)
