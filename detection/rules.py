from src.detection.states import (
    check_ssh_bruteforce,
    check_port_scan
)

SUSPICIOUS_PORTS = {4444, 1337}


def analyze_packet(packet):
   
    alerts = []

    src_ip = packet["src_ip"]
    dst_ip = packet["dst_ip"]
    dst_port = packet["port_dst"]
    protocol = packet["protocol"]

    
    if dst_port in SUSPICIOUS_PORTS:
        alerts.append(
            f"[ALERT] Suspicious port {dst_port} accessed "
            f"{src_ip} -> {dst_ip}"
        )

   
    if check_ssh_bruteforce(src_ip, dst_port):
        alerts.append(
            f"[ALERT] Possible SSH brute force from {src_ip}"
        )

    
    if check_port_scan(src_ip, dst_port):
        alerts.append(
            f"[ALERT] Possible port scan from {src_ip}"
        )

    return alerts
