import time
from collections import defaultdict


ssh_attempts = defaultdict(list)
port_scan_tracker = defaultdict(set)


def check_ssh_bruteforce(src_ip, dst_port, window=60, threshold=5):
    
    if dst_port != 22:
        return False

    now = time.time()
    ssh_attempts[src_ip].append(now)

    
    ssh_attempts[src_ip] = [
        t for t in ssh_attempts[src_ip]
        if now - t <= window
    ]

    return len(ssh_attempts[src_ip]) >= threshold


def check_port_scan(src_ip, dst_port, threshold=10):
    
    port_scan_tracker[src_ip].add(dst_port)

    return len(port_scan_tracker[src_ip]) >= threshold
