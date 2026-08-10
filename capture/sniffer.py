from scapy.all import sniff,IP,TCP,UDP,ICMP



def organize_packet(packet):
  if IP not in packet:
    return None
  packet_data={
    "src_ip":packet[IP].src,
    "dest_ip":packet[IP].dst,
    "protocol":None,
    "port_src":None,
    "port_dst":None
  }
  if TCP in packet:
    packet_data["protocol"]="TCP"
    packet_data["port_src"]=packet[TCP].sport
    packet_data["port_dst"]=packet[TCP].dport
  elif UDP in packet:
    packet_data["protocol"]="UDP"
    packet_data["port_src"]=packet[UDP].sport
    packet_data["port_dst"]=packet[UDP].dport
  elif ICMP in packet:
     packet_data["protocol"]="ICMP"
  return packet_data  
  
   
  
def packet_exec(packet):
    organized=organize_packet(packet)
    if organized:
      print (organized)
def start_sniffing(interface=None):
    sniff(iface=interface,
        prn=callback if callback else packet_exec,
        store=False)
if __name__ == "__main__":
    print("Starting packet capture...")
    start_sniffing()

 

