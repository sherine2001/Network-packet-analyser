from scapy.all import sniff, IP, TCP, UDP
from collections import Counter
import json

packet_log = []
protocol_counter = Counter()

def packet_callback(packet, callback_fn=None):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        proto = "OTHER"
        if TCP in packet:
            proto = "TCP"
        elif UDP in packet:
            proto = "UDP"
            
        protocol_counter[proto] += 1
        
        entry = {
            "src": src_ip,
            "dst": dst_ip,
            "protocol": proto
        }
        packet_log.append(entry)
        
        # Call UI update function if provided
        if callback_fn:
            callback_fn(entry)

def start_sniffing(count=100, callback_fn=None):
    sniff(count=count, prn=lambda pkt: packet_callback(pkt, callback_fn))

def save_log():
    with open("packet_log.json", "w") as f:
        json.dump(packet_log, f, indent=4)
    print("Log saved to packet_log.json")

def get_stats():
    return protocol_counter