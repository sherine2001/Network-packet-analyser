from scapy.all import sniff, IP, TCP, UDP
from collections import Counter
import json

packet_log = []
protocol_counter = Counter()

# IP protocol numbers for routing protocols
PROTO_MAP = {
    6:   "TCP",
    17:  "UDP",
    89:  "OSPF",
    88:  "EIGRP",
    103: "PIM",
    112: "VRRP",
    2:   "IGMP",
}

def detect_anomaly(entry):
    flags = []

    # Flag unusually large packets
    if entry.get("size", 0) > 1400:
        flags.append("LARGE_PACKET")

    # Flag high volume from a single source (potential flood)
    src_counts = Counter(p["src"] for p in packet_log)
    if src_counts[entry["src"]] > 20:
        flags.append("HIGH_VOLUME_SRC")

    # Flag uncommon routing protocol traffic
    if entry["protocol"] in ("OSPF", "EIGRP", "PIM", "IGMP"):
        flags.append("ROUTING_PROTO_DETECTED")

    return flags if flags else None


def packet_callback(packet, callback_fn=None):
    if IP in packet:
        src_ip    = packet[IP].src
        dst_ip    = packet[IP].dst
        proto_num = packet[IP].proto
        size      = len(packet)

        proto = PROTO_MAP.get(proto_num, f"OTHER({proto_num})")

        protocol_counter[proto] += 1

        entry = {
            "src":      src_ip,
            "dst":      dst_ip,
            "protocol": proto,
            "size":     size,
        }

        anomaly = detect_anomaly(entry)
        entry["anomaly"] = anomaly

        packet_log.append(entry)

        if callback_fn:
            callback_fn(entry)


def start_sniffing(count=100, callback_fn=None):
    sniff(count=count, prn=lambda pkt: packet_callback(pkt, callback_fn))


def save_log():
    with open("packet_log.json", "w") as f:
        json.dump(packet_log, f, indent=4)
    print("Log saved to packet_log.json")


def get_stats():
    return dict(protocol_counter)


def get_anomaly_count():
    return sum(1 for p in packet_log if p.get("anomaly"))