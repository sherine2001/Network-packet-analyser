# 🔍 Network Packet Analyzer

A real-time network packet capture and analysis tool built with Python and Scapy.  
Detects routing protocols (OSPF, EIGRP, PIM, VRRP), classifies traffic, and flags anomalies — all through a clean desktop GUI.

---

## 📸 Screenshot

> *(Add a screenshot of your app here after running it)*  
> `screenshot.png`

---

## ✨ Features

- **Live Packet Capture** — Captures packets in real time from your network interface
- **Routing Protocol Detection** — Identifies OSPF, EIGRP, PIM, VRRP, IGMP alongside TCP/UDP
- **Anomaly Detection Engine** — Flags:
  - Oversized packets (> 1400 bytes)
  - High-volume sources (potential flood)
  - Routing protocol events on the wire
- **Protocol Stats Dashboard** — Live count of every protocol seen
- **JSON Log Export** — Save captured packets to `packet_log.json`
- **Configurable Packet Count** — Set how many packets to capture per session
- **Multithreaded** — Capture runs in background thread, GUI stays responsive

---

## 🛠️ Tech Stack

| Tool | Purpose |
|---|---|
| Python 3.x | Core language |
| Scapy | Packet sniffing and protocol parsing |
| Tkinter | Desktop GUI |
| Threading | Non-blocking capture |
| JSON | Log storage |
| Collections.Counter | Protocol statistics |

---

## 📁 Project Structure

```
network-packet-analyzer/
├── main.py           # GUI — layout, buttons, display logic
├── capture.py        # Capture engine — sniffing, protocol detection, anomaly logic
├── packet_log.json   # Auto-generated when you click Save Log
└── README.md
```

---

## ⚙️ Installation

**1. Clone the repo**
```bash
git clone https://github.com/sherinehoro/network-packet-analyzer.git
cd network-packet-analyzer
```

**2. Install dependencies**
```bash
pip install scapy
```

> Tkinter comes built-in with Python. If missing:
> ```bash
> # Ubuntu/Debian
> sudo apt install python3-tk
> ```

---

## ▶️ Running the App

**Windows** — Run as Administrator (required for raw packet capture):
```bash
python main.py
```

**Linux / Mac** — Run with sudo:
```bash
sudo python3 main.py
```

---

## 🖥️ How to Use

1. Set the **Packet Count** (default: 100)
2. Click **▶ Start Capture** — live packets appear in real time
3. Watch the **Stats Bar** at the bottom update per protocol
4. **Red rows** = anomaly detected (hover to see flag type)
5. Click **💾 Save Log** to export all packets to `packet_log.json`
6. Click **🗑 Clear** to reset the display

---

## 🔍 Protocols Detected

| Protocol | IP Number | Description |
|---|---|---|
| TCP | 6 | Transmission Control Protocol |
| UDP | 17 | User Datagram Protocol |
| OSPF | 89 | Open Shortest Path First (routing) |
| EIGRP | 88 | Enhanced Interior Gateway Routing Protocol |
| PIM | 103 | Protocol Independent Multicast |
| VRRP | 112 | Virtual Router Redundancy Protocol |
| IGMP | 2 | Internet Group Management Protocol |

---

## ⚠️ Anomaly Detection Rules

| Flag | Trigger |
|---|---|
| `LARGE_PACKET` | Packet size > 1400 bytes |
| `HIGH_VOLUME_SRC` | Same source IP seen > 20 times |
| `ROUTING_PROTO_DETECTED` | OSPF / EIGRP / PIM / IGMP packet observed |

---

## 📄 Sample JSON Output

```json
[
    {
        "src": "192.168.1.5",
        "dst": "224.0.0.5",
        "protocol": "OSPF",
        "size": 86,
        "anomaly": ["ROUTING_PROTO_DETECTED"]
    },
    {
        "src": "192.168.1.10",
        "dst": "8.8.8.8",
        "protocol": "UDP",
        "size": 72,
        "anomaly": null
    }
]
```

---

---

## 👤 Author

**Sherine Horo**  
B.Tech CSE — NIT Arunachal Pradesh, 2024  
[LinkedIn](https://linkedin.com/in/sherinehoro) • [GitHub](https://github.com/sherinehoro)

---

## 📜 License

MIT License — free to use, modify, and distribute.