import tkinter as tk
from tkinter import ttk
from threading import Thread
from capture import start_sniffing, save_log, get_stats, get_anomaly_count

# ── UI Update (called from capture thread) ───────────────────────────────────

def update_ui(entry):
    is_anomaly = bool(entry.get("anomaly"))
    anomaly_str = ""

    if is_anomaly:
        anomaly_str = "  ⚠  " + ", ".join(entry["anomaly"])

    line = (
        f"{entry['src']:<18}  -->  {entry['dst']:<18}"
        f"  |  {entry['protocol']:<10}"
        f"  |  {entry['size']} bytes"
        f"{anomaly_str}\n"
    )

    tag = "anomaly" if is_anomaly else "normal"
    log_text.insert(tk.END, line, tag)
    log_text.see(tk.END)

    # Update protocol stats bar
    stats = get_stats()
    stats_parts = [f"{proto}: {count}" for proto, count in sorted(stats.items())]
    stats_label.config(text="   |   ".join(stats_parts) if stats_parts else "No packets yet")

    # Update anomaly counter
    anomaly_count = get_anomaly_count()
    anomaly_label.config(
        text=f"⚠  Anomalies Detected: {anomaly_count}",
        fg="#ff4444" if anomaly_count > 0 else "#aaaaaa"
    )

# ── Button Functions ─────────────────────────────────────────────────────────

def start_capture():
    start_btn.config(state=tk.DISABLED, text="Capturing...")
    log_text.insert(tk.END, "─── Capture Started ───\n", "info")
    Thread(target=run_capture, daemon=True).start()

def run_capture():
    try:
        count = int(count_var.get())
    except ValueError:
        count = 100

    start_sniffing(count=count, callback_fn=update_ui)
    log_text.insert(tk.END, "─── Capture Complete ───\n", "info")
    start_btn.config(state=tk.NORMAL, text="▶  Start Capture")

def save_packets():
    save_log()
    log_text.insert(tk.END, "─── Log Saved to packet_log.json ───\n", "info")

def clear_screen():
    log_text.delete(1.0, tk.END)

# ── Build UI ─────────────────────────────────────────────────────────────────

root = tk.Tk()
root.title("Network Packet Analyzer")
root.geometry("900x580")
root.configure(bg="#1e1e1e")
root.resizable(True, True)

# Title bar
title_frame = tk.Frame(root, bg="#141414", pady=8)
title_frame.pack(fill=tk.X)

title_label = tk.Label(
    title_frame, text="🔍  Network Packet Analyzer",
    font=("Arial", 16, "bold"), bg="#141414", fg="#00ff99"
)
title_label.pack(side=tk.LEFT, padx=16)

version_label = tk.Label(
    title_frame, text="v1.1 — OSPF / EIGRP / PIM / VRRP Detection + Anomaly Engine",
    font=("Arial", 9), bg="#141414", fg="#666666"
)
version_label.pack(side=tk.LEFT, padx=4)

# Controls row
ctrl_frame = tk.Frame(root, bg="#1e1e1e", pady=6)
ctrl_frame.pack(fill=tk.X, padx=12)

tk.Label(ctrl_frame, text="Packet Count:", font=("Arial", 10),
         bg="#1e1e1e", fg="#aaaaaa").pack(side=tk.LEFT)

count_var = tk.StringVar(value="100")
count_entry = tk.Entry(ctrl_frame, textvariable=count_var, width=6,
                       bg="#2d2d2d", fg="#ffffff", font=("Courier", 10),
                       insertbackground="white")
count_entry.pack(side=tk.LEFT, padx=6)

start_btn = tk.Button(
    ctrl_frame, text="▶  Start Capture", width=16,
    bg="#00ff99", fg="#000000", font=("Arial", 10, "bold"),
    relief=tk.FLAT, cursor="hand2", command=start_capture
)
start_btn.pack(side=tk.LEFT, padx=8)

save_btn = tk.Button(
    ctrl_frame, text="💾  Save Log", width=14,
    bg="#4da6ff", fg="#000000", font=("Arial", 10, "bold"),
    relief=tk.FLAT, cursor="hand2", command=save_packets
)
save_btn.pack(side=tk.LEFT, padx=4)

clear_btn = tk.Button(
    ctrl_frame, text="🗑  Clear", width=10,
    bg="#ff6666", fg="#000000", font=("Arial", 10, "bold"),
    relief=tk.FLAT, cursor="hand2", command=clear_screen
)
clear_btn.pack(side=tk.LEFT, padx=4)

# Column header
header = tk.Label(
    root,
    text=f"  {'SRC IP':<18}        {'DST IP':<18}    {'PROTOCOL':<10}    SIZE         ANOMALY FLAGS",
    font=("Courier", 9, "bold"), bg="#2a2a2a", fg="#888888",
    anchor="w", padx=12, pady=4
)
header.pack(fill=tk.X, padx=12)

# Log display
log_frame = tk.Frame(root, bg="#1e1e1e")
log_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)

scrollbar = tk.Scrollbar(log_frame)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

log_text = tk.Text(
    log_frame, bg="#2d2d2d", fg="#ffffff",
    font=("Courier", 9), yscrollcommand=scrollbar.set,
    relief=tk.FLAT, padx=8, pady=4
)
log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
scrollbar.config(command=log_text.yview)

# Text tags for colors
log_text.tag_config("anomaly", foreground="#ff4444")
log_text.tag_config("normal",  foreground="#cccccc")
log_text.tag_config("info",    foreground="#00ff99", font=("Courier", 9, "bold"))

# Stats bar
stats_frame = tk.Frame(root, bg="#141414", pady=5)
stats_frame.pack(fill=tk.X)

stats_label = tk.Label(
    stats_frame, text="No packets captured yet",
    font=("Arial", 10), bg="#141414", fg="#ffcc00"
)
stats_label.pack(side=tk.LEFT, padx=16)

anomaly_label = tk.Label(
    stats_frame, text="⚠  Anomalies Detected: 0",
    font=("Arial", 10, "bold"), bg="#141414", fg="#aaaaaa"
)
anomaly_label.pack(side=tk.RIGHT, padx=16)

root.mainloop()