import tkinter as tk
from threading import Thread
from capture import start_sniffing, save_log, get_stats

# --- UI Update Function ---
def update_ui(entry):
    log_text.insert(tk.END, 
        f"{entry['src']}  -->  {entry['dst']}  |  {entry['protocol']}\n")
    log_text.see(tk.END)
    
    stats = get_stats()
    stats_label.config(
        text=f"TCP: {stats['TCP']}  |  UDP: {stats['UDP']}  |  Other: {stats['OTHER']}"
    )

# --- Button Functions ---
def start_capture():
    start_btn.config(state=tk.DISABLED, text="Capturing...")
    log_text.insert(tk.END, "--- Capture Started ---\n")
    Thread(target=run_capture).start()

def run_capture():
    start_sniffing(count=100, callback_fn=update_ui)
    log_text.insert(tk.END, "--- Capture Complete ---\n")
    start_btn.config(state=tk.NORMAL, text="Start Capture")

def save_packets():
    save_log()
    log_text.insert(tk.END, "--- Log Saved to packet_log.json ---\n")

def clear_screen():
    log_text.delete(1.0, tk.END)

# --- Build UI ---
root = tk.Tk()
root.title("Network Packet Analyzer")
root.geometry("750x500")
root.configure(bg="#1e1e1e")

# Title
title_label = tk.Label(root, text="Network Packet Analyzer", 
    font=("Arial", 16, "bold"), bg="#1e1e1e", fg="#00ff99")
title_label.pack(pady=10)

# Log display
log_text = tk.Text(root, height=20, width=85, 
    bg="#2d2d2d", fg="#ffffff", font=("Courier", 9))
log_text.pack(padx=10)

# Stats
stats_label = tk.Label(root, text="TCP: 0  |  UDP: 0  |  Other: 0",
    font=("Arial", 11), bg="#1e1e1e", fg="#ffcc00")
stats_label.pack(pady=5)

# Buttons frame
btn_frame = tk.Frame(root, bg="#1e1e1e")
btn_frame.pack(pady=5)

start_btn = tk.Button(btn_frame, text="Start Capture", width=15,
    bg="#00ff99", fg="#000000", font=("Arial", 10, "bold"),
    command=start_capture)
start_btn.grid(row=0, column=0, padx=10)

save_btn = tk.Button(btn_frame, text="Save Log", width=15,
    bg="#4da6ff", fg="#000000", font=("Arial", 10, "bold"),
    command=save_packets)
save_btn.grid(row=0, column=1, padx=10)

clear_btn = tk.Button(btn_frame, text="Clear Screen", width=15,
    bg="#ff6666", fg="#000000", font=("Arial", 10, "bold"),
    command=clear_screen)
clear_btn.grid(row=0, column=2, padx=10)

root.mainloop()