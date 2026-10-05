# ==============================================================================
# ARP Spoofing Intrusion Detection, Defense & Incident Response Suite
# Project Enhancements:
#   1. Complete Cybersecurity GUI with Dark HUD Theme & Tabbed Panels
#   2. Forensic PDF Incident Report Generation (via report_generator.py)
#   3. Continuous Dual-Engine Scanning (Real-Time Passive Sniffer + Active Cache Audit)
#   4. Attacker Attribution & Profiler (Physical MAC, IP, OUI Vendor, Hostname)
#   5. ARP Cache Integrity Tracking (Baseline vs Corrupted Diff)
#   6. Sensitive Protocol & Cleartext Leakage Auditor (Demonstrating MITM Exposure)
#
# CORRECTIONS IN THIS VERSION
#   - Fixed the invisible first-run email dialog (transient() on a withdrawn
#     root hid the dialog and wait_window() blocked forever).
#   - Subprocess calls no longer flash console windows in --noconsole builds.
#   - Sniffer loop restarts cleanly and stops within ~2 seconds.
#   - Duplicate-alert cooldown so the active scanner doesn't spam every 4 s.
#   - Safer SMTP port parsing, admin-rights warning, startup error logging.
# ==============================================================================

import os
import sys
import json
import threading
import csv
import subprocess
import socket
import smtplib
import re
import webbrowser
import traceback
from pathlib import Path
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Third-party dependencies
# Import Scapy objects from their concrete modules. This avoids false
# Pylance "unknown import symbol" warnings caused by Scapy's dynamic exports.
from scapy.sendrecv import sniff
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import TCP
from scapy.packet import Raw
# Import Tkinter names explicitly so static analysis can resolve them.
from tkinter import (
    Tk, Toplevel, Frame, Label, Button, Entry, Text, Scrollbar, Canvas,
    LabelFrame, BOTH, BOTTOM, END, FLAT, LEFT, NW, RIGHT, TOP, VERTICAL,
    W, X, Y, ttk, messagebox, filedialog
)
from PIL import Image, ImageTk
from plyer import notification
import cv2

# Local PDF Forensic Report Generator
try:
    from report_generator import generate_pdf_report
except ImportError:
    generate_pdf_report = None

# === Configuration & State Store ===
# Keep runtime-generated files beside the Python script / EXE instead of
# depending on the current working directory.
if getattr(sys, "frozen", False):
    APP_DIR = Path(sys.executable).resolve().parent
    RESOURCE_DIR = Path(getattr(sys, "_MEIPASS", APP_DIR))
else:
    APP_DIR = Path(__file__).resolve().parent
    RESOURCE_DIR = APP_DIR

# Application branding asset.  When packaged with PyInstaller, this is loaded
# from the bundled resource directory; when running from source, it is loaded
# from the project directory.
ICON_PATH = RESOURCE_DIR / "assets" / "arp_safeguard.ico"

CONFIG_FILE = str(APP_DIR / "config.json")
CSV_LOG_FILE = str(APP_DIR / "arp_alerts.csv")
SNAPSHOT_IMG_FILE = str(APP_DIR / "intruder_capture.jpg")
CRASH_LOG_FILE = str(APP_DIR / "startup_error.log")

# Global Runtime Variables
baseline_arp = {}          # { ip: mac }
current_arp_cache = {}     # { ip: mac }
threats_detected = []      # List of threat dicts
captured_exposures = []    # List of cleartext credential/token leakages
monitoring = False
packet_counter = 0
threat_counter = 0
last_alert_time = {}       # { (ip, mac): datetime } for alert cooldown
ALERT_COOLDOWN_SECONDS = 30

MY_IP = "Unknown"
MY_MAC = "Unknown"
GATEWAY_IP = "Unknown"
GATEWAY_MAC = "Unknown"
RECEIVER_EMAIL = ""

# GUI reference; assigned in __main__ before any background worker starts.
app_window = None

# Built-in OUI Database for Common Network Equipment & Attack Hardware
OUI_DATABASE = {
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi Foundation",
    "e4:5f:01": "Raspberry Pi Foundation",
    "00:0c:29": "VMware Virtual NIC",
    "00:50:56": "VMware Virtual NIC",
    "08:00:27": "Oracle VirtualBox NIC",
    "52:54:00": "QEMU / KVM Virtual NIC",
    "f0:18:98": "Apple, Inc.",
    "3c:22:fb": "Apple, Inc.",
    "a4:83:e7": "Apple, Inc.",
    "70:85:c2": "Intel Corporate",
    "34:97:f6": "Intel Corporate",
    "00:e0:4c": "Realtek Semiconductor",
    "50:3e:aa": "Realtek Semiconductor",
    "50:c7:bf": "TP-Link Technologies",
    "60:38:e0": "TP-Link Technologies",
    "d8:32:14": "Espressif Systems (IoT Device)",
    "84:f3:eb": "Espressif Systems (IoT Device)",
    "00:1a:2b": "Cisco Systems",
    "f4:f5:e8": "Google LLC",
    "00:15:5d": "Microsoft Hyper-V"
}


def lookup_oui_vendor(mac_address):
    """Identifies the hardware vendor based on the IEEE MAC prefix."""
    if not mac_address or len(mac_address) < 8:
        return "Unknown Manufacturer"
    prefix = mac_address[:8].lower()
    return OUI_DATABASE.get(prefix, "Standard Network Device")


# === Helpers ===
def run_command(command):
    """Run a shell command and return its output as text.

    Uses CREATE_NO_WINDOW so --noconsole builds don't flash cmd windows.
    """
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.check_output(
        command, shell=True, creationflags=flags
    ).decode(errors="ignore")


def is_admin():
    """True if the process has administrator rights (needed for sniffing)."""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# === Load / Save Configurations ===
def load_config():
    global RECEIVER_EMAIL
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                data = json.load(f)
                RECEIVER_EMAIL = data.get("receiver_email", "")
                return data
        except Exception as e:
            print(f"[Config Error] {e}")
    return {}


def save_config(config_dict):
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config_dict, f, indent=4)
    except Exception as e:
        print(f"[Config Save Error] {e}")


# === System Network Discovery ===
def get_own_info():
    global MY_IP, MY_MAC, GATEWAY_IP, GATEWAY_MAC
    try:
        output = run_command("ipconfig /all")
        for block in output.split("\n\n"):
            if ("Wireless LAN adapter Wi-Fi" in block or "Ethernet adapter" in block) and "Physical Address" in block:
                for line in block.splitlines():
                    if "IPv4 Address" in line and MY_IP == "Unknown":
                        MY_IP = line.split(":")[1].strip().split("(")[0]
                    if ("Physical Address" in line or "Physical address" in line) and MY_MAC == "Unknown":
                        MY_MAC = line.split(":")[1].strip().lower().replace("-", ":")
                    if "Default Gateway" in line and GATEWAY_IP == "Unknown":
                        parts = line.split(":")
                        if len(parts) > 1 and parts[1].strip():
                            gw = parts[1].strip()
                            if "." in gw:
                                GATEWAY_IP = gw

        # Fallback for IP
        if MY_IP == "Unknown":
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                MY_IP = s.getsockname()[0]
            except Exception:
                MY_IP = "127.0.0.1"
            finally:
                s.close()
    except Exception as e:
        print(f"[Network Info Error] {e}")


# === ARP Baseline Snapshot & Query ===
def _read_arp_table():
    """Parse `arp -a` output into { ip: mac }."""
    table = {}
    output = run_command("arp -a")
    for line in output.splitlines():
        if "-" in line and "." in line:
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[0].strip()
                mac = parts[1].strip().replace("-", ":").lower()
                table[ip] = mac
    return table


def snapshot_baseline():
    """Takes a trusted initial snapshot of the ARP table."""
    global baseline_arp
    baseline_arp.clear()
    try:
        baseline_arp.update(_read_arp_table())
        print(f"[+] Baseline ARP table mapped: {len(baseline_arp)} devices.")
    except Exception as e:
        print(f"[Baseline Error] {e}")


def update_current_arp_cache():
    """Polls the live system ARP cache."""
    global current_arp_cache
    try:
        current_arp_cache = _read_arp_table()
    except Exception as e:
        print(f"[ARP Cache Query Error] {e}")


def flush_arp_cache():
    """Flushes the Windows ARP cache to remove poisoned entries."""
    try:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        subprocess.call("netsh interface ip delete arpcache", shell=True, creationflags=flags)
        snapshot_baseline()
        messagebox.showinfo("ARP Flush", "ARP cache has been successfully flushed and re-baselined.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to flush ARP cache: {e}")


# === Email Dispatch Engine ===
def send_email_alert(attacker_ip, attacker_mac, spoofed_ip, original_mac, spoofed_mac):
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        config = load_config()

        sender_email = config.get("sender_email", "")
        sender_password = config.get("sender_password", "")
        smtp_server = config.get("smtp_server", "smtp.gmail.com")
        smtp_port = int(config.get("smtp_port", 587))
        receiver = config.get("receiver_email", RECEIVER_EMAIL)

        if not (sender_email and sender_password and receiver):
            print("[!] SMTP credentials incomplete in config.json. Skipping email dispatch.")
            return

        subject = "🚨 [CRITICAL ALERT] ARP Spoofing Attack Detected on Your Network"
        body = f"""CYBERSECURITY INCIDENT ALERT: ARP SPOOFING / MITM DETECTED

Timestamp         : {timestamp}
Attacker IP       : {attacker_ip}
Attacker MAC      : {attacker_mac} (Vendor: {lookup_oui_vendor(attacker_mac)})
Target Device     : {MY_IP} ({MY_MAC})

Spoofed Resource  : {spoofed_ip}
Original MAC      : {original_mac}
Poisoned MAC      : {spoofed_mac}

STATUS: Active interception detected. Security defenses triggered.
Inspect attached camera evidence and immediately flush the local ARP cache.
"""
        msg = MIMEMultipart()
        msg["From"] = sender_email
        msg["To"] = receiver
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain", "utf-8"))

        if os.path.exists(SNAPSHOT_IMG_FILE):
            from email.mime.image import MIMEImage
            try:
                with open(SNAPSHOT_IMG_FILE, "rb") as f:
                    img_part = MIMEImage(f.read(), name="attacker_evidence.jpg")
                    msg.attach(img_part)
            except Exception as e:
                print(f"[Email Attachment Error] {e}")

        if smtp_port == 465:
            server = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=20)
        else:
            server = smtplib.SMTP(smtp_server, smtp_port, timeout=20)
            server.ehlo()
            server.starttls()
            server.ehlo()
        server.login(sender_email, sender_password.replace(" ", ""))
        server.sendmail(sender_email, receiver, msg.as_string())
        server.quit()
        print("[+] Forensic alert email dispatched successfully.")
    except Exception as e:
        print(f"[SMTP Send Error] {e}")


# === Central Alert & Incident Response Manager ===
def send_alert(spoofed_ip, original_mac, spoofed_mac, attacker_ip, attacker_mac):
    global threat_counter

    # Cooldown: don't re-alert the same IP/MAC pair repeatedly.
    key = (spoofed_ip, spoofed_mac)
    now = datetime.now()
    last = last_alert_time.get(key)
    if last and (now - last).total_seconds() < ALERT_COOLDOWN_SECONDS:
        return
    last_alert_time[key] = now

    threat_counter += 1
    timestamp = now.strftime("%Y-%m-%d %H:%M:%S")
    vendor = lookup_oui_vendor(attacker_mac)

    # Resolve Attacker Hostname if possible
    try:
        attacker_host = socket.gethostbyaddr(attacker_ip)[0]
    except Exception:
        attacker_host = "Unresolved"

    threat_record = {
        "timestamp": timestamp,
        "spoofed_ip": spoofed_ip,
        "original_mac": original_mac,
        "spoofed_mac": spoofed_mac,
        "attacker_ip": attacker_ip,
        "attacker_mac": attacker_mac,
        "vendor": vendor,
        "hostname": attacker_host
    }
    threats_detected.append(threat_record)

    log_entry = f"🚨 [{timestamp}] ATTACK DETECTED! Spoofed IP: {spoofed_ip} | Attacker MAC: {attacker_mac} ({vendor})"
    print(log_entry)

    # 1. Desktop Notification
    try:
        notify_func = getattr(notification, "notify", None)
        if callable(notify_func):
            notify_func(
                title="🚨 ARP Spoofing Detected!",
                message=f"Spoofing on {spoofed_ip} by MAC {attacker_mac}",
                app_name="ARP Defense Suite",
                timeout=8
            )
    except Exception as e:
        print(f"[Notification Error] {e}")

    # 2. Camera Evidence Capture (OpenCV)
    try:
        cap = cv2.VideoCapture(0)  # type: ignore[reportOptionalCall]
        if cap.isOpened():
            ret, frame = cap.read()
            if ret:
                cv2.imwrite(SNAPSHOT_IMG_FILE, frame)
            cap.release()
    except Exception as e:
        print(f"[Webcam Capture Error] {e}")

    # 3. CSV Forensic Logging
    try:
        file_exists = os.path.exists(CSV_LOG_FILE)
        with open(CSV_LOG_FILE, mode="a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            if not file_exists:
                writer.writerow(["Timestamp", "Spoofed_IP", "Original_MAC", "Spoofed_MAC", "Attacker_IP", "Attacker_MAC", "Vendor", "Hostname"])
            writer.writerow([timestamp, spoofed_ip, original_mac, spoofed_mac, attacker_ip, attacker_mac, vendor, attacker_host])
    except Exception as e:
        print(f"[CSV Log Error] {e}")

    # 4. Asynchronous Email Alert
    threading.Thread(
        target=send_email_alert,
        args=(attacker_ip, attacker_mac, spoofed_ip, original_mac, spoofed_mac),
        daemon=True
    ).start()

    # 5. UI Updates (invoked on main loop)
    if app_window:
        app_window.after(0, lambda: update_threat_ui(threat_record, log_entry))


# === Sensitive Data & Cleartext Exposure Auditor ===
def audit_packet_payload(packet):
    """Passively inspects unencrypted packets to demonstrate data exposure during MITM."""
    if packet.haslayer(Raw) and packet.haslayer(TCP):
        try:
            payload = packet[Raw].load.decode(errors="ignore")
            dport = packet[TCP].dport

            # Check HTTP POST credentials / tokens
            if "POST" in payload or "password=" in payload or "passwd=" in payload or "pwd=" in payload:
                timestamp = datetime.now().strftime("%H:%M:%S")
                service = "HTTP Web Auth"
                user_match = re.search(r'(?:user|username|uname|email|login)=([^&;\s]+)', payload, re.IGNORECASE)
                pass_match = re.search(r'(?:pass|password|passwd|pwd)=([^&;\s]+)', payload, re.IGNORECASE)

                username = user_match.group(1) if user_match else "Unspecified"
                secret = pass_match.group(1) if pass_match else "Token/Data"

                if pass_match or user_match:
                    exposure = {
                        "timestamp": timestamp,
                        "protocol": f"HTTP (Port {dport})",
                        "service": service,
                        "user": username,
                        "value": secret
                    }
                    captured_exposures.append(exposure)
                    if app_window:
                        app_window.after(0, lambda e=exposure: add_exposure_to_ui(e))

            # Check FTP Authentication
            elif "USER " in payload or "PASS " in payload:
                timestamp = datetime.now().strftime("%H:%M:%S")
                cmd = "USER" if "USER " in payload else "PASS"
                val = payload.split(cmd)[1].strip()
                exposure = {
                    "timestamp": timestamp,
                    "protocol": f"FTP (Port {dport})",
                    "service": "File Transfer Protocol",
                    "user": val if cmd == "USER" else "FTP User",
                    "value": val if cmd == "PASS" else "[User Login Initiated]"
                }
                captured_exposures.append(exposure)
                if app_window:
                    app_window.after(0, lambda e=exposure: add_exposure_to_ui(e))
        except Exception:
            pass


# === Packet Sniffer & Processing ===
def process_packet(packet):
    global packet_counter
    if not monitoring:
        return

    packet_counter += 1
    if packet_counter % 10 == 0 and app_window:
        app_window.after(0, update_packet_stats)

    # 1. ARP Spoofing Detection
    if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP Reply
        src_ip = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc.lower()
        ether_mac = packet[Ether].src.lower() if packet.haslayer(Ether) else src_mac
        attacker_ip = packet[ARP].psrc

        if src_ip in baseline_arp:
            real_mac = baseline_arp[src_ip]
            if src_mac != real_mac:
                # Collision detected!
                send_alert(src_ip, real_mac, src_mac, attacker_ip, ether_mac)

    # 2. Cleartext Sensitive Data Inspection
    audit_packet_payload(packet)


def sniffing_worker():
    """Background worker for Scapy live capture.

    Sniffs in short 2-second windows so the loop exits promptly when
    monitoring is switched off, even if the network is quiet.
    """
    try:
        while monitoring:
            sniff(
                filter="arp or tcp port 80 or tcp port 21 or tcp port 23",
                prn=process_packet,
                store=0,
                timeout=2
            )
    except Exception as e:
        msg = (
            f"[Sniffing Worker Error] {e}\n"
            "Make sure Npcap is installed (WinPcap API-compatible mode) "
            "and the app is running as Administrator."
        )
        print(msg)
        win = app_window
        if win:
            win.after(0, lambda: win.append_log(msg, "danger"))


# === Continuous Active ARP Cache Auditor Daemon ===
def continuous_active_scanner():
    """Active background audit daemon that checks system ARP table integrity."""
    while monitoring:
        update_current_arp_cache()
        for ip, curr_mac in list(current_arp_cache.items()):
            if ip in baseline_arp:
                base_mac = baseline_arp[ip]
                if curr_mac != base_mac:
                    send_alert(ip, base_mac, curr_mac, ip, curr_mac)
        threading.Event().wait(4)


# ==============================================================================
# Window Branding
# ==============================================================================
def apply_app_icon(window):
    """Apply the ARP Safe Guard icon to a Tk/Toplevel window."""
    try:
        if ICON_PATH.exists():
            window.iconbitmap(default=str(ICON_PATH))
            window.iconbitmap(str(ICON_PATH))
    except Exception:
        # Icon loading must never prevent the security application from starting.
        pass


def ask_email_with_icon(parent=None):
    """Show the first-run email prompt with the same ARP Safe Guard icon.

    FIX: the dialog is no longer made transient to a withdrawn root window.
    On Windows that made the dialog invisible while wait_window() blocked
    forever, which is why the packaged app seemed to "not open".
    """
    dialog_root = Tk()
    dialog_root.withdraw()
    apply_app_icon(dialog_root)

    dialog = Toplevel(dialog_root)
    dialog.withdraw()  # build off-screen, then show once fully laid out
    dialog.title("Initial Setup")
    dialog.configure(bg="#0B0E14")
    dialog.resizable(False, False)
    apply_app_icon(dialog)

    # Only attach to a parent that is actually visible.
    if parent is not None:
        dialog.transient(parent)

    result = {"value": None}

    frame = Frame(dialog, bg="#151922", padx=20, pady=18)
    frame.pack(fill=BOTH, expand=True)

    Label(
        frame, text="🛡  ARP SAFE GUARD",
        bg="#151922", fg="#38BDF8",
        font=("Segoe UI", 13, "bold")
    ).pack(anchor=W, pady=(0, 12))

    Label(
        frame, text="Enter alert recipient email address:",
        bg="#151922", fg="#E2E8F0",
        font=("Segoe UI", 10)
    ).pack(anchor=W, pady=(0, 7))

    entry = Entry(
        frame, width=42,
        bg="#0B0E14", fg="#E2E8F0",
        insertbackground="#E2E8F0",
        relief=FLAT, font=("Segoe UI", 10)
    )
    entry.pack(fill=X, ipady=7, pady=(0, 16))

    buttons = Frame(frame, bg="#151922")
    buttons.pack(fill=X)

    def finish(value):
        result["value"] = value
        try:
            dialog.grab_release()
        except Exception:
            pass
        dialog.destroy()

    Button(
        buttons, text="Cancel", command=lambda: finish(None),
        bg="#1E2330", fg="#E2E8F0", relief=FLAT,
        padx=16, pady=7, cursor="hand2"
    ).pack(side=RIGHT, padx=(8, 0))

    Button(
        buttons, text="Continue", command=lambda: finish(entry.get().strip()),
        bg="#38BDF8", fg="#081018", relief=FLAT,
        padx=16, pady=7, cursor="hand2"
    ).pack(side=RIGHT)

    dialog.bind("<Return>", lambda event: finish(entry.get().strip()))
    dialog.bind("<Escape>", lambda event: finish(None))
    dialog.protocol("WM_DELETE_WINDOW", lambda: finish(None))

    # Position the dialog, then force it visible and focused.
    dialog.update_idletasks()
    w, h = dialog.winfo_width(), dialog.winfo_height()
    if parent is not None:
        x = parent.winfo_rootx() + (parent.winfo_width() - w) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - h) // 2
    else:
        x = (dialog.winfo_screenwidth() - w) // 2
        y = (dialog.winfo_screenheight() - h) // 2
    dialog.geometry(f"+{max(0, x)}+{max(0, y)}")

    dialog.deiconify()
    dialog.lift()
    dialog.attributes("-topmost", True)
    dialog.after(300, lambda: dialog.attributes("-topmost", False))
    dialog.focus_force()
    entry.focus_set()
    try:
        dialog.wait_visibility()
        dialog.grab_set()
    except Exception:
        pass  # grab is optional; never let it block startup

    dialog_root.wait_window(dialog)
    dialog_root.destroy()
    return result["value"]


# ==============================================================================
# Modern Cybersecurity GUI HUD (Tkinter & TTK)
# ==============================================================================
class CardFrame(Frame):
    """Tkinter Frame with a label reference used by the metric cards."""
    val_lbl: Label


class CybersecurityApp(Tk):
    def __init__(self):
        super().__init__()
        apply_app_icon(self)
        self.title("ARP Sentinel - Network Defense & Forensics")
        self.geometry("1120x740")
        self.minsize(980, 650)
        self.configure(bg="#0B0E14")

        # Color Palette
        self.c_bg = "#0B0E14"
        self.c_panel = "#151922"
        self.c_card = "#1E2330"
        self.c_accent = "#38BDF8"
        self.c_success = "#00FF9D"
        self.c_danger = "#FF4B6E"
        self.c_warning = "#FBBF24"
        self.c_text = "#E2E8F0"
        self.c_muted = "#94A3B8"

        self.mask_secrets = True

        self.apply_styles()
        self.build_ui()
        self.refresh_arp_view()

        if not is_admin():
            self.append_log(
                "[WARNING] Not running as Administrator. Packet sniffing may fail. "
                "Right-click the app and choose 'Run as administrator'.",
                "danger"
            )

    def apply_styles(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        # Clean, compact SOC-style theme.  The application remains Tkinter
        # based so the existing detection/reporting engine is unchanged.
        style.configure(
            "TNotebook",
            background=self.c_bg,
            borderwidth=0,
            tabmargins=[0, 0, 0, 0]
        )
        style.configure(
            "TNotebook.Tab",
            background=self.c_panel,
            foreground=self.c_muted,
            padding=[18, 9],
            font=("Segoe UI", 9, "bold"),
            borderwidth=0
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", self.c_card), ("active", "#242B38")],
            foreground=[("selected", self.c_accent), ("active", self.c_text)]
        )

        style.configure(
            "Treeview",
            background=self.c_panel,
            foreground=self.c_text,
            fieldbackground=self.c_panel,
            rowheight=29,
            font=("Segoe UI", 9),
            borderwidth=0
        )
        style.configure(
            "Treeview.Heading",
            background=self.c_card,
            foreground=self.c_accent,
            font=("Segoe UI", 9, "bold"),
            relief="flat",
            padding=[8, 7]
        )
        style.map(
            "Treeview",
            background=[("selected", "#263448")],
            foreground=[("selected", "#FFFFFF")]
        )

        style.configure(
            "Vertical.TScrollbar",
            background=self.c_card,
            troughcolor=self.c_bg,
            bordercolor=self.c_bg,
            arrowcolor=self.c_muted
        )

    def _button(self, parent, text, command, bg=None, fg=None, **kwargs):
        """Create consistently styled buttons across the application."""
        button = Button(
            parent,
            text=text,
            command=command,
            bg=bg or self.c_card,
            fg=fg or self.c_text,
            activebackground=kwargs.pop("activebackground", "#263448"),
            activeforeground=kwargs.pop("activeforeground", "#FFFFFF"),
            font=kwargs.pop("font", ("Segoe UI", 9, "bold")),
            relief=FLAT,
            bd=0,
            cursor="hand2",
            padx=kwargs.pop("padx", 14),
            pady=kwargs.pop("pady", 7),
            **kwargs
        )
        return button

    def build_ui(self):
        # =========================
        # Premium but simple header
        # =========================
        header = Frame(self, bg=self.c_panel, height=78)
        header.pack(fill=X, side=TOP)
        header.pack_propagate(False)

        title_area = Frame(header, bg=self.c_panel)
        title_area.pack(side=LEFT, padx=22, pady=12)

        Label(
            title_area,
            text="🛡  ARP SENTINEL",
            font=("Segoe UI", 17, "bold"),
            fg=self.c_accent,
            bg=self.c_panel
        ).pack(anchor=W)

        Label(
            title_area,
            text="Network Threat Detection  •  Real-Time Protection  •  Forensic Response",
            font=("Segoe UI", 9),
            fg=self.c_muted,
            bg=self.c_panel
        ).pack(anchor=W, pady=(2, 0))

        header_actions = Frame(header, bg=self.c_panel)
        header_actions.pack(side=RIGHT, padx=20, pady=15)

        self.status_badge = Label(
            header_actions,
            text="●  DEFENSE INACTIVE",
            font=("Segoe UI", 9, "bold"),
            fg=self.c_danger,
            bg="#2A1620",
            padx=13,
            pady=7
        )
        self.status_badge.pack(side=RIGHT, padx=(8, 0))

        self.btn_info = self._button(
            header_actions,
            "ℹ  Project Info",
            self.show_project_info,
            bg=self.c_card,
            fg=self.c_accent,
            padx=12,
            pady=6
        )
        self.btn_info.pack(side=RIGHT)

        # Thin separator
        Frame(self, bg="#252C38", height=1).pack(fill=X)

        # Main notebook
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=BOTH, expand=True, padx=14, pady=(10, 12))

        self.tab_hud = Frame(self.notebook, bg=self.c_bg)
        self.notebook.add(self.tab_hud, text="  📊  Dashboard  ")

        self.tab_attacker = Frame(self.notebook, bg=self.c_bg)
        self.notebook.add(self.tab_attacker, text="  🎯  Attacker Intel  ")

        self.tab_arp = Frame(self.notebook, bg=self.c_bg)
        self.notebook.add(self.tab_arp, text="  📋  ARP Monitor  ")

        self.tab_sniffer = Frame(self.notebook, bg=self.c_bg)
        self.notebook.add(self.tab_sniffer, text="  🔍  Packet Auditor  ")

        self.tab_settings = Frame(self.notebook, bg=self.c_bg)
        self.notebook.add(self.tab_settings, text="  ⚙  Reports & Settings  ")

        self.build_hud_tab()
        self.build_attacker_tab()
        self.build_arp_tab()
        self.build_sniffer_tab()
        self.build_settings_tab()

    # === TAB 1: Live HUD ===
    def build_hud_tab(self):
        # Dashboard heading
        heading = Frame(self.tab_hud, bg=self.c_bg)
        heading.pack(fill=X, padx=12, pady=(8, 4))

        Label(
            heading,
            text="NETWORK SECURITY OVERVIEW",
            font=("Segoe UI", 11, "bold"),
            fg=self.c_text,
            bg=self.c_bg
        ).pack(side=LEFT)

        Label(
            heading,
            text="Continuous ARP monitoring and real-time threat detection",
            font=("Segoe UI", 8),
            fg=self.c_muted,
            bg=self.c_bg
        ).pack(side=LEFT, padx=12)

        # Metrics
        metrics_frame = Frame(self.tab_hud, bg=self.c_bg)
        metrics_frame.pack(fill=X, padx=8, pady=(4, 10))

        cards = [
            ("HOST IP", MY_IP, self.c_accent),
            ("HOST MAC", MY_MAC, self.c_accent),
            ("BASELINE HOSTS", str(len(baseline_arp)), self.c_warning),
            ("PACKETS SCANNED", "0", self.c_success),
            ("THREATS BLOCKED", "0", self.c_danger),
        ]

        card_objects = []
        for title, value, color in cards:
            card = self.create_card(metrics_frame, title, value, color)
            card_objects.append(card)
            card.pack(side=LEFT, fill=BOTH, expand=True, padx=4)

        (self.card_my_ip, self.card_my_mac, self.card_baseline,
         self.card_packets, self.card_threats) = card_objects

        # Protection status panel
        status_panel = Frame(
            self.tab_hud,
            bg=self.c_panel,
            highlightthickness=1,
            highlightbackground="#252C38"
        )
        status_panel.pack(fill=X, padx=12, pady=(0, 9))

        left_status = Frame(status_panel, bg=self.c_panel)
        left_status.pack(side=LEFT, fill=X, expand=True, padx=14, pady=11)

        Label(
            left_status,
            text="REAL-TIME PROTECTION",
            font=("Segoe UI", 9, "bold"),
            fg=self.c_muted,
            bg=self.c_panel
        ).pack(anchor=W)

        self.protection_text = Label(
            left_status,
            text="Monitoring engine is ready",
            font=("Segoe UI", 10, "bold"),
            fg=self.c_text,
            bg=self.c_panel
        )
        self.protection_text.pack(anchor=W, pady=(3, 0))

        self.engine_status = Label(
            left_status,
            text="● Passive Sniffer     ● ARP Cache Audit     ● Threat Logging",
            font=("Segoe UI", 8),
            fg=self.c_muted,
            bg=self.c_panel
        )
        self.engine_status.pack(anchor=W, pady=(4, 0))

        # Main controls
        controls = Frame(status_panel, bg=self.c_panel)
        controls.pack(side=RIGHT, padx=12, pady=12)

        self.btn_toggle = self._button(
            controls,
            "▶  START REAL-TIME DEFENSE",
            self.toggle_monitoring,
            bg=self.c_success,
            fg="#06130E",
            activebackground="#21C98A",
            padx=16,
            pady=8
        )
        self.btn_toggle.pack(side=LEFT, padx=4)

        self._button(
            controls,
            "🧹 Flush ARP",
            flush_arp_cache,
            bg=self.c_card,
            fg=self.c_text,
            padx=12,
            pady=8
        ).pack(side=LEFT, padx=4)

        self._button(
            controls,
            "📄 Generate PDF",
            self.trigger_report_gen,
            bg="#1677A8",
            fg="#FFFFFF",
            activebackground="#208CBF",
            padx=12,
            pady=8
        ).pack(side=LEFT, padx=4)

        # Event log
        log_panel = Frame(
            self.tab_hud,
            bg=self.c_panel,
            highlightthickness=1,
            highlightbackground="#252C38"
        )
        log_panel.pack(fill=BOTH, expand=True, padx=12, pady=(0, 10))

        log_header = Frame(log_panel, bg=self.c_panel)
        log_header.pack(fill=X, padx=12, pady=(9, 5))

        Label(
            log_header,
            text="LIVE EVENT LOG",
            font=("Segoe UI", 9, "bold"),
            fg=self.c_text,
            bg=self.c_panel
        ).pack(side=LEFT)

        Label(
            log_header,
            text="SYSTEM / ARP / THREAT EVENTS",
            font=("Segoe UI", 8),
            fg=self.c_muted,
            bg=self.c_panel
        ).pack(side=LEFT, padx=10)

        self._button(
            log_header,
            "Clear",
            self.clear_logs,
            bg=self.c_card,
            fg=self.c_muted,
            font=("Segoe UI", 8, "bold"),
            padx=10,
            pady=4
        ).pack(side=RIGHT)

        log_body = Frame(log_panel, bg=self.c_panel)
        log_body.pack(fill=BOTH, expand=True, padx=10, pady=(0, 10))

        scroll = Scrollbar(
            log_body,
            orient=VERTICAL,
            bg=self.c_card,
            troughcolor=self.c_panel,
            activebackground=self.c_accent
        )
        scroll.pack(side=RIGHT, fill=Y)

        self.log_box = Text(
            log_body,
            bg="#11161F",
            fg=self.c_text,
            font=("Consolas", 9),
            yscrollcommand=scroll.set,
            relief=FLAT,
            bd=0,
            padx=12,
            pady=10,
            insertbackground=self.c_text
        )
        self.log_box.pack(fill=BOTH, expand=True)
        scroll.config(command=self.log_box.yview)

        self.log_box.tag_config(
            "danger",
            foreground=self.c_danger,
            font=("Consolas", 9, "bold")
        )
        self.log_box.tag_config("success", foreground=self.c_success)
        self.log_box.tag_config("info", foreground=self.c_accent)

    def create_card(self, parent, title, val, color):
        card = CardFrame(
            parent,
            bg=self.c_card,
            padx=13,
            pady=11,
            relief=FLAT,
            highlightthickness=1,
            highlightbackground="#293241"
        )

        Label(
            card,
            text=title,
            font=("Segoe UI", 8, "bold"),
            fg=self.c_muted,
            bg=self.c_card
        ).pack(anchor=W)

        val_lbl = Label(
            card,
            text=val,
            font=("Consolas", 13, "bold"),
            fg=color,
            bg=self.c_card
        )
        val_lbl.pack(anchor=W, pady=(5, 0))
        card.val_lbl = val_lbl

        return card

    # === TAB 2: Attacker Dossier ===
    def build_attacker_tab(self):
        content = Frame(self.tab_attacker, bg=self.c_bg)
        content.pack(fill=BOTH, expand=True, padx=10, pady=10)

        # Left Column: Attacker Table
        left_frame = Frame(content, bg=self.c_panel)
        left_frame.pack(side=LEFT, fill=BOTH, expand=True, padx=(0, 6))

        Label(left_frame, text="IDENTIFIED INTRUDERS & ATTACKER SIGNATURES",
              font=("Helvetica", 10, "bold"), fg=self.c_danger, bg=self.c_panel, padx=8, pady=8).pack(anchor=W)

        cols = ("time", "ip", "mac", "vendor", "spoofed")
        self.attacker_tree = ttk.Treeview(left_frame, columns=cols, show="headings", height=12)
        self.attacker_tree.heading("time", text="Timestamp")
        self.attacker_tree.heading("ip", text="Attacker IP")
        self.attacker_tree.heading("mac", text="Physical MAC")
        self.attacker_tree.heading("vendor", text="Hardware Manufacturer")
        self.attacker_tree.heading("spoofed", text="Spoofed IP")

        self.attacker_tree.column("time", width=120)
        self.attacker_tree.column("ip", width=110)
        self.attacker_tree.column("mac", width=130)
        self.attacker_tree.column("vendor", width=160)
        self.attacker_tree.column("spoofed", width=110)
        self.attacker_tree.pack(fill=BOTH, expand=True, padx=8, pady=8)

        # Right Column: Camera Snapshot Evidence
        right_frame = Frame(content, bg=self.c_card, width=280)
        right_frame.pack(side=RIGHT, fill=Y, padx=(6, 0))

        Label(right_frame, text="INTRUDER WEBCAM EVIDENCE", font=("Helvetica", 9, "bold"),
              fg=self.c_accent, bg=self.c_card, pady=10).pack()

        self.img_label = Label(right_frame, text="[No Snapshot Captured]",
                               bg=self.c_panel, fg=self.c_muted, width=32, height=14)
        self.img_label.pack(padx=12, pady=10)

        Button(right_frame, text="📸 Manual Photo Capture", command=self.manual_snapshot,
               bg=self.c_panel, fg=self.c_text, font=("Segoe UI", 9), relief=FLAT).pack(pady=6)

    # === TAB 3: ARP Cache Integrity ===
    def build_arp_tab(self):
        ctrl = Frame(self.tab_arp, bg=self.c_bg)
        ctrl.pack(fill=X, padx=10, pady=8)

        Button(ctrl, text="🔄 Refresh & Rescan ARP Table", command=self.refresh_arp_view,
               bg=self.c_accent, fg="#000", font=("Helvetica", 9, "bold"),
               padx=14, pady=6, relief=FLAT, cursor="hand2").pack(side=LEFT)

        Button(ctrl, text="📌 Set Current State as Trusted Baseline", command=self.rebaseline,
               bg=self.c_card, fg=self.c_text, font=("Segoe UI", 9),
               padx=14, pady=6, relief=FLAT, cursor="hand2").pack(side=LEFT, padx=8)

        tree_frame = Frame(self.tab_arp, bg=self.c_panel)
        tree_frame.pack(fill=BOTH, expand=True, padx=10, pady=(0, 10))

        cols = ("ip", "base_mac", "curr_mac", "vendor", "status")
        self.arp_tree = ttk.Treeview(tree_frame, columns=cols, show="headings")
        self.arp_tree.heading("ip", text="IP Address")
        self.arp_tree.heading("base_mac", text="Baseline MAC")
        self.arp_tree.heading("curr_mac", text="Current MAC")
        self.arp_tree.heading("vendor", text="Hardware Vendor")
        self.arp_tree.heading("status", text="Integrity State")

        self.arp_tree.column("ip", width=120)
        self.arp_tree.column("base_mac", width=140)
        self.arp_tree.column("curr_mac", width=140)
        self.arp_tree.column("vendor", width=160)
        self.arp_tree.column("status", width=120)
        self.arp_tree.pack(fill=BOTH, expand=True, padx=8, pady=8)

    # === TAB 4: Cleartext Protocol Auditor ===
    def build_sniffer_tab(self):
        top = Frame(self.tab_sniffer, bg=self.c_bg)
        top.pack(fill=X, padx=10, pady=8)

        Label(top, text="UNENCRYPTED PROTOCOL EXPOSURE AUDITOR (MITM EVIDENCE)",
              font=("Helvetica", 10, "bold"), fg=self.c_warning, bg=self.c_bg).pack(side=LEFT)

        self.btn_mask = Button(top, text="👁️ Toggle Password Masking", command=self.toggle_mask,
                               bg=self.c_card, fg=self.c_text, font=("Segoe UI", 9),
                               padx=10, pady=4, relief=FLAT, cursor="hand2")
        self.btn_mask.pack(side=RIGHT)

        frame = Frame(self.tab_sniffer, bg=self.c_panel)
        frame.pack(fill=BOTH, expand=True, padx=10, pady=(0, 10))

        cols = ("time", "proto", "service", "user", "secret")
        self.sniff_tree = ttk.Treeview(frame, columns=cols, show="headings")
        self.sniff_tree.heading("time", text="Timestamp")
        self.sniff_tree.heading("proto", text="Protocol")
        self.sniff_tree.heading("service", text="Service / Port")
        self.sniff_tree.heading("user", text="Account Identifier")
        self.sniff_tree.heading("secret", text="Captured Secret / Token")

        self.sniff_tree.column("time", width=100)
        self.sniff_tree.column("proto", width=110)
        self.sniff_tree.column("service", width=160)
        self.sniff_tree.column("user", width=140)
        self.sniff_tree.column("secret", width=220)
        self.sniff_tree.pack(fill=BOTH, expand=True, padx=8, pady=8)

    # === TAB 5: Settings & Report Export ===
    def build_settings_tab(self):
        container = Frame(self.tab_settings, bg=self.c_bg)
        container.pack(fill=BOTH, expand=True, padx=20, pady=16)

        # PDF Report Section
        rep_box = LabelFrame(container, text="📄 Forensic Incident PDF Report",
                             font=("Helvetica", 11, "bold"), fg=self.c_accent, bg=self.c_panel, padx=16, pady=14)
        rep_box.pack(fill=X, pady=(0, 15))

        Label(rep_box, text="Generate a formal, publication-ready Cybersecurity Forensic Report documenting all detected ARP anomalies, attacker attribution profiles, ARP table diffs, and intercepted credentials.",
              font=("Segoe UI", 9), fg=self.c_muted, bg=self.c_panel, wraplength=800, justify=LEFT).pack(anchor=W, pady=(0, 10))

        Button(rep_box, text="⚡ Generate & Open Forensic Report Now", command=self.trigger_report_gen,
               bg=self.c_accent, fg="#000", font=("Helvetica", 10, "bold"), padx=16, pady=8, relief=FLAT, cursor="hand2").pack(anchor=W)

        # SMTP Setup Section
        smtp_box = LabelFrame(container, text="✉️ Automated Email Alert Configuration (SMTP)",
                              font=("Helvetica", 11, "bold"), fg=self.c_accent, bg=self.c_panel, padx=16, pady=14)
        smtp_box.pack(fill=X)

        cfg = load_config()

        grid_frame = Frame(smtp_box, bg=self.c_panel)
        grid_frame.pack(fill=X, pady=8)

        Label(grid_frame, text="Alert Recipient Email:", font=("Segoe UI", 9), fg=self.c_text, bg=self.c_panel).grid(row=0, column=0, sticky=W, pady=4)
        self.ent_receiver = Entry(grid_frame, width=36, font=("Consolas", 9), bg=self.c_card, fg=self.c_text, insertbackground="#fff")
        self.ent_receiver.grid(row=0, column=1, sticky=W, padx=10, pady=4)
        self.ent_receiver.insert(0, cfg.get("receiver_email", RECEIVER_EMAIL))

        Label(grid_frame, text="Sender Email (Gmail):", font=("Segoe UI", 9), fg=self.c_text, bg=self.c_panel).grid(row=1, column=0, sticky=W, pady=4)
        self.ent_sender = Entry(grid_frame, width=36, font=("Consolas", 9), bg=self.c_card, fg=self.c_text, insertbackground="#fff")
        self.ent_sender.grid(row=1, column=1, sticky=W, padx=10, pady=4)
        self.ent_sender.insert(0, cfg.get("sender_email", ""))

        Label(grid_frame, text="Sender App Password:", font=("Segoe UI", 9), fg=self.c_text, bg=self.c_panel).grid(row=2, column=0, sticky=W, pady=4)
        self.ent_password = Entry(grid_frame, width=36, show="*", font=("Consolas", 9), bg=self.c_card, fg=self.c_text, insertbackground="#fff")
        self.ent_password.grid(row=2, column=1, sticky=W, padx=10, pady=4)
        self.ent_password.insert(0, cfg.get("sender_password", ""))

        Label(grid_frame, text="SMTP Server & Port:", font=("Segoe UI", 9), fg=self.c_text, bg=self.c_panel).grid(row=3, column=0, sticky=W, pady=4)
        srv_frame = Frame(grid_frame, bg=self.c_panel)
        srv_frame.grid(row=3, column=1, sticky=W, padx=10, pady=4)
        self.ent_server = Entry(srv_frame, width=22, font=("Consolas", 9), bg=self.c_card, fg=self.c_text, insertbackground="#fff")
        self.ent_server.pack(side=LEFT)
        self.ent_server.insert(0, cfg.get("smtp_server", "smtp.gmail.com"))
        self.ent_port = Entry(srv_frame, width=8, font=("Consolas", 9), bg=self.c_card, fg=self.c_text, insertbackground="#fff")
        self.ent_port.pack(side=LEFT, padx=6)
        self.ent_port.insert(0, str(cfg.get("smtp_port", 587)))

        btn_row = Frame(smtp_box, bg=self.c_panel)
        btn_row.pack(fill=X, pady=(10, 0))

        Button(btn_row, text="💾 Save Settings", command=self.save_smtp_settings,
               bg=self.c_success, fg="#000", font=("Helvetica", 9, "bold"), padx=12, pady=6, relief=FLAT, cursor="hand2").pack(side=LEFT)

        Button(btn_row, text="🧪 Send Test Alert Email", command=self.test_email,
               bg=self.c_card, fg=self.c_text, font=("Segoe UI", 9), padx=12, pady=6, relief=FLAT, cursor="hand2").pack(side=LEFT, padx=8)

        # Project Information Section
        info_box = LabelFrame(container, text="ℹ️ System & Project Architecture",
                              font=("Helvetica", 11, "bold"), fg=self.c_accent, bg=self.c_panel, padx=16, pady=14)
        info_box.pack(fill=X, pady=(15, 0))

        Label(info_box, text="ARP Spoofing Intrusion Detection, Defense & Forensic Incident Response Suite.\nReview full architectural specifications, dual-engine detection modules, attribution models, and threat mitigation systems.",
              font=("Segoe UI", 9), fg=self.c_muted, bg=self.c_panel, justify=LEFT).pack(anchor=W, pady=(0, 10))

        Button(info_box, text="📖 View Full Project Specifications & Architecture", command=self.show_project_info,
               bg=self.c_card, fg=self.c_accent, font=("Helvetica", 9, "bold"), padx=14, pady=6, relief=FLAT, cursor="hand2").pack(anchor=W)

    # === Handlers & Actions ===
    def toggle_monitoring(self):
        global monitoring
        if not monitoring:
            monitoring = True
            self.status_badge.config(text="●  PROTECTED", fg=self.c_success, bg="#102A1E")
            self.btn_toggle.config(text="⏹  STOP PROTECTION", bg=self.c_danger, fg="#FFF")
            self.protection_text.config(text="Real-time protection is active")
            self.engine_status.config(
                text="● Passive Sniffer ACTIVE     ● ARP Cache Audit ACTIVE     ● Threat Logging ACTIVE",
                fg=self.c_success
            )
            self.append_log("[SYSTEM] Real-time defense engine activated. Scapy sniffer & active audit running.", "success")
            threading.Thread(target=sniffing_worker, daemon=True).start()
            threading.Thread(target=continuous_active_scanner, daemon=True).start()
        else:
            monitoring = False
            self.status_badge.config(text="●  DEFENSE INACTIVE", fg=self.c_danger, bg="#2A1620")
            self.btn_toggle.config(text="▶  START REAL-TIME DEFENSE", bg=self.c_success, fg="#000")
            self.protection_text.config(text="Monitoring engine is ready")
            self.engine_status.config(
                text="● Passive Sniffer     ● ARP Cache Audit     ● Threat Logging",
                fg=self.c_muted
            )
            self.append_log("[SYSTEM] Protection stopped.", "info")

    def append_log(self, text, tag="info"):
        self.log_box.insert(END, text + "\n", tag)
        self.log_box.see(END)

    def clear_logs(self):
        self.log_box.delete("1.0", END)

    def refresh_arp_view(self):
        update_current_arp_cache()
        for item in self.arp_tree.get_children():
            self.arp_tree.delete(item)

        all_ips = sorted(set(list(baseline_arp.keys()) + list(current_arp_cache.keys())))
        for ip in all_ips:
            base = baseline_arp.get(ip, "Not in Baseline")
            curr = current_arp_cache.get(ip, "Not Present")
            vendor = lookup_oui_vendor(curr if curr != "Not Present" else base)

            if base != "Not in Baseline" and curr != "Not Present":
                status = "CLEAN / MATCH" if base.lower() == curr.lower() else "POISONED / MISMATCH"
            elif base == "Not in Baseline":
                status = "NEW HOST"
            else:
                status = "OFFLINE"

            self.arp_tree.insert("", END, values=(ip, base, curr, vendor, status))

        self.card_baseline.val_lbl.config(text=str(len(baseline_arp)))

    def rebaseline(self):
        snapshot_baseline()
        self.refresh_arp_view()
        self.append_log("[SYSTEM] Trusted baseline re-established from current ARP entries.", "success")

    def toggle_mask(self):
        self.mask_secrets = not self.mask_secrets
        for item in self.sniff_tree.get_children():
            self.sniff_tree.delete(item)
        for exp in captured_exposures:
            self.add_exposure_row(exp)

    def add_exposure_row(self, exp):
        val = exp.get("value", "")
        if self.mask_secrets and len(val) > 4:
            masked = val[:2] + ("*" * (len(val) - 4)) + val[-2:]
        elif self.mask_secrets:
            masked = "***"
        else:
            masked = val
        self.sniff_tree.insert("", END, values=(
            exp.get("timestamp"),
            exp.get("protocol"),
            exp.get("service"),
            exp.get("user"),
            masked
        ))

    def manual_snapshot(self):
        try:
            cap = cv2.VideoCapture(0)  # type: ignore[reportOptionalCall]
            if cap.isOpened():
                ret, frame = cap.read()
                if ret:
                    cv2.imwrite(SNAPSHOT_IMG_FILE, frame)
                    self.update_preview_image()
                    self.append_log("[CAMERA] Snapshot captured and saved.", "info")
                cap.release()
            else:
                messagebox.showwarning("Webcam", "No camera was found or it is in use.")
        except Exception as e:
            messagebox.showerror("Webcam Error", f"Could not access camera: {e}")

    def update_preview_image(self):
        if os.path.exists(SNAPSHOT_IMG_FILE):
            try:
                img = Image.open(SNAPSHOT_IMG_FILE)
                img = img.resize((240, 160), Image.Resampling.LANCZOS)
                photo = ImageTk.PhotoImage(img)
                self.img_label.config(image=photo, text="")
                setattr(self.img_label, "image", photo)
            except Exception as e:
                print(f"[Preview Error] {e}")

    def trigger_report_gen(self):
        update_current_arp_cache()
        # Save reports beside the app, not in whatever the working dir is.
        filename = str(APP_DIR / f"ARP_Incident_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
        victim_info = {
            "ip": MY_IP,
            "mac": MY_MAC,
            "gateway_ip": GATEWAY_IP
        }
        try:
            if generate_pdf_report:
                saved_file = generate_pdf_report(
                    filename, victim_info, threats_detected,
                    baseline_arp, current_arp_cache, captured_exposures,
                    SNAPSHOT_IMG_FILE if os.path.exists(SNAPSHOT_IMG_FILE) else None
                )
                self.append_log(f"[REPORT] Forensic incident report successfully generated: {saved_file}", "success")
                messagebox.showinfo("Report Ready", f"Forensic incident report successfully generated:\n{saved_file}")
                try:
                    os.startfile(os.path.abspath(saved_file))  # type: ignore[attr-defined]
                except Exception:
                    webbrowser.open(os.path.abspath(saved_file))
            else:
                messagebox.showerror("Error", "Report generator module is unavailable.")
        except Exception as e:
            messagebox.showerror("Report Error", f"Failed to generate report: {e}")

    def save_smtp_settings(self):
        global RECEIVER_EMAIL
        RECEIVER_EMAIL = self.ent_receiver.get().strip()
        try:
            port = int(self.ent_port.get().strip() or 587)
        except ValueError:
            messagebox.showerror("Invalid Port", "SMTP port must be a number (e.g. 587).")
            return
        cfg = {
            "receiver_email": RECEIVER_EMAIL,
            "sender_email": self.ent_sender.get().strip(),
            "sender_password": self.ent_password.get().strip(),
            "smtp_server": self.ent_server.get().strip(),
            "smtp_port": port
        }
        save_config(cfg)
        messagebox.showinfo("Saved", "SMTP & Alert configurations successfully updated.")
        self.append_log("[CONFIG] SMTP alert settings saved.", "info")

    def test_email(self):
        threading.Thread(
            target=send_email_alert,
            args=("192.168.1.250", "aa:bb:cc:dd:ee:ff", "192.168.1.1", "00:11:22:33:44:55", "aa:bb:cc:dd:ee:ff"),
            daemon=True
        ).start()
        messagebox.showinfo("Test Dispatched", "Test alert email dispatched in the background. Check your inbox.")

    def show_project_info(self):
        """Displays a dedicated Dark Cybersecurity HUD modal dialog with comprehensive project specifications."""
        info_win = Toplevel(self)
        apply_app_icon(info_win)
        info_win.title("ℹ️ Project Architecture & Specifications")
        info_win.configure(bg=self.c_bg)
        info_win.transient(self)

        # Geometry & Centering
        win_w, win_h = 780, 640
        self.update_idletasks()
        pos_x = max(0, self.winfo_x() + (self.winfo_width() // 2) - (win_w // 2))
        pos_y = max(0, self.winfo_y() + (self.winfo_height() // 2) - (win_h // 2))
        info_win.geometry(f"{win_w}x{win_h}+{pos_x}+{pos_y}")
        info_win.minsize(680, 520)

        # Header Banner
        header = Frame(info_win, bg=self.c_panel, height=64)
        header.pack(fill=X, side=TOP)

        title_col = Frame(header, bg=self.c_panel)
        title_col.pack(side=LEFT, padx=18, pady=10)

        Label(title_col, text="🛡️ ARP SPOOFING DEFENSE & FORENSICS SUITE",
              font=("Helvetica", 13, "bold"), fg=self.c_accent, bg=self.c_panel).pack(anchor=W)
        Label(title_col, text="Intrusion Detection, Threat Attribution & Forensic Incident Response",
              font=("Segoe UI", 9), fg=self.c_muted, bg=self.c_panel).pack(anchor=W)

        badge_col = Frame(header, bg=self.c_panel)
        badge_col.pack(side=RIGHT, padx=18, pady=12)

        Label(badge_col, text="v2.0 SOC EDITION", font=("Helvetica", 9, "bold"),
              fg=self.c_success, bg="#102A1E", padx=10, pady=4, relief=FLAT).pack()

        # Bottom Controls
        footer = Frame(info_win, bg=self.c_panel, height=52)
        footer.pack(fill=X, side=BOTTOM)

        Button(footer, text="✖ Close", command=info_win.destroy,
               bg=self.c_card, fg=self.c_text, font=("Helvetica", 9, "bold"),
               padx=18, pady=6, relief=FLAT, cursor="hand2").pack(side=RIGHT, padx=16, pady=10)

        Button(footer, text="📄 Generate Incident Report", command=self.trigger_report_gen,
               bg=self.c_accent, fg="#000", font=("Helvetica", 9, "bold"),
               padx=14, pady=6, relief=FLAT, cursor="hand2").pack(side=LEFT, padx=16, pady=10)

        # Scrollable Content Area
        body = Frame(info_win, bg=self.c_bg)
        body.pack(fill=BOTH, expand=True, padx=16, pady=(10, 6))

        canvas = Canvas(body, bg=self.c_bg, highlightthickness=0)
        scrollbar = ttk.Scrollbar(body, orient=VERTICAL, command=canvas.yview)
        content_frame = Frame(canvas, bg=self.c_bg)

        content_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas_win = canvas.create_window((0, 0), window=content_frame, anchor="nw")

        def _on_canvas_resize(event):
            canvas.itemconfig(canvas_win, width=event.width)

        canvas.bind("<Configure>", _on_canvas_resize)
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill=Y)

        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        info_win.bind("<MouseWheel>", _on_mousewheel)

        # Helper to construct cyber HUD info cards
        def make_card(parent, title, icon, color, items):
            card = Frame(parent, bg=self.c_card, padx=14, pady=12)
            card.pack(fill=X, pady=(0, 10))

            card_hdr = Frame(card, bg=self.c_card)
            card_hdr.pack(fill=X, pady=(0, 8))

            Label(card_hdr, text=f"{icon}  {title}", font=("Helvetica", 10, "bold"),
                  fg=color, bg=self.c_card).pack(side=LEFT)

            for key, val in items:
                row = Frame(card, bg=self.c_card)
                row.pack(fill=X, pady=3)
                Label(row, text=f"• {key}:", font=("Helvetica", 9, "bold"),
                      fg=self.c_text, bg=self.c_card, width=22, anchor=W).pack(side=LEFT, anchor=NW)
                Label(row, text=val, font=("Segoe UI", 9),
                      fg=self.c_muted, bg=self.c_card, wraplength=480, justify=LEFT).pack(side=LEFT, fill=X, expand=True, anchor=NW)
            return card

        # Card 1: Project Overview
        make_card(
            content_frame,
            "PROJECT OVERVIEW & EXECUTIVE SUMMARY",
            "📋",
            self.c_accent,
            [
                ("Project Name", "ARP Spoofing Intrusion Detection, Defense & Incident Response Suite"),
                ("Domain", "Data Link Layer (Layer 2) Security, Threat Hunting & Digital Forensics"),
                ("Primary Mission", "Detect, trace, alert, and mitigate Address Resolution Protocol (ARP) poisoning, Man-in-the-Middle (MITM) hijacking, and credential eavesdropping in local area networks."),
                ("Core Strategy", "Combines real-time passive packet sniffing with continuous active ARP cache differential analysis, biometric intruder capture, and instant automated mitigation.")
            ]
        )

        # Card 2: Detection Engines & Modules
        make_card(
            content_frame,
            "CORE DETECTION & DEFENSE ENGINES",
            "⚙️",
            self.c_warning,
            [
                ("Dual-Engine Scanning", "Asynchronously combines Scapy raw packet sniffing with an active OS ARP cache polling daemon to catch both wire-level floods and stealth poisoning."),
                ("Attacker Attribution", "Dissects attacker MAC addresses against an integrated IEEE OUI database (Raspberry Pi, VMware, Cisco, Intel, Realtek, Apple, etc.) and resolves hostnames."),
                ("Credential Leakage Auditor", "Deep Packet Inspection (DPI) auditing unencrypted protocols (HTTP, FTP, Telnet, POP3, IMAP, SMTP) to capture and document exposed auth secrets."),
                ("Biometric Evidence Capture", "Automatically activates local camera upon verified threat to record visual evidence of physical console intruders."),
                ("Active Cache Purging", "One-click and automated Windows ARP table purging ('netsh interface ip delete arpcache') and dynamic re-baselining for instant threat containment.")
            ]
        )

        # Card 3: Forensics, Reporting & Alerting
        make_card(
            content_frame,
            "DIGITAL FORENSICS, ALERTING & MITIGATION",
            "📄",
            self.c_success,
            [
                ("Forensic PDF Report", "Automated publication-ready incident reports compiled via ReportLab (with HTML fallback) containing attack timelines, attacker profiles, and ARP diffs."),
                ("Multi-Channel Alerts", "Instant desktop notifications via Plyer and automated SMTP emails with attached intruder photographic evidence."),
                ("Telemetry HUD", "Real-time color-coded incident logs, threat counters, packet telemetry, and interactive intruder dossier table.")
            ]
        )

        # Card 4: Technology Stack
        make_card(
            content_frame,
            "TECHNOLOGY STACK & DEPENDENCIES",
            "💻",
            "#A78BFA",
            [
                ("Core Language", "Python 3.x with concurrent threading architecture"),
                ("Packet Analysis", "Scapy (sniff, ARP, Ether, IP, TCP, Raw)"),
                ("User Interface", "Tkinter & TTK with custom Dark Cyber HUD styling"),
                ("Forensics & Documents", "ReportLab PDF Engine & Responsive HTML5/CSS3 fallback"),
                ("Computer Vision", "OpenCV (cv2) & Pillow (PIL)"),
                ("System Integration", "Windows Sockets, Subprocess (netsh, ipconfig, arp), SMTPlib, Plyer")
            ]
        )

        # Card 5: Current Runtime Telemetry
        engine_state = "RUNNING / ACTIVE DEFENSE" if monitoring else "STANDBY / DEFENSE INACTIVE"
        status_color = self.c_success if monitoring else self.c_danger
        make_card(
            content_frame,
            "ACTIVE SYSTEM & NETWORK RUNTIME TELEMETRY",
            "🌐",
            status_color,
            [
                ("Host Profile", f"IP: {MY_IP}  |  MAC: {MY_MAC}"),
                ("Default Gateway", f"IP: {GATEWAY_IP}"),
                ("Baseline Hosts", f"{len(baseline_arp)} trusted endpoints recorded in baseline table"),
                ("Threats Counter", f"{threat_counter} malicious spoofing events intercepted"),
                ("Engine Status", engine_state)
            ]
        )


# === Bridge Functions between Backend & GUI ===
def update_threat_ui(threat, log_entry):
    if app_window:
        app_window.append_log(log_entry, "danger")
        app_window.card_threats.val_lbl.config(text=str(threat_counter))
        app_window.attacker_tree.insert("", 0, values=(
            threat.get("timestamp"),
            threat.get("attacker_ip"),
            threat.get("attacker_mac"),
            threat.get("vendor"),
            threat.get("spoofed_ip")
        ))
        app_window.update_preview_image()


def add_exposure_to_ui(exposure):
    if app_window:
        app_window.add_exposure_row(exposure)
        app_window.append_log(f"⚠️ [EXPOSURE] Insecure {exposure.get('protocol')} auth transmission captured: User '{exposure.get('user')}'", "danger")


def update_packet_stats():
    if app_window:
        app_window.card_packets.val_lbl.config(text=str(packet_counter))


# === Main Entry Point ===
def main():
    global app_window, RECEIVER_EMAIL

    # 1. Discover local host network profile
    get_own_info()

    # 2. Establish trusted initial ARP baseline
    snapshot_baseline()

    # 3. Load configuration or prompt for email
    config_dict = load_config()
    if not RECEIVER_EMAIL:
        # Prompt user once on first run
        prompted_email = ask_email_with_icon()
        if prompted_email:
            RECEIVER_EMAIL = prompted_email.strip()
            config_dict["receiver_email"] = RECEIVER_EMAIL
            save_config(config_dict)

    # 4. Launch GUI Application
    app_window = CybersecurityApp()
    app_window.mainloop()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Windowed (--noconsole) builds hide tracebacks, so write them to a file.
        err = traceback.format_exc()
        print(err)
        try:
            with open(CRASH_LOG_FILE, "w", encoding="utf-8") as f:
                f.write(err)
        except Exception:
            pass
        try:
            messagebox.showerror(
                "ARP Safe Guard - Startup Error",
                f"The application failed to start.\n\nDetails saved to:\n{CRASH_LOG_FILE}\n\n{err[-600:]}"
            )
        except Exception:
            pass
        sys.exit(1)