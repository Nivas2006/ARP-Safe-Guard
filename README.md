# ARP Safe Guard

**ARP Spoofing Intrusion Detection, Defense & Incident Response Suite** for Windows.

ARP Safe Guard watches your local network for ARP spoofing (the technique behind many Man-in-the-Middle attacks). When it detects an attack, it identifies the attacker's MAC address and hardware vendor, takes a webcam snapshot, logs the event, sends alerts, and can generate a PDF incident report.

## Features

- Real-time detection with two engines: a Scapy packet sniffer and an active ARP cache auditor
- Attacker attribution: MAC address, IP, hardware vendor (OUI lookup), hostname
- ARP table integrity view (trusted baseline vs current state)
- Webcam evidence capture, CSV logging, desktop notifications
- Email alerts through SMTP (Gmail App Password)
- Forensic PDF incident report
- Cleartext (HTTP/FTP) credential exposure auditor for demonstrating MITM risk, with masked secrets
- Dark-themed GUI with five tabs

## Requirements

- Windows 10 or 11
- Python 3.10 or newer (3.12 or 3.13 recommended)
- **Npcap** from https://npcap.com. During installation, tick **"Install Npcap in WinPcap API-compatible mode"**
- Administrator rights (needed for packet capture)
- A webcam (optional, for evidence snapshots)

## Installation

1. Unzip the project folder.
2. Open **PowerShell** in that folder and install the packages:

```
python -m pip install -r requirements.txt
```

## Running

Open PowerShell **as Administrator** (right-click, Run as administrator), then:

```
cd "path\to\ARP_Safe_Guard"
python arp_spoofing_detector.py
```

On first launch, a small window asks for the **alert recipient email**. Enter your own address, or cancel to skip.

## Using the app

1. **Dashboard:** click **START REAL-TIME DEFENSE**. The status badge turns green and monitoring begins.
2. **ARP Monitor:** shows the baseline vs current ARP table. Use **Set Current State as Trusted Baseline** only when you know the network is clean.
3. **Attacker Intel:** lists detected attackers and the webcam evidence.
4. **Packet Auditor:** shows unencrypted logins seen on this machine. Secrets are masked by default.
5. **Reports & Settings:** generate the PDF report and configure email alerts.
6. **Flush ARP** (Dashboard) clears poisoned entries after an attack.

## Setting up email alerts (optional)

Email alerts need **your own** Gmail account and an App Password. Do not use your normal Gmail password.

1. Turn on 2-Step Verification for your Google account.
2. Create an App Password at https://myaccount.google.com/apppasswords.
3. In the app, open **Reports & Settings** and enter:
   - Alert recipient email
   - Sender email (your Gmail address)
   - Sender App Password (16 characters, no spaces)
   - SMTP server `smtp.gmail.com` and port `587`
4. Click **Save Settings**, then **Send Test Alert Email**.

Your settings are saved in `config.json` next to the program. Never share that file, because it contains your App Password in plain text.

## Testing safely

Detection can be tried in a lab, for example with a virtual machine on your own network. Use only networks you own or have written permission to test.

## Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError` | Run `python -m pip install -r requirements.txt` with the same Python you use to run the app |
| Sniffer error or no packets | Install Npcap with WinPcap API-compatible mode and run PowerShell as Administrator |
| Window does not open | Run it from PowerShell to see the error. If the app crashes at startup, it writes `startup_error.log` |
| Email says login failed (535) | Create a new App Password and enter it with no spaces |
| Email says connection closed | Check that the sender, App Password and server are correct; try port 465 |
| Many alerts after a router change | The router's MAC changed legitimately. Click **Flush ARP**, then **Set Current State as Trusted Baseline** |

## Project files

```
arp_spoofing_detector.py   Main application (GUI, detection, alerts)
report_generator.py        PDF incident report generator
assets/arp_safeguard.ico   Application icon
requirements.txt           Python dependencies
```

Files created at run time (not included): `config.json`, `arp_alerts.csv`, `intruder_capture.jpg`, `ARP_Incident_Report_*.pdf`.

## Limitations

- Windows only, IPv4 ARP only
- Detects and alerts; it does not automatically block the attacker
- Trusts the ARP table present when the baseline is taken
- Legitimate MAC changes (new router, failover) can cause false alerts until re-baselined
- The cleartext auditor cannot read encrypted (HTTPS) traffic

## Ethical use

Use this tool only on networks you own or are authorised to monitor. It can reveal sensitive information from unencrypted traffic, so keep it to lab and educational use.

## Author

Akarapu Sainivas – Vidya Jyothi Institute of technology – 3rdYear
