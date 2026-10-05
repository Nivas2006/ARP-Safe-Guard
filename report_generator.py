# ==============================================================================
# Cybersecurity Forensics & Incident Response: PDF Report Generator Module
# Generates detailed security assessment & incident documentation
# ==============================================================================

import os
from datetime import datetime

def generate_pdf_report(
    report_filename,
    victim_info,
    threats_detected,
    arp_baseline,
    current_arp,
    captured_exposures,
    snapshot_image=None
):
    """
    Compiles a comprehensive Cybersecurity Incident & ARP Spoofing Forensic Report.
    Uses ReportLab if installed; otherwise generates an interactive HTML incident report.
    """
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, HRFlowable
        )
        return _generate_reportlab_pdf(
            report_filename, victim_info, threats_detected,
            arp_baseline, current_arp, captured_exposures, snapshot_image
        )
    except ImportError:
        # Graceful fallback: generate an elegant HTML forensic report
        html_filename = os.path.splitext(report_filename)[0] + ".html"
        return _generate_html_report(
            html_filename, victim_info, threats_detected,
            arp_baseline, current_arp, captured_exposures, snapshot_image
        )

def _generate_reportlab_pdf(
    report_filename, victim_info, threats_detected,
    arp_baseline, current_arp, captured_exposures, snapshot_image
):
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, HRFlowable, KeepTogether
    )

    doc = SimpleDocTemplate(
        report_filename,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    
    # Custom Palette
    primary_color = colors.HexColor("#1A237E")    # Deep Navy
    danger_color = colors.HexColor("#C62828")     # Crimson
    accent_color = colors.HexColor("#0D47A1")     # Blue
    dark_gray = colors.HexColor("#263238")
    light_bg = colors.HexColor("#ECEFF1")

    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=primary_color,
        alignment=1
    )

    sub_title_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=14,
        textColor=danger_color,
        alignment=1
    )

    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=17,
        textColor=accent_color,
        spaceBefore=12,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=12,
        textColor=dark_gray
    )

    table_header_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.white,
        alignment=1
    )

    table_cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=10,
        textColor=dark_gray
    )

    elements = []

    # Title Banner
    elements.append(Paragraph("CYBERSECURITY INCIDENT INVESTIGATION REPORT", title_style))
    elements.append(Paragraph("SECURITY AUDIT: ARP SPOOFING & MAN-IN-THE-MIDDLE (MITM) DETECTION", sub_title_style))
    elements.append(Spacer(1, 10))
    elements.append(HRFlowable(width="100%", thickness=2, color=primary_color, spaceAfter=15))

    # Executive Summary Metadata
    gen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    severity = "CRITICAL - ACTIVE MITM DETECTED" if threats_detected else "NORMAL - NO ACTIVE THREATS"
    sev_color = colors.HexColor("#FFEBEE") if threats_detected else colors.HexColor("#E8F5E9")

    summary_data = [
        [Paragraph("<b>Report Generated:</b>", body_style), Paragraph(gen_time, body_style),
         Paragraph("<b>Incident Status:</b>", body_style), Paragraph(f"<b>{severity}</b>", body_style)],
        [Paragraph("<b>Protected Host IP:</b>", body_style), Paragraph(str(victim_info.get("ip", "N/A")), body_style),
         Paragraph("<b>Protected Host MAC:</b>", body_style), Paragraph(str(victim_info.get("mac", "N/A")), body_style)],
        [Paragraph("<b>Gateway IP:</b>", body_style), Paragraph(str(victim_info.get("gateway_ip", "N/A")), body_style),
         Paragraph("<b>Total Threats Identified:</b>", body_style), Paragraph(str(len(threats_detected)), body_style)]
    ]

    summary_table = Table(summary_data, colWidths=[110, 160, 120, 150])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), light_bg),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CFD8DC")),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 12))

    # Section 1: Detected Attackers & Threat Intelligence
    elements.append(Paragraph("1. Attacker Attribution & Forensic Details", h2_style))
    if threats_detected:
        threat_headers = ["Timestamp", "Attacker IP", "Attacker MAC", "Device Vendor (OUI)", "Target / Spoofed IP"]
        threat_rows = [[Paragraph(f"<b>{h}</b>", table_header_style) for h in threat_headers]]

        for t in threats_detected:
            threat_rows.append([
                Paragraph(str(t.get("timestamp", "-")), table_cell_style),
                Paragraph(str(t.get("attacker_ip", "-")), table_cell_style),
                Paragraph(str(t.get("attacker_mac", "-")), table_cell_style),
                Paragraph(str(t.get("vendor", "Unknown Manufacturer")), table_cell_style),
                Paragraph(str(t.get("spoofed_ip", "-")), table_cell_style)
            ])

        threat_table = Table(threat_rows, colWidths=[100, 95, 115, 120, 110])
        threat_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), danger_color),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#FFCDD2")),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#FFF5F5"), colors.white]),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ]))
        elements.append(threat_table)
    else:
        elements.append(Paragraph("No unauthorized ARP anomalies or malicious spoofing signatures were captured during the active monitoring window.", body_style))

    elements.append(Spacer(1, 12))

    # Section 2: ARP Cache Integrity Analysis (Baseline vs Current Table)
    elements.append(Paragraph("2. ARP Cache Integrity Matrix (Baseline vs Current State)", h2_style))
    arp_headers = ["IP Address", "Baseline MAC", "Current MAC", "Integrity Status"]
    arp_rows = [[Paragraph(f"<b>{h}</b>", table_header_style) for h in arp_headers]]

    all_ips = sorted(list(set(list(arp_baseline.keys()) + list(current_arp.keys()))))
    for ip in all_ips[:30]:  # Limit to top entries for report layout
        base_mac = arp_baseline.get(ip, "Not in Baseline")
        curr_mac = current_arp.get(ip, "Not Present")

        if base_mac != "Not in Baseline" and curr_mac != "Not Present":
            if base_mac.lower() == curr_mac.lower():
                status_text = "<font color='green'><b>VERIFIED / CLEAN</b></font>"
            else:
                status_text = "<font color='red'><b>POISONED / MISMATCH</b></font>"
        elif base_mac == "Not in Baseline":
            status_text = "<font color='orange'><b>NEW DEVICE</b></font>"
        else:
            status_text = "<font color='gray'><b>OFFLINE</b></font>"

        arp_rows.append([
            Paragraph(ip, table_cell_style),
            Paragraph(base_mac, table_cell_style),
            Paragraph(curr_mac, table_cell_style),
            Paragraph(status_text, table_cell_style)
        ])

    arp_table = Table(arp_rows, colWidths=[120, 140, 140, 140])
    arp_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), accent_color),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CFD8DC")),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [light_bg, colors.white]),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    elements.append(arp_table)
    elements.append(Spacer(1, 12))

    # Section 3: Insecure Cleartext Authentication & Data Exposure Audit
    elements.append(Paragraph("3. Unencrypted Protocol Exposure Audit (MITM Risk Analysis)", h2_style))
    if captured_exposures:
        exp_headers = ["Timestamp", "Protocol", "Service / Host", "Account Identifier", "Exposed Secret (Masked)"]
        exp_rows = [[Paragraph(f"<b>{h}</b>", table_header_style) for h in exp_headers]]

        for exp in captured_exposures[:20]:
            val = exp.get("value", "")
            masked_val = val[:2] + ("*" * max(len(val) - 4, 3)) + val[-2:] if len(val) > 4 else "***"
            exp_rows.append([
                Paragraph(str(exp.get("timestamp", "-")), table_cell_style),
                Paragraph(str(exp.get("protocol", "HTTP/TCP")), table_cell_style),
                Paragraph(str(exp.get("service", "Web Service")), table_cell_style),
                Paragraph(str(exp.get("user", "Anonymous")), table_cell_style),
                Paragraph(f"<code>{masked_val}</code>", table_cell_style)
            ])

        exp_table = Table(exp_rows, colWidths=[90, 80, 140, 110, 120])
        exp_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), primary_color),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CFD8DC")),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [light_bg, colors.white]),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        elements.append(exp_table)
    else:
        elements.append(Paragraph("No cleartext authentication tokens or credentials leaked over inspected unencrypted sessions.", body_style))

    elements.append(Spacer(1, 12))

    # Section 4: Forensic Camera Evidence (if captured)
    if snapshot_image and os.path.exists(snapshot_image):
        try:
            elements.append(KeepTogether([
                Paragraph("4. Physical / Surveillance Evidence Snapshot", h2_style),
                Spacer(1, 4),
                Image(snapshot_image, width=280, height=180),
                Spacer(1, 6)
            ]))
        except Exception:
            pass

    # Section 5: Mitigation & Hardening Recommendations
    elements.append(Paragraph("5. Defense Recommendations & Remediation Guidelines", h2_style))
    recs = [
        "<b>1. Enforce Dynamic ARP Inspection (DAI):</b> Enable DAI and DHCP Snooping on managed network switches to drop invalid ARP bindings.",
        "<b>2. Static ARP Binding:</b> Set static ARP mappings on critical endpoints and default gateways (<code>arp -s &lt;gateway_ip&gt; &lt;gateway_mac&gt;</code>).",
        "<b>3. Enforce End-to-End Encryption:</b> Mandate HTTPS (HSTS), SSHv2, and SFTP. Deprecate legacy unencrypted protocols (HTTP, Telnet, FTP).",
        "<b>4. Network Segmentation:</b> Isolate untrusted endpoints into separate VLANs with IEEE 802.1X port security.",
        "<b>5. Endpoint Security Agent:</b> Run continuous ARP monitoring daemons with automated cache flush and intrusion response."
    ]
    for r in recs:
        elements.append(Paragraph(r, body_style))
        elements.append(Spacer(1, 3))

    doc.build(elements)
    return report_filename

def _generate_html_report(
    html_filename, victim_info, threats_detected,
    arp_baseline, current_arp, captured_exposures, snapshot_image
):
    """Fallback interactive HTML report when reportlab is not installed."""
    gen_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    threat_count = len(threats_detected)
    status_badge = '<span style="background:#ef4444;color:white;padding:3px 8px;border-radius:4px;">CRITICAL ATTACK DETECTED</span>' if threat_count > 0 else '<span style="background:#10b981;color:white;padding:3px 8px;border-radius:4px;">SYSTEM SECURE</span>'

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Cybersecurity Incident Report - ARP Spoofing Investigation</title>
<style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 24px; }}
    .container {{ max-width: 1000px; margin: auto; background: #1e293b; border-radius: 12px; padding: 32px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }}
    h1 {{ color: #38bdf8; font-size: 24px; margin-bottom: 4px; }}
    h2 {{ color: #94a3b8; font-size: 16px; margin-top: 0; border-bottom: 2px solid #334155; padding-bottom: 12px; }}
    h3 {{ color: #f43f5e; font-size: 18px; margin-top: 24px; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin: 20px 0; }}
    .card {{ background: #0f172a; padding: 16px; border-radius: 8px; border-left: 4px solid #38bdf8; }}
    .card p {{ margin: 4px 0; font-size: 13px; color: #94a3b8; }}
    .card h4 {{ margin: 0; font-size: 18px; color: #f8fafc; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }}
    th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #334155; }}
    th {{ background: #0f172a; color: #94a3b8; }}
    tr:hover {{ background: #283548; }}
    .btn {{ background: #38bdf8; color: #0f172a; padding: 10px 20px; font-weight: bold; border-radius: 6px; border: none; cursor: pointer; text-decoration: none; display: inline-block; }}
</style>
</head>
<body>
<div class="container">
    <div style="display:flex; justify-content:space-between; align-items:center;">
        <div>
            <h1>🛡️ CYBERSECURITY INCIDENT INVESTIGATION REPORT</h1>
            <h2>ARP Spoofing & Man-In-The-Middle (MITM) Detection Forensic Document</h2>
        </div>
        <button class="btn" onclick="window.print()">🖨️ Print / Save as PDF</button>
    </div>

    <div class="grid">
        <div class="card">
            <p>Incident Status</p>
            <h4>{status_badge}</h4>
        </div>
        <div class="card">
            <p>Victim Device IP</p>
            <h4>{victim_info.get("ip", "Unknown")}</h4>
        </div>
        <div class="card">
            <p>Attacks Logged</p>
            <h4 style="color:#ef4444;">{threat_count}</h4>
        </div>
        <div class="card">
            <p>Audit Timestamp</p>
            <h4>{gen_time}</h4>
        </div>
    </div>

    <h3>1. Attacker Attribution & Intrusion Evidence</h3>
    <table>
        <thead>
            <tr><th>Timestamp</th><th>Attacker IP</th><th>Attacker MAC</th><th>Vendor (OUI)</th><th>Target / Spoofed IP</th></tr>
        </thead>
        <tbody>
"""
    if threats_detected:
        for t in threats_detected:
            html_content += f"""
            <tr>
                <td>{t.get("timestamp", "-")}</td>
                <td style="color:#f43f5e;font-weight:bold;">{t.get("attacker_ip", "-")}</td>
                <td style="font-family:monospace;">{t.get("attacker_mac", "-")}</td>
                <td>{t.get("vendor", "Unknown")}</td>
                <td>{t.get("spoofed_ip", "-")}</td>
            </tr>
            """
    else:
        html_content += '<tr><td colspan="5" style="text-align:center;color:#10b981;">No malicious ARP poisoning anomalies detected.</td></tr>'

    html_content += """
        </tbody>
    </table>

    <h3>2. Insecure Cleartext Authentication & Protocol Audit</h3>
    <table>
        <thead>
            <tr><th>Timestamp</th><th>Protocol</th><th>Service / Host</th><th>Account</th><th>Captured Value</th></tr>
        </thead>
        <tbody>
"""
    if captured_exposures:
        for exp in captured_exposures:
            html_content += f"""
            <tr>
                <td>{exp.get("timestamp", "-")}</td>
                <td>{exp.get("protocol", "HTTP")}</td>
                <td>{exp.get("service", "-")}</td>
                <td>{exp.get("user", "-")}</td>
                <td style="font-family:monospace;color:#facc15;">{exp.get("value", "")}</td>
            </tr>
            """
    else:
        html_content += '<tr><td colspan="5" style="text-align:center;color:#94a3b8;">No unencrypted authentication transmissions detected.</td></tr>'

    html_content += """
        </tbody>
    </table>

    <h3>3. Recommended Mitigation Strategies</h3>
    <ul>
        <li><b>Dynamic ARP Inspection (DAI):</b> Configure managed switches to drop gratuitous ARP anomalies.</li>
        <li><b>Static ARP Entries:</b> Bind the gateway MAC address permanently to prevent poisoning.</li>
        <li><b>HTTPS / TLS Enforcement:</b> Transition all legacy protocols to encrypted tunnels.</li>
    </ul>
</div>
</body>
</html>
"""
    with open(html_filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    return html_filename
