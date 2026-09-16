"""
generate_dummy_report.py — Generates a dummy Daily Report PDF for structure preview.
Run: venv\Scripts\python generate_dummy_report.py
"""
import os
import sys
import datetime

# Allow imports from backend
sys.path.insert(0, os.path.dirname(__file__))

from fpdf import FPDF

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")
if not os.path.exists(REPORTS_DIR):
    os.makedirs(REPORTS_DIR)

class DummyPDF(FPDF):
    def header(self):
        self.set_font("helvetica", "B", 18)
        self.set_text_color(10, 132, 255)
        self.cell(0, 10, "R3P Network Security Daily Report", ln=True, align="C")
        self.set_font("helvetica", "I", 10)
        self.set_text_color(100, 100, 100)
        self.cell(0, 10, f"Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  |  [DEMO / DUMMY DATA]", ln=True, align="C")
        self.ln(8)

    def footer(self):
        self.set_y(-15)
        self.set_font("helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()}  |  R3P - Ransomware Readiness & Remediation Platform", align="C")

    def section_title(self, title):
        self.set_font("helvetica", "B", 13)
        self.set_fill_color(240, 240, 245)
        self.set_text_color(30, 30, 80)
        self.cell(0, 10, title, ln=True, fill=True)
        self.ln(3)

    def body_text(self, text):
        self.set_font("helvetica", "", 11)
        self.set_text_color(40, 40, 40)
        self.multi_cell(0, 7, text)
        self.ln(3)

    def kv_row(self, label, value, highlight=None):
        self.set_font("helvetica", "B", 10)
        self.set_text_color(80, 80, 80)
        self.cell(70, 8, label)
        self.set_font("helvetica", "", 10)
        if highlight == "red":
            self.set_text_color(255, 69, 58)
        elif highlight == "green":
            self.set_text_color(48, 209, 88)
        elif highlight == "orange":
            self.set_text_color(255, 159, 10)
        else:
            self.set_text_color(30, 30, 30)
        self.cell(0, 8, str(value), ln=True)

pdf = DummyPDF()
pdf.add_page()

# ── PAGE 1: EXECUTIVE SUMMARY ────────────────────────────────────────────────────
pdf.section_title("1. Executive Summary")
pdf.body_text(
    "This is a DUMMY report generated to demonstrate the structure and layout of the R3P daily report. "
    "All data below is fabricated for preview purposes only. In a live environment, this report is "
    "generated on-the-fly from your actual SQLite database."
)
pdf.ln(4)
pdf.section_title("1.1  Network Overview (24-Hour Window)")
pdf.kv_row("Report Date", datetime.datetime.now().strftime("%Y-%m-%d"))
pdf.kv_row("Report Generated At", datetime.datetime.now().strftime("%H:%M:%S"))
pdf.kv_row("Total Endpoints Monitored", "8")
pdf.kv_row("Endpoints with SAFE status", "3", highlight="green")
pdf.kv_row("Endpoints with LOW RISK status", "2")
pdf.kv_row("Endpoints with HIGH RISK status", "2", highlight="orange")
pdf.kv_row("Endpoints with CRITICAL status", "1", highlight="red")
pdf.ln(4)
pdf.kv_row("Total Telemetry Scans (24h)", "142")
pdf.kv_row("Anomalies Detected (24h)", "4", highlight="red")
pdf.kv_row("Remediation Commands Issued (24h)", "6")
pdf.kv_row("Remediation Failures", "1", highlight="orange")
pdf.ln(6)

pdf.section_title("1.2  Summary Narrative")
pdf.body_text(
    "Over the last 24 hours, the R3P platform monitored 8 Windows endpoints across 2 subnets. "
    "One machine (WORKSTATION-04) is currently in CRITICAL status with an active anomaly streak of 3 scans. "
    "The most common misconfiguration detected across the fleet is 'SMBv1 Enabled', which is present on "
    "3 out of 8 endpoints. Two HIGH RISK machines have pending remediation commands. Administrators "
    "successfully applied 5 fixes with 1 failing due to a timeout on WORKSTATION-07."
)

# ── PAGE 2: ENDPOINT STATUS TABLE ────────────────────────────────────────────────
pdf.add_page()
pdf.section_title("2. Current Endpoint Status")

# Table header
DUMMY_MACHINES = [
    ("WORKSTATION-01", "192.168.1.10", "SAFE",      12.5),
    ("WORKSTATION-02", "192.168.1.11", "LOW RISK",  31.0),
    ("WORKSTATION-03", "192.168.1.12", "HIGH RISK", 67.3),
    ("WORKSTATION-04", "192.168.1.13", "CRITICAL",  91.7),
    ("SERVER-DC01",    "192.168.2.1",  "SAFE",       5.0),
    ("SERVER-FS01",    "192.168.2.2",  "LOW RISK",  28.4),
    ("LAPTOP-MGR01",   "192.168.1.20", "HIGH RISK", 55.9),
    ("LAPTOP-HR01",    "192.168.1.21", "SAFE",       9.1),
]
RISK_COLOR_MAP = {
    "CRITICAL":  (255, 69, 58),
    "HIGH RISK": (255, 159, 10),
    "LOW RISK":  (255, 214, 10),
    "SAFE":      (48, 209, 88),
}

pdf.set_font("helvetica", "B", 10)
pdf.set_fill_color(220, 220, 235)
pdf.cell(55, 9, "Hostname", border=1, fill=True)
pdf.cell(40, 9, "IP Address", border=1, fill=True)
pdf.cell(40, 9, "Risk Class", border=1, fill=True)
pdf.cell(30, 9, "Risk Score", border=1, fill=True)
pdf.cell(0,  9, "Last Seen", border=1, fill=True, ln=True)

pdf.set_font("helvetica", "", 10)
alt = False
for hostname, ip, risk, score in DUMMY_MACHINES:
    r, g, b = RISK_COLOR_MAP.get(risk, (30, 30, 30))
    bg = (245, 245, 245) if alt else (255, 255, 255)
    pdf.set_fill_color(*bg)
    pdf.cell(55, 8, hostname, border=1, fill=True)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(40, 8, ip, border=1, fill=True)
    pdf.set_text_color(r, g, b)
    pdf.cell(40, 8, risk, border=1, fill=True)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(30, 8, f"{score:.1f}", border=1, fill=True)
    pdf.cell(0,  8, "5 min ago", border=1, fill=True, ln=True)
    alt = not alt

# ── PAGE 3: ANOMALIES & REMEDIATIONS ─────────────────────────────────────────────
pdf.add_page()
pdf.section_title("3. Anomalies Detected (Last 24h)")

DUMMY_ANOMALIES = [
    ("WORKSTATION-04", "91.7", "3.42", "Active - 3 consecutive scans"),
    ("WORKSTATION-03", "67.3", "2.11", "Resolved"),
    ("LAPTOP-MGR01",   "55.9", "2.05", "Resolved"),
    ("WORKSTATION-02", "31.0", "1.92", "Resolved"),
]
pdf.set_font("helvetica", "B", 10)
pdf.set_fill_color(220, 220, 235)
pdf.cell(55, 9, "Hostname",   border=1, fill=True)
pdf.cell(30, 9, "Risk Score", border=1, fill=True)
pdf.cell(30, 9, "Z-Score",    border=1, fill=True)
pdf.cell(0,  9, "Status",     border=1, fill=True, ln=True)

pdf.set_font("helvetica", "", 10)
for hostname, score, z, status in DUMMY_ANOMALIES:
    color = (255, 69, 58) if "Active" in status else (48, 209, 88)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(55, 8, hostname, border=1)
    pdf.cell(30, 8, score, border=1)
    pdf.cell(30, 8, z, border=1)
    pdf.set_text_color(*color)
    pdf.cell(0,  8, status, border=1, ln=True)

pdf.set_text_color(30, 30, 30)
pdf.ln(8)

pdf.section_title("4. Remediation Commands Executed (Last 24h)")

DUMMY_REMEDIATIONS = [
    ("WORKSTATION-04", "disable_smb_v1",        "done",    "admin", "SMBv1 disabled successfully."),
    ("WORKSTATION-04", "enable_defender",        "done",    "admin", "Defender re-enabled."),
    ("WORKSTATION-03", "enable_firewall",        "done",    "admin", "Firewall activated."),
    ("WORKSTATION-03", "disable_autorun",        "done",    "admin", "AutoRun disabled."),
    ("LAPTOP-MGR01",   "enable_uac",             "done",    "admin", "UAC enforced successfully."),
    ("WORKSTATION-07", "disable_guest_account",  "failed",  "admin", "Timeout: agent unreachable."),
]
STATUS_COLOR = {"done": (48, 209, 88), "failed": (255, 69, 58), "pending": (255, 159, 10)}

pdf.set_font("helvetica", "B", 9)
pdf.set_fill_color(220, 220, 235)
pdf.cell(42, 9, "Hostname",   border=1, fill=True)
pdf.cell(52, 9, "Command",    border=1, fill=True)
pdf.cell(22, 9, "Status",     border=1, fill=True)
pdf.cell(20, 9, "By",         border=1, fill=True)
pdf.cell(0,  9, "Output",     border=1, fill=True, ln=True)

pdf.set_font("helvetica", "", 9)
alt = False
for hostname, cmd, status, by, output in DUMMY_REMEDIATIONS:
    bg = (245, 245, 245) if alt else (255, 255, 255)
    pdf.set_fill_color(*bg)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(42, 8, hostname, border=1, fill=True)
    pdf.cell(52, 8, cmd[:22], border=1, fill=True)
    r, g, b = STATUS_COLOR.get(status, (30, 30, 30))
    pdf.set_text_color(r, g, b)
    pdf.cell(22, 8, status, border=1, fill=True)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(20, 8, by, border=1, fill=True)
    pdf.cell(0,  8, output[:40], border=1, fill=True, ln=True)
    alt = not alt

# ── PAGE 4: TOP MISCONFIGURATIONS ────────────────────────────────────────────────
pdf.add_page()
pdf.section_title("5. Top Misconfigurations Across Fleet")

DUMMY_ISSUES = [
    ("smb_v1_enabled",            "SMBv1 Enabled",               "CRITICAL", 3, "WORKSTATION-01, 03, 04"),
    ("defender_disabled",         "Windows Defender Disabled",    "HIGH RISK", 2, "WORKSTATION-03, 04"),
    ("firewall_disabled",         "Windows Firewall Disabled",    "HIGH RISK", 2, "WORKSTATION-03, 07"),
    ("powershell_unrestricted",   "PowerShell Unrestricted",      "HIGH RISK", 2, "LAPTOP-MGR01, WORKSTATION-04"),
    ("uac_disabled",              "UAC Disabled",                 "HIGH RISK", 1, "LAPTOP-MGR01"),
    ("autorun_enabled",           "AutoRun Enabled",              "LOW RISK",  2, "WORKSTATION-01, 02"),
    ("guest_account_active",      "Guest Account Active",         "LOW RISK",  1, "WORKSTATION-02"),
    ("backup_absent",             "No Backup Solution",           "HIGH RISK", 1, "WORKSTATION-04"),
]

pdf.set_font("helvetica", "B", 9)
pdf.set_fill_color(220, 220, 235)
pdf.cell(52, 9, "Parameter",   border=1, fill=True)
pdf.cell(26, 9, "Severity",    border=1, fill=True)
pdf.cell(18, 9, "# Affected",  border=1, fill=True)
pdf.cell(0,  9, "Affected Machines", border=1, fill=True, ln=True)

pdf.set_font("helvetica", "", 9)
alt = False
for _, label, severity, count, machines in DUMMY_ISSUES:
    bg = (245, 245, 245) if alt else (255, 255, 255)
    pdf.set_fill_color(*bg)
    r, g, b = RISK_COLOR_MAP.get(severity, (30, 30, 30))
    pdf.set_text_color(30, 30, 30)
    pdf.cell(52, 8, label[:30], border=1, fill=True)
    pdf.set_text_color(r, g, b)
    pdf.cell(26, 8, severity, border=1, fill=True)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(18, 8, str(count), border=1, fill=True, align="C")
    pdf.cell(0,  8, machines[:50], border=1, fill=True, ln=True)
    alt = not alt

# Save
filename = f"dummy_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
filepath = os.path.join(REPORTS_DIR, filename)
pdf.output(filepath)
print(f"[OK] Dummy report saved to: {filepath}")
