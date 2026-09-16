import os
import datetime
from fpdf import FPDF
from sqlalchemy.orm import Session
from sqlalchemy import func
from models import MachineRegistry, ConfigurationScan, RemediationCommand

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")
if not os.path.exists(REPORTS_DIR):
    os.makedirs(REPORTS_DIR)

class PDFReport(FPDF):
    def header(self):
        # Header for the PDF
        self.set_font("helvetica", "B", 18)
        self.set_text_color(10, 132, 255) # Apple Blue-ish
        self.cell(0, 10, "R3P Network Security Daily Report", ln=True, align="C")
        self.set_font("helvetica", "I", 10)
        self.set_text_color(100, 100, 100)
        self.cell(0, 10, f"Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
        self.ln(10)

    def footer(self):
        # Footer
        self.set_y(-15)
        self.set_font("helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")

    def section_title(self, title):
        self.set_font("helvetica", "B", 14)
        self.set_text_color(50, 50, 50)
        self.cell(0, 10, title, ln=True, align="L")
        self.ln(2)

    def body_text(self, text):
        self.set_font("helvetica", "", 11)
        self.set_text_color(30, 30, 30)
        self.multi_cell(0, 8, text)
        self.ln(2)

def generate_daily_report(db: Session) -> str:
    """
    Generates a daily report PDF and returns the file path.
    """
    pdf = PDFReport()
    pdf.add_page()

    # 1. Gather Data
    now = datetime.datetime.now(datetime.timezone.utc)
    yesterday = now - datetime.timedelta(days=1)

    # Active Machines
    machines = db.query(MachineRegistry).all()
    total_machines = len(machines)
    safe_machines = [m for m in machines if m.last_risk_class == "SAFE"]
    critical_machines = [m for m in machines if m.last_risk_class == "CRITICAL"]

    # Scans and Anomalies in last 24h
    scans_24h = db.query(ConfigurationScan).filter(ConfigurationScan.scanned_at >= yesterday).all()
    anomalies_24h = [s for s in scans_24h if s.is_anomaly]
    
    # Remediations in last 24h
    remediations_24h = db.query(RemediationCommand).filter(RemediationCommand.issued_at >= yesterday).all()
    failed_remediations = [r for r in remediations_24h if r.status == "failed"]

    # 2. Executive Summary
    pdf.section_title("1. Executive Summary")
    summary = (
        f"Total Endpoints Monitored: {total_machines}\n"
        f"Endpoints with SAFE status: {len(safe_machines)}\n"
        f"Endpoints with CRITICAL status: {len(critical_machines)}\n\n"
        f"In the last 24 hours, the system recorded {len(scans_24h)} telemetry scans. "
        f"There were {len(anomalies_24h)} anomalies detected. "
        f"Administrators issued {len(remediations_24h)} remediation commands, "
        f"with {len(failed_remediations)} resulting in failure."
    )
    pdf.body_text(summary)
    pdf.ln(5)

    # 3. Machine Status Table
    pdf.section_title("2. Current Endpoint Status")
    
    # Table Header
    pdf.set_font("helvetica", "B", 10)
    pdf.set_fill_color(220, 220, 220)
    pdf.cell(50, 8, "Hostname", border=1, fill=True)
    pdf.cell(40, 8, "IP Address", border=1, fill=True)
    pdf.cell(40, 8, "Risk Class", border=1, fill=True)
    pdf.cell(30, 8, "Risk Score", border=1, fill=True, ln=True)

    # Table Body
    pdf.set_font("helvetica", "", 10)
    for m in machines:
        # Determine color for risk class
        if m.last_risk_class == "CRITICAL":
            pdf.set_text_color(255, 69, 58)
        elif m.last_risk_class == "HIGH RISK":
            pdf.set_text_color(255, 159, 10)
        elif m.last_risk_class == "LOW RISK":
            pdf.set_text_color(255, 214, 10)
        else:
            pdf.set_text_color(48, 209, 88) # SAFE

        pdf.cell(50, 8, m.hostname[:20], border=1)
        pdf.set_text_color(30, 30, 30) # Reset color
        pdf.cell(40, 8, m.ip_address, border=1)
        pdf.cell(40, 8, m.last_risk_class, border=1)
        pdf.cell(30, 8, f"{m.last_risk_score:.1f}", border=1, ln=True)

    pdf.ln(10)

    # 4. Recent Remediations
    pdf.section_title("3. Remediations Executed (Last 24h)")
    if remediations_24h:
        pdf.set_font("helvetica", "B", 9)
        pdf.cell(40, 8, "Hostname", border=1, fill=True)
        pdf.cell(50, 8, "Command", border=1, fill=True)
        pdf.cell(30, 8, "Status", border=1, fill=True)
        pdf.cell(40, 8, "Issued By", border=1, fill=True, ln=True)

        pdf.set_font("helvetica", "", 9)
        for r in remediations_24h[-15:]: # Show last 15 max to save space
            pdf.cell(40, 8, r.hostname[:15], border=1)
            pdf.cell(50, 8, r.command_key[:20], border=1)
            
            # Color status
            if r.status == "done":
                pdf.set_text_color(48, 209, 88)
            elif r.status == "failed":
                pdf.set_text_color(255, 69, 58)
            else:
                pdf.set_text_color(255, 159, 10)
                
            pdf.cell(30, 8, r.status, border=1)
            pdf.set_text_color(30, 30, 30)
            
            pdf.cell(40, 8, r.issued_by[:15], border=1, ln=True)
    else:
        pdf.body_text("No remediation commands were issued in the last 24 hours.")

    # Save PDF
    filename = f"daily_report_{now.strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(REPORTS_DIR, filename)
    pdf.output(filepath)

    return filepath
