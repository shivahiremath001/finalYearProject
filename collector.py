"""
R3P Agent — Ransomware Readiness & Risk Profiler
Standalone collector with Tkinter GUI.

Package as a single .exe (no Python needed on target machine):
    pyinstaller --onefile --windowed --uac-admin --name R3P_Agent collector.py

On first run a dialog asks for the server IP and saves it to r3p_server.txt
next to the executable. Subsequent runs skip straight to scanning.
"""

import socket
import platform
import subprocess
import json
import sys
import os
import threading
from datetime import datetime
import tkinter as tk
from tkinter import ttk

# ── requests import with friendly error ───────────────────────────────────────
try:
    import requests
except ImportError:
    _root = tk.Tk()
    _root.withdraw()
    import tkinter.messagebox as mb
    mb.showerror(
        "Missing Library",
        "The 'requests' library is not installed.\n\nRun:  pip install requests"
    )
    sys.exit(1)

# ── CONSTANTS ──────────────────────────────────────────────────────────────────
SERVER_PORT = 8000

# Config file lives next to the .exe (or the .py during dev)
_BASE = os.path.dirname(
    sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)
)
CONFIG_FILE = os.path.join(_BASE, "r3p_server.txt")

COLORS = {
    "bg":       "#0d1117",
    "card":     "#161b27",
    "border":   "#21262d",
    "accent":   "#6c63ff",
    "text":     "#e6edf3",
    "subtle":   "#8b949e",
    "safe":     "#3fb950",
    "low":      "#d29922",
    "high":     "#f85149",
    "critical": "#da3633",
    "warning":  "#e3b341",
}

RISK_COLORS = {
    "SAFE":      COLORS["safe"],
    "LOW RISK":  COLORS["low"],
    "HIGH RISK": COLORS["high"],
    "CRITICAL":  COLORS["critical"],
}

# ── SERVER CONFIG PERSISTENCE ─────────────────────────────────────────────────
def load_server_ip():
    try:
        if os.path.exists(CONFIG_FILE):
            ip = open(CONFIG_FILE).read().strip()
            return ip if ip else None
    except Exception:
        pass
    return None


def save_server_ip(ip: str):
    try:
        with open(CONFIG_FILE, "w") as f:
            f.write(ip.strip())
    except Exception:
        pass


def build_api_url(server_input: str) -> str:
    """
    Build the full /ingest URL from whatever the user typed:
      - Plain IP:          192.168.1.105   → http://192.168.1.105:8000/ingest
      - IP + port:         192.168.1.105:8000 → http://192.168.1.105:8000/ingest
      - ngrok URL:         abc123.ngrok.io → https://abc123.ngrok.io/ingest
      - Full https URL:    https://abc.ngrok.io → https://abc.ngrok.io/ingest
    """
    s = server_input.strip().rstrip("/")
    # Already a full URL?
    if s.startswith("http://") or s.startswith("https://"):
        return s.rstrip("/") + "/ingest"
    # Contains a domain-like dot but no port → likely ngrok or hostname
    if "." in s and ":" not in s and not s.replace(".", "").isdigit():
        return f"https://{s}/ingest"
    # Plain IP (with or without port)
    if ":" not in s:
        return f"http://{s}:{SERVER_PORT}/ingest"
    # IP:port already included
    return f"http://{s}/ingest"


# ── POWERSHELL HELPER ──────────────────────────────────────────────────────────
def _ps(cmd: str, timeout: int = 12) -> str:
    """Run PowerShell silently and return stdout."""
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout,
            creationflags=flags,
        )
        return r.stdout.strip()
    except Exception:
        return ""


# ── SECURITY CHECKS ────────────────────────────────────────────────────────────
def get_os_info() -> str:
    return f"{platform.system()} {platform.release()}"


def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "unknown"


def check_rdp_open() -> bool:
    """True = RDP port 3389 is open (risky)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    result = s.connect_ex(("127.0.0.1", 3389))
    s.close()
    return result == 0


def check_firewall_on() -> bool:
    """True = all firewall profiles are ON (safe)."""
    out = _ps(
        "(Get-NetFirewallProfile | Where-Object { $_.Enabled -eq $false }).Count"
    )
    try:
        return int(out) == 0
    except Exception:
        out2 = _ps("netsh advfirewall show allprofiles state")
        return "ON" in out2.upper()


def check_smb_v1() -> bool:
    """True = SMBv1 is enabled (risky — WannaCry vector)."""
    out = _ps("(Get-SmbServerConfiguration).EnableSMB1Protocol")
    return out.lower() == "true"


def check_defender_disabled() -> bool:
    """True = Windows Defender real-time protection is OFF (risky)."""
    out = _ps(
        "(Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled"
    )
    return out.lower() != "true"


def check_tamper_protection_off() -> bool:
    """True = Defender Tamper Protection is OFF (risky)."""
    out = _ps(
        "(Get-MpComputerStatus -ErrorAction SilentlyContinue).IsTamperProtected"
    )
    return out.lower() != "true"


def check_uac_disabled() -> bool:
    """True = UAC is disabled (risky)."""
    out = _ps(
        r"(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"
        r"\Policies\System' -ErrorAction SilentlyContinue).EnableLUA"
    )
    return out.strip() == "0"


def check_powershell_unrestricted() -> bool:
    """True = PowerShell execution policy is Unrestricted or Bypass (risky)."""
    out = _ps("Get-ExecutionPolicy").lower()
    return out in ("unrestricted", "bypass")


def check_autorun_enabled() -> bool:
    """True = USB AutoRun is enabled (risky)."""
    out = _ps(
        r"(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"
        r"\Policies\Explorer' -ErrorAction SilentlyContinue).NoDriveTypeAutoRun"
    )
    try:
        return int(out.strip()) != 255
    except Exception:
        return True


def check_guest_account() -> bool:
    """True = Guest account is enabled (risky)."""
    out = _ps(
        "(Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue).Enabled"
    )
    return out.lower() == "true"


def check_lsass_protection_off() -> bool:
    """True = LSASS is not running as PPL (risky — credential dump vector)."""
    out = _ps(
        r"(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'"
        r" -ErrorAction SilentlyContinue).RunAsPPL"
    )
    return out.strip() != "1"


def check_admin_shares() -> bool:
    """True = default admin shares (C$, ADMIN$) are present (risky)."""
    out = _ps(
        "(Get-SmbShare -ErrorAction SilentlyContinue"
        r" | Where-Object { $_.Name -match 'ADMIN\$|C\$' }).Count"
    )
    try:
        return int(out.strip()) > 0
    except Exception:
        return False


def check_event_logging_disabled() -> bool:
    """True = Windows Event Log service is NOT running (risky)."""
    out = _ps("(Get-Service -Name 'eventlog').Status")
    return out.lower() != "running"


def check_vss_deleted() -> bool:
    """True = no Volume Shadow Copies exist (risky — no recovery)."""
    out = _ps(
        "(Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue"
        " | Measure-Object).Count"
    )
    try:
        return int(out.strip()) == 0
    except Exception:
        return False


def check_backup_configured() -> bool:
    """True = Windows Backup service is running (safe)."""
    out = _ps(
        "(Get-Service -Name 'SDRSVC' -ErrorAction SilentlyContinue).Status"
    )
    return out.lower() == "running"


def check_bitlocker_off() -> bool:
    """True = C: drive is NOT fully encrypted (risky)."""
    out = _ps(
        "(Get-BitLockerVolume -MountPoint 'C:' -ErrorAction SilentlyContinue)"
        ".VolumeStatus"
    )
    return "fullyencrypted" not in out.lower()


def check_open_network_shares() -> bool:
    """True = network shares are accessible to 'Everyone' (risky)."""
    out = _ps(
        "Get-SmbShare -ErrorAction SilentlyContinue"
        " | ForEach-Object { Get-SmbShareAccess $_.Name -ErrorAction SilentlyContinue }"
        " | Where-Object { $_.AccountName -eq 'Everyone' -and $_.AccessRight -ne 'None' }"
        " | Measure-Object | Select-Object -ExpandProperty Count"
    )
    try:
        return int(out.strip()) > 0
    except Exception:
        return False


def check_macro_execution_enabled() -> bool:
    """True = Office macros are enabled without notification (risky)."""
    # VBAWarnings=1 means macros enabled; 2=with notification; 3=signed only; 4=disabled
    # Check for Word, Excel, PowerPoint across common Office versions
    ps_cmd = (
        "$officeVersions = @('16.0','15.0','14.0');"
        "$apps = @('Word','Excel','PowerPoint');"
        "$found = $false;"
        "foreach ($ver in $officeVersions) {"
        "  foreach ($app in $apps) {"
        "    $path = \"HKCU:\\SOFTWARE\\Microsoft\\Office\\$ver\\$app\\Security\";"
        "    $val = (Get-ItemProperty $path -ErrorAction SilentlyContinue).VBAWarnings;"
        "    if ($val -eq 1) { $found = $true }"
        "  }"
        "};"
        "$found"
    )
    out = _ps(ps_cmd)
    return out.lower() == "true"


def check_applocker_absent() -> bool:
    """True = AppLocker has no active rules configured (risky)."""
    # Check if AppLocker service (AppIDSvc) is running AND has rules
    svc = _ps("(Get-Service -Name 'AppIDSvc' -ErrorAction SilentlyContinue).Status")
    if svc.lower() != "running":
        return True  # service not running = AppLocker not enforced
    # Check for any enforced rule collections
    out = _ps(
        "(Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue)"
        ".RuleCollections.Count"
    )
    try:
        return int(out.strip()) == 0
    except Exception:
        return True  # if we can't read, assume absent


# ── CHECK MANIFEST ─────────────────────────────────────────────────────────────
CHECKS = [
    # ── Entry Vector (30 pts) ──────────────────────────────────────────────────
    ("rdp_open",                 "Checking RDP port 3389...",              check_rdp_open),
    ("smb_v1_enabled",           "Checking SMBv1 protocol...",             check_smb_v1),
    ("autorun_enabled",          "Checking AutoRun settings...",           check_autorun_enabled),
    ("open_network_shares",      "Checking open network shares...",        check_open_network_shares),

    # ── Execution (25 pts) ────────────────────────────────────────────────────
    ("macro_execution_enabled",  "Checking Office macro settings...",      check_macro_execution_enabled),
    ("powershell_unrestricted",  "Checking PowerShell policy...",          check_powershell_unrestricted),
    ("uac_disabled",             "Checking UAC (User Account Control)...", check_uac_disabled),
    ("applocker_absent",         "Checking AppLocker policy...",           check_applocker_absent),

    # ── Evasion / Persistence (20 pts) ───────────────────────────────────────
    ("defender_disabled",        "Checking Windows Defender...",           check_defender_disabled),
    ("firewall_on",              "Checking Windows Firewall...",            check_firewall_on),
    ("tamper_protection_off",    "Checking Tamper Protection...",          check_tamper_protection_off),
    ("event_logging_disabled",   "Checking Event Log service...",          check_event_logging_disabled),

    # ── Lateral Movement (15 pts) ────────────────────────────────────────────
    ("admin_shares_enabled",     "Checking default admin shares...",       check_admin_shares),
    ("lsass_protection_off",     "Checking LSASS protection...",           check_lsass_protection_off),
    ("guest_account_active",     "Checking Guest account status...",       check_guest_account),

    # ── Recovery Prevention (10 pts) ─────────────────────────────────────────
    ("vss_deleted",              "Checking Volume Shadow Copies...",       check_vss_deleted),
    ("backup_configured",        "Checking backup service...",             check_backup_configured),
    ("bitlocker_off",            "Checking BitLocker encryption...",       check_bitlocker_off),
]


def run_all_checks(status_cb=None) -> dict:
    results = {}
    for key, label, fn in CHECKS:
        if status_cb:
            status_cb(label)
        try:
            results[key] = fn()
        except Exception:
            results[key] = False
    return results


# ── GUI: SERVER IP SETUP DIALOG ───────────────────────────────────────────────
class SetupDialog(tk.Tk):
    """Shown only on first run — asks for server IP and saves it."""

    def __init__(self):
        super().__init__()
        self.result = None
        self.title("R3P Scanner — Setup")
        self.configure(bg=COLORS["bg"])
        self.resizable(False, False)
        self._center(430, 250)
        self._build()

    def _center(self, w, h):
        self.update_idletasks()
        x = (self.winfo_screenwidth() - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _build(self):
        tk.Frame(self, bg=COLORS["accent"], height=4).pack(fill="x")
        body = tk.Frame(self, bg=COLORS["bg"], padx=36, pady=28)
        body.pack(fill="both", expand=True)

        tk.Label(body, text="🛡  R3P Scanner",
                 font=("Segoe UI", 15, "bold"),
                 bg=COLORS["bg"], fg=COLORS["text"]).pack(anchor="w")

        tk.Label(body,
                 text="Enter your server IP or ngrok URL:",
                 font=("Segoe UI", 9), bg=COLORS["bg"], fg=COLORS["subtle"],
                 justify="left").pack(anchor="w", pady=(6, 2))

        examples = (
            "Examples:\n"
            "  Same network:  192.168.1.105\n"
            "  ngrok tunnel:  abc123.ngrok.io"
        )
        tk.Label(body, text=examples,
                 font=("Consolas", 8), bg=COLORS["bg"], fg=COLORS["subtle"],
                 justify="left").pack(anchor="w", pady=(0, 6))

        self.ip_var = tk.StringVar(value="")
        entry = tk.Entry(body, textvariable=self.ip_var,
                         font=("Consolas", 12),
                         bg=COLORS["card"], fg=COLORS["text"],
                         insertbackground=COLORS["text"],
                         relief="flat", bd=8, width=24,
                         highlightthickness=1,
                         highlightcolor=COLORS["accent"],
                         highlightbackground=COLORS["border"])
        entry.pack(anchor="w")
        entry.icursor(tk.END)
        entry.focus_set()
        entry.bind("<Return>", lambda _: self._submit())

        tk.Button(body, text="Connect & Scan  →",
                  font=("Segoe UI", 10, "bold"),
                  bg=COLORS["accent"], fg="white",
                  activebackground="#7c73ff", activeforeground="white",
                  relief="flat", bd=0, padx=18, pady=7,
                  cursor="hand2", command=self._submit).pack(anchor="w", pady=(16, 0))

    def _submit(self):
        ip = self.ip_var.get().strip()
        if not ip:
            return
        save_server_ip(ip)
        self.result = ip
        self.destroy()


# ── GUI: MAIN SCANNER WINDOW ──────────────────────────────────────────────────
class ScannerApp(tk.Tk):

    def __init__(self, server_ip: str):
        super().__init__()
        self.server_ip = server_ip
        self.api_url = build_api_url(server_ip)
        self.title("R3P — Ransomware Readiness Scanner")
        self.configure(bg=COLORS["bg"])
        self.resizable(False, False)
        self._center(500, 480)
        self._build_scanning_ui()
        self.after(400, lambda: threading.Thread(
            target=self._scan_worker, daemon=True).start())

    def _center(self, w, h):
        self.update_idletasks()
        x = (self.winfo_screenwidth() - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

    # ── scanning layout ─────────────────────────────────────────────────────
    def _build_scanning_ui(self):
        tk.Frame(self, bg=COLORS["accent"], height=4).pack(fill="x")

        hdr = tk.Frame(self, bg=COLORS["bg"], pady=18)
        hdr.pack(fill="x", padx=30)
        tk.Label(hdr, text="🛡  R3P Scanner",
                 font=("Segoe UI", 17, "bold"),
                 bg=COLORS["bg"], fg=COLORS["text"]).pack(anchor="w")
        tk.Label(hdr, text="Ransomware Readiness & Risk Profiler",
                 font=("Segoe UI", 9), bg=COLORS["bg"], fg=COLORS["subtle"]).pack(anchor="w")

        self.scan_card = tk.Frame(self, bg=COLORS["card"],
                                  highlightthickness=1,
                                  highlightbackground=COLORS["border"])
        self.scan_card.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        inner = tk.Frame(self.scan_card, bg=COLORS["card"], padx=28, pady=28)
        inner.pack(fill="both", expand=True)

        tk.Label(inner, text="Scanning your system…",
                 font=("Segoe UI", 11, "bold"),
                 bg=COLORS["card"], fg=COLORS["text"]).pack(anchor="w")

        self.status_lbl = tk.Label(inner, text="Initializing…",
                                   font=("Segoe UI", 9),
                                   bg=COLORS["card"], fg=COLORS["subtle"],
                                   anchor="w")
        self.status_lbl.pack(anchor="w", pady=(6, 12), fill="x")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("R3P.Horizontal.TProgressbar",
                         troughcolor=COLORS["border"],
                         background=COLORS["accent"],
                         bordercolor=COLORS["card"],
                         lightcolor=COLORS["accent"],
                         darkcolor=COLORS["accent"])
        self.bar = ttk.Progressbar(inner, style="R3P.Horizontal.TProgressbar",
                                   mode="indeterminate", length=420)
        self.bar.pack(anchor="w")
        self.bar.start(8)

        tk.Label(inner, text=f"Server: {self.server_ip}:{SERVER_PORT}",
                 font=("Consolas", 8),
                 bg=COLORS["card"], fg=COLORS["subtle"]).pack(anchor="w", pady=(16, 0))

        self.footer = tk.Frame(self, bg=COLORS["bg"], pady=10)
        self.footer.pack(fill="x")
        self.close_btn = tk.Button(self.footer, text="Please wait…",
                                   font=("Segoe UI", 9),
                                   bg=COLORS["border"], fg=COLORS["subtle"],
                                   relief="flat", bd=0, padx=18, pady=6,
                                   state="disabled", command=self.destroy)
        self.close_btn.pack()

    def _set_status(self, msg: str):
        self.status_lbl.config(text=msg)
        self.update_idletasks()

    # ── background worker ───────────────────────────────────────────────────
    def _scan_worker(self):
        data = run_all_checks(lambda m: self.after(0, self._set_status, m))
        self.after(0, self._set_status, "Sending results to server…")

        payload = {
            "host_id":   platform.node(),
            "os":        get_os_info(),
            "ip":        get_local_ip(),
            "timestamp": datetime.now().isoformat(),
            "data":      data,
        }

        try:
            resp = requests.post(self.api_url, json=payload, timeout=15)
            if resp.status_code == 200:
                self.after(0, self._show_result, resp.json())
            else:
                self.after(0, self._show_error,
                           f"Server returned HTTP {resp.status_code}.\n{resp.text[:200]}")
        except requests.exceptions.ConnectionError:
            self.after(0, self._show_error,
                       f"Cannot reach server at {self.server_ip}:{SERVER_PORT}.\n\n"
                       "Make sure the R3P backend is running.\n\n"
                       "Delete r3p_server.txt next to this app to re-enter the IP.")
        except Exception as exc:
            self.after(0, self._show_error, str(exc))

    # ── result layout ───────────────────────────────────────────────────────
    def _show_result(self, result: dict):
        self.bar.stop()
        self.scan_card.destroy()

        risk_class = result.get("risk_class", "UNKNOWN")
        risk_score = result.get("risk_score", 0)
        flagged    = result.get("flagged", [])
        color = RISK_COLORS.get(risk_class, COLORS["subtle"])

        card = tk.Frame(self, bg=COLORS["card"],
                        highlightthickness=1,
                        highlightbackground=COLORS["border"])
        card.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        inner = tk.Frame(card, bg=COLORS["card"], padx=28, pady=22)
        inner.pack(fill="both", expand=True)

        # risk badge
        badge = tk.Frame(inner, bg=color, padx=14, pady=5)
        badge.pack(anchor="w", pady=(0, 12))
        tk.Label(badge, text=f"  {risk_class}  ",
                 font=("Segoe UI", 13, "bold"),
                 bg=color, fg="white").pack()

        # score row
        row = tk.Frame(inner, bg=COLORS["card"])
        row.pack(anchor="w", pady=(0, 4))
        tk.Label(row, text="Risk Score: ",
                 font=("Segoe UI", 10),
                 bg=COLORS["card"], fg=COLORS["subtle"]).pack(side="left")
        tk.Label(row, text=f"{risk_score} / 100",
                 font=("Segoe UI", 10, "bold"),
                 bg=COLORS["card"], fg=color).pack(side="left")

        tk.Label(inner,
                 text=f"Machine: {platform.node()}   |   "
                      f"{len(flagged)} / {len(CHECKS)} checks flagged",
                 font=("Segoe UI", 8),
                 bg=COLORS["card"], fg=COLORS["subtle"]).pack(anchor="w", pady=(0, 12))

        tk.Frame(inner, bg=COLORS["border"], height=1).pack(fill="x", pady=(0, 10))

        if flagged:
            tk.Label(inner, text="⚠  Issues Found:",
                     font=("Segoe UI", 9, "bold"),
                     bg=COLORS["card"], fg=COLORS["warning"]).pack(anchor="w", pady=(0, 4))
            for item in flagged[:10]:
                r2 = tk.Frame(inner, bg=COLORS["card"])
                r2.pack(anchor="w", pady=1)
                tk.Label(r2, text="•",
                         font=("Segoe UI", 9),
                         bg=COLORS["card"], fg=color).pack(side="left", padx=(8, 4))
                tk.Label(r2, text=item.replace("_", " ").title(),
                         font=("Segoe UI", 9),
                         bg=COLORS["card"], fg=COLORS["text"]).pack(side="left")
            if len(flagged) > 10:
                tk.Label(inner,
                         text=f"   … and {len(flagged) - 10} more (see server dashboard)",
                         font=("Segoe UI", 8),
                         bg=COLORS["card"], fg=COLORS["subtle"]).pack(anchor="w")
        else:
            tk.Label(inner, text="✅  No issues detected — system looks clean!",
                     font=("Segoe UI", 10),
                     bg=COLORS["card"], fg=COLORS["safe"]).pack(anchor="w")

        tk.Label(inner, text="✓ Results saved to R3P server",
                 font=("Segoe UI", 8),
                 bg=COLORS["card"], fg=COLORS["safe"]).pack(anchor="w", pady=(10, 0))

        self.close_btn.config(text="Close", state="normal",
                              bg=COLORS["accent"], fg="white",
                              activebackground="#7c73ff")

    def _show_error(self, msg: str):
        self.bar.stop()
        self.status_lbl.config(text=f"❌ Error:\n\n{msg}",
                               fg=COLORS["high"],
                               font=("Segoe UI", 9),
                               justify="left", wraplength=420)
        self.close_btn.config(text="Close", state="normal",
                              bg=COLORS["border"], fg=COLORS["text"])


# ── ENTRY POINT ───────────────────────────────────────────────────────────────
def main():
    server_ip = load_server_ip()

    if not server_ip:
        dlg = SetupDialog()
        dlg.mainloop()
        server_ip = dlg.result
        if not server_ip:
            sys.exit(0)

    app = ScannerApp(server_ip)
    app.mainloop()


if __name__ == "__main__":
    main()