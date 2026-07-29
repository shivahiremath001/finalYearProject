"""
R3P Agent — Ransomware Readiness & Risk Profiler
Continuous monitoring edition (v2).

Changes from v1:
  • 60-second continuous scan loop — collects and sends simultaneously
  • Command polling: after each scan, checks for admin-issued remediation commands
  • Remediation executor: runs allowlisted PowerShell fixes and ACKs the server
  • Windows auto-start: registers itself in HKCU Run key on first run
  • Updated GUI: countdown timer, live score badge, command status label

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
import time
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

_BASE = os.path.dirname(
    sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)
)
CONFIG_FILE        = os.path.join(_BASE, "r3p_server.txt")
AGENT_CONFIG_FILE  = os.path.join(_BASE, "agent_config.json")

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
    "info":     "#58a6ff",
}

RISK_COLORS = {
    "SAFE":      COLORS["safe"],
    "LOW RISK":  COLORS["low"],
    "HIGH RISK": COLORS["high"],
    "CRITICAL":  COLORS["critical"],
}

# ── REMEDIATION ALLOWLIST (must mirror backend/remediation_registry.py) ───────
# SECURITY: Only keys cross the network. PowerShell lives here, locally.
AGENT_REMEDIATION = {
    "disable_smb1": (
        "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force; "
        "Write-Output 'SMBv1 disabled successfully.'"
    ),
    "block_rdp": (
        "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' "
        "-Name 'fDenyTSConnections' -Value 1; "
        "Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue; "
        "Write-Output 'RDP disabled.'"
    ),
    "disable_autorun": (
        "$path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer'; "
        "If (!(Test-Path $path)) { New-Item -Path $path -Force }; "
        "Set-ItemProperty -Path $path -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord; "
        "Write-Output 'AutoRun disabled.'"
    ),
    "restrict_powershell": (
        "Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force; "
        "Write-Output 'PowerShell execution policy set to RemoteSigned.'"
    ),
    "enable_uac": (
        "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
        "-Name 'EnableLUA' -Value 1; "
        "Write-Output 'UAC enabled.'"
    ),
    "enable_defender": (
        "Set-MpPreference -DisableRealtimeMonitoring $false; "
        "Start-Service -Name WinDefend -ErrorAction SilentlyContinue; "
        "Write-Output 'Windows Defender enabled.'"
    ),
    "enable_firewall": (
        "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True; "
        "Write-Output 'Windows Firewall enabled.'"
    ),
    "enable_tamper_protection": (
        "Set-MpPreference -DisableTamperProtection $false -ErrorAction SilentlyContinue; "
        "Write-Output 'Tamper Protection set.'"
    ),
    "enable_event_log": (
        "Set-Service -Name 'eventlog' -StartupType Automatic; "
        "Start-Service -Name 'eventlog'; "
        "Write-Output 'Event Log service started.'"
    ),
    "disable_guest": (
        "Disable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue; "
        "Write-Output 'Guest account disabled.'"
    ),
    "enable_lsass_protection": (
        "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
        "-Name 'RunAsPPL' -Value 1 -Type DWord; "
        "Write-Output 'LSASS PPL protection enabled.'"
    ),
}


# ── CONFIG PERSISTENCE ────────────────────────────────────────────────────────
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


def load_agent_config() -> dict:
    defaults = {
        "api_key": "R3P-DEMO-KEY",
        "scan_interval_seconds": 60,
        "command_poll_enabled": True,
        "auto_start_enabled": True,
    }
    try:
        if os.path.exists(AGENT_CONFIG_FILE):
            with open(AGENT_CONFIG_FILE, "r") as f:
                data = json.load(f)
                defaults.update(data)
    except Exception:
        pass
    return defaults


def build_api_url(server_input: str) -> str:
    s = server_input.strip().rstrip("/")
    if s.startswith("http://") or s.startswith("https://"):
        return s.rstrip("/")
    if "." in s and ":" not in s and not s.replace(".", "").isdigit():
        return f"https://{s}"
    if ":" not in s:
        return f"http://{s}:{SERVER_PORT}"
    return f"http://{s}"


# ── WINDOWS AUTO-START ────────────────────────────────────────────────────────
def register_auto_start():
    """
    Register this executable in HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
    so R3P Agent runs automatically on Windows login.
    Only registers if running as a frozen .exe and auto_start_enabled = True.
    """
    if not getattr(sys, "frozen", False):
        return  # Don't register during development (only .exe)
    config = load_agent_config()
    if not config.get("auto_start_enabled", True):
        return
    try:
        exe_path = sys.executable
        reg_key = (
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
        )
        subprocess.run(
            ["reg", "add", reg_key, "/v", "R3P_Agent", "/t", "REG_SZ",
             "/d", f'"{exe_path}"', "/f"],
            capture_output=True, check=False
        )
    except Exception:
        pass


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
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    result = s.connect_ex(("127.0.0.1", 3389))
    s.close()
    return result == 0


def check_firewall_on() -> bool:
    out = _ps("(Get-NetFirewallProfile | Where-Object { $_.Enabled -eq $false }).Count")
    try:
        return int(out) == 0
    except Exception:
        out2 = _ps("netsh advfirewall show allprofiles state")
        return "ON" in out2.upper()


def check_smb_v1() -> bool:
    out = _ps("(Get-SmbServerConfiguration).EnableSMB1Protocol")
    return out.lower() == "true"


def check_defender_disabled() -> bool:
    out = _ps("(Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled")
    return out.lower() != "true"


def check_tamper_protection_off() -> bool:
    out = _ps("(Get-MpComputerStatus -ErrorAction SilentlyContinue).IsTamperProtected")
    return out.lower() != "true"


def check_uac_disabled() -> bool:
    out = _ps(
        r"(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"
        r"\Policies\System' -ErrorAction SilentlyContinue).EnableLUA"
    )
    return out.strip() == "0"


def check_powershell_unrestricted() -> bool:
    out = _ps("Get-ExecutionPolicy").lower()
    return out in ("unrestricted", "bypass")


def check_autorun_enabled() -> bool:
    out = _ps(
        r"(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion"
        r"\Policies\Explorer' -ErrorAction SilentlyContinue).NoDriveTypeAutoRun"
    )
    try:
        return int(out.strip()) != 255
    except Exception:
        return True


def check_guest_account() -> bool:
    out = _ps("(Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue).Enabled")
    return out.lower() == "true"


def check_lsass_protection_off() -> bool:
    out = _ps(
        r"(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'"
        r" -ErrorAction SilentlyContinue).RunAsPPL"
    )
    return out.strip() != "1"


def check_admin_shares() -> bool:
    out = _ps(
        "(Get-SmbShare -ErrorAction SilentlyContinue"
        r" | Where-Object { $_.Name -match 'ADMIN\$|C\$' }).Count"
    )
    try:
        return int(out.strip()) > 0
    except Exception:
        return False


def check_event_logging_disabled() -> bool:
    out = _ps("(Get-Service -Name 'eventlog').Status")
    return out.lower() != "running"


def check_vss_deleted() -> bool:
    out = _ps(
        "(Get-WmiObject Win32_ShadowCopy -ErrorAction SilentlyContinue"
        " | Measure-Object).Count"
    )
    try:
        return int(out.strip()) == 0
    except Exception:
        return False


def check_backup_configured() -> bool:
    out = _ps("(Get-Service -Name 'SDRSVC' -ErrorAction SilentlyContinue).Status")
    return out.lower() == "running"


def check_bitlocker_off() -> bool:
    out = _ps(
        "(Get-BitLockerVolume -MountPoint 'C:' -ErrorAction SilentlyContinue)"
        ".VolumeStatus"
    )
    return "fullyencrypted" not in out.lower()


def check_open_network_shares() -> bool:
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
    svc = _ps("(Get-Service -Name 'AppIDSvc' -ErrorAction SilentlyContinue).Status")
    if svc.lower() != "running":
        return True
    out = _ps(
        "(Get-AppLockerPolicy -Effective -ErrorAction SilentlyContinue)"
        ".RuleCollections.Count"
    )
    try:
        return int(out.strip()) == 0
    except Exception:
        return True


# ── CHECK MANIFEST ─────────────────────────────────────────────────────────────
CHECKS = [
    ("rdp_open",                 "Checking RDP port 3389...",              check_rdp_open),
    ("smb_v1_enabled",           "Checking SMBv1 protocol...",             check_smb_v1),
    ("autorun_enabled",          "Checking AutoRun settings...",           check_autorun_enabled),
    ("open_network_shares",      "Checking open network shares...",        check_open_network_shares),
    ("macro_execution_enabled",  "Checking Office macro settings...",      check_macro_execution_enabled),
    ("powershell_unrestricted",  "Checking PowerShell policy...",          check_powershell_unrestricted),
    ("uac_disabled",             "Checking UAC (User Account Control)...", check_uac_disabled),
    ("applocker_absent",         "Checking AppLocker policy...",           check_applocker_absent),
    ("defender_disabled",        "Checking Windows Defender...",           check_defender_disabled),
    ("firewall_on",              "Checking Windows Firewall...",           check_firewall_on),
    ("tamper_protection_off",    "Checking Tamper Protection...",          check_tamper_protection_off),
    ("event_logging_disabled",   "Checking Event Log service...",          check_event_logging_disabled),
    ("admin_shares_enabled",     "Checking default admin shares...",       check_admin_shares),
    ("lsass_protection_off",     "Checking LSASS protection...",           check_lsass_protection_off),
    ("guest_account_active",     "Checking Guest account status...",       check_guest_account),
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


# ── REMEDIATION EXECUTOR ──────────────────────────────────────────────────────
def execute_remediation(cmd_key: str) -> tuple[bool, str]:
    """
    Look up the PowerShell command from the LOCAL allowlist and execute it.
    Returns (success: bool, output: str).
    NEVER executes a command key not present in AGENT_REMEDIATION.
    """
    ps_cmd = AGENT_REMEDIATION.get(cmd_key)
    if ps_cmd is None:
        return False, f"REJECTED: Unknown command key '{cmd_key}' not in local allowlist."

    try:
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=30,
            creationflags=flags,
        )
        output = (r.stdout + r.stderr).strip()
        success = r.returncode == 0
        return success, output or ("Success" if success else "No output")
    except subprocess.TimeoutExpired:
        return False, "FAILED: PowerShell command timed out after 30 seconds."
    except Exception as e:
        return False, f"FAILED: {e}"


# ── GUI: SERVER IP SETUP DIALOG ───────────────────────────────────────────────
class SetupDialog(tk.Tk):
    """Shown only on first run — asks for server IP."""

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

        tk.Button(body, text="Connect & Start Monitoring  →",
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


# ── GUI: MAIN MONITOR WINDOW ──────────────────────────────────────────────────
class MonitorApp(tk.Tk):

    def __init__(self, server_ip: str):
        super().__init__()
        self.server_ip      = server_ip
        self.base_url       = build_api_url(server_ip)
        self.config_data    = load_agent_config()
        self.scan_interval  = int(self.config_data.get("scan_interval_seconds", 60))
        self.api_key        = self.config_data.get("api_key", "R3P-DEMO-KEY")
        self.cmd_poll_on    = self.config_data.get("command_poll_enabled", True)

        self._stop_event    = threading.Event()
        self._last_result   = None
        self._next_scan_at  = None
        self._cmd_label_text = tk.StringVar(value="")

        self.title("R3P — Continuous Security Monitor")
        self.configure(bg=COLORS["bg"])
        self.resizable(False, False)
        self._center(520, 560)
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Start the continuous monitoring loop
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True
        )
        self._monitor_thread.start()

        # Start the countdown ticker (runs on main thread via `after`)
        self._tick_countdown()

    def _center(self, w, h):
        self.update_idletasks()
        x = (self.winfo_screenwidth() - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

    # ── UI Layout ─────────────────────────────────────────────────────────
    def _build_ui(self):
        tk.Frame(self, bg=COLORS["accent"], height=4).pack(fill="x")

        # Header
        hdr = tk.Frame(self, bg=COLORS["bg"], pady=14)
        hdr.pack(fill="x", padx=26)
        tk.Label(hdr, text="🛡  R3P Monitor",
                 font=("Segoe UI", 17, "bold"),
                 bg=COLORS["bg"], fg=COLORS["text"]).pack(anchor="w")
        tk.Label(hdr, text="Continuous Ransomware Readiness Monitoring",
                 font=("Segoe UI", 9), bg=COLORS["bg"], fg=COLORS["subtle"]).pack(anchor="w")

        # Status card
        self.status_card = tk.Frame(self, bg=COLORS["card"],
                                    highlightthickness=1,
                                    highlightbackground=COLORS["border"])
        self.status_card.pack(fill="x", padx=20, pady=(0, 6))
        inner_s = tk.Frame(self.status_card, bg=COLORS["card"], padx=22, pady=16)
        inner_s.pack(fill="x")

        # Live indicator dot
        dot_row = tk.Frame(inner_s, bg=COLORS["card"])
        dot_row.pack(anchor="w")
        self.dot_canvas = tk.Canvas(dot_row, bg=COLORS["card"], width=12, height=12,
                                    highlightthickness=0)
        self.dot_canvas.pack(side="left", padx=(0, 6))
        self._dot = self.dot_canvas.create_oval(2, 2, 10, 10, fill=COLORS["subtle"], outline="")
        self.monitor_label = tk.Label(dot_row, text="Initializing…",
                                      font=("Segoe UI", 10, "bold"),
                                      bg=COLORS["card"], fg=COLORS["text"])
        self.monitor_label.pack(side="left")

        self.status_lbl = tk.Label(inner_s, text="Starting first scan…",
                                   font=("Segoe UI", 9),
                                   bg=COLORS["card"], fg=COLORS["subtle"],
                                   anchor="w")
        self.status_lbl.pack(anchor="w", pady=(4, 0), fill="x")

        # Timer row
        timer_row = tk.Frame(inner_s, bg=COLORS["card"])
        timer_row.pack(anchor="w", pady=(6, 0))
        tk.Label(timer_row, text="Next scan in:",
                 font=("Segoe UI", 8), bg=COLORS["card"], fg=COLORS["subtle"]).pack(side="left")
        self.countdown_lbl = tk.Label(timer_row, text="–",
                                      font=("Consolas", 9, "bold"),
                                      bg=COLORS["card"], fg=COLORS["accent"])
        self.countdown_lbl.pack(side="left", padx=(6, 0))

        # Command notification label
        self.cmd_lbl = tk.Label(inner_s, textvariable=self._cmd_label_text,
                                font=("Segoe UI", 8, "italic"),
                                bg=COLORS["card"], fg=COLORS["info"],
                                anchor="w", wraplength=440)
        self.cmd_lbl.pack(anchor="w", pady=(4, 0), fill="x")

        # Result card
        self.result_card = tk.Frame(self, bg=COLORS["card"],
                                    highlightthickness=1,
                                    highlightbackground=COLORS["border"])
        self.result_card.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        self.result_inner = tk.Frame(self.result_card, bg=COLORS["card"], padx=22, pady=18)
        self.result_inner.pack(fill="both", expand=True)

        tk.Label(self.result_inner, text="Waiting for first scan result…",
                 font=("Segoe UI", 10),
                 bg=COLORS["card"], fg=COLORS["subtle"]).pack(anchor="w")

        # Footer
        footer = tk.Frame(self, bg=COLORS["bg"], pady=8)
        footer.pack(fill="x")
        self.close_btn = tk.Button(footer, text="Stop Monitoring & Close",
                                   font=("Segoe UI", 9),
                                   bg=COLORS["border"], fg=COLORS["text"],
                                   relief="flat", bd=0, padx=18, pady=6,
                                   cursor="hand2", command=self._on_close)
        self.close_btn.pack()

    # ── Helpers ───────────────────────────────────────────────────────────
    def _set_status(self, msg: str):
        self.after(0, lambda: self.status_lbl.config(text=msg))
        self.update_idletasks()

    def _set_dot(self, color: str):
        self.after(0, lambda: self.dot_canvas.itemconfig(self._dot, fill=color))

    def _set_cmd_notice(self, msg: str):
        self.after(0, lambda: self._cmd_label_text.set(msg))

    def _tick_countdown(self):
        """Update the countdown label every second."""
        if self._next_scan_at is not None:
            remaining = max(0, int(self._next_scan_at - time.time()))
            self.countdown_lbl.config(text=f"{remaining}s")
        self.after(1000, self._tick_countdown)

    def _pulse_dot(self):
        """Flash green dot to indicate a live scan is transmitting."""
        self._set_dot(COLORS["safe"])
        self.after(800, lambda: self._set_dot(COLORS["accent"]))

    # ── Continuous monitoring loop (background thread) ────────────────────
    def _monitor_loop(self):
        """
        Main continuous loop:
          1. Run all security checks
          2. POST telemetry to /ingest
          3. Poll for pending remediation commands
          4. Execute any commands found
          5. Sleep until next cycle
        """
        cycle = 0
        while not self._stop_event.is_set():
            cycle += 1
            t_start = time.time()

            # Update GUI
            self.after(0, lambda c=cycle: self.monitor_label.config(
                text=f"🔄  Monitoring Active  [scan #{c}]"
            ))
            self._set_dot(COLORS["accent"])

            # ── Step 1: Run checks ────────────────────────────────────────
            self._set_status(f"Scan #{cycle} — collecting telemetry…")
            data = run_all_checks(lambda m: self._set_status(m))

            # ── Step 2: POST /ingest ──────────────────────────────────────
            self._set_status("Sending telemetry to server…")
            result = self._send_telemetry(data)
            if result:
                self.after(0, self._update_result_card, result)
                self._pulse_dot()
                self._set_status(
                    f"Scan #{cycle} complete — "
                    f"Score: {result.get('risk_score', '?')} | "
                    f"{result.get('risk_class', '?')} | "
                    f"Last sent: {datetime.now().strftime('%H:%M:%S')}"
                )
            else:
                self._set_status(f"Scan #{cycle} — ⚠ Could not reach server")
                self._set_dot(COLORS["high"])

            # ── Step 3: Poll for commands ─────────────────────────────────
            if self.cmd_poll_on and result:
                self._poll_and_execute_commands()

            # ── Step 4: Sleep until next cycle ───────────────────────────
            elapsed = time.time() - t_start
            sleep_time = max(1, self.scan_interval - elapsed)
            self._next_scan_at = time.time() + sleep_time
            self._stop_event.wait(timeout=sleep_time)

    def _send_telemetry(self, data: dict) -> dict | None:
        payload = {
            "host_id":   platform.node(),
            "os":        get_os_info(),
            "ip":        get_local_ip(),
            "timestamp": datetime.now().isoformat(),
            "data":      data,
        }
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            resp = requests.post(
                f"{self.base_url}/ingest",
                json=payload,
                headers={"X-API-Key": self.api_key},
                timeout=15,
                verify=False,
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            print(f"[SEND ERROR] {e}")
        return None

    def _poll_and_execute_commands(self):
        """Poll for pending commands, execute them, and ACK each one."""
        try:
            resp = requests.get(
                f"{self.base_url}/commands/{platform.node()}",
                headers={"X-API-Key": self.api_key},
                timeout=10,
                verify=False,
            )
            if resp.status_code != 200:
                return
            commands = resp.json()
        except Exception:
            return

        for cmd in commands:
            cmd_id  = cmd.get("id")
            cmd_key = cmd.get("command_key", "")

            self._set_cmd_notice(f"⚙ Executing remote fix: '{cmd_key}'…")
            success, output = execute_remediation(cmd_key)

            self._ack_command(cmd_id, "done" if success else "failed", output)
            notice = (
                f"✅ Fix applied: '{cmd_key}'" if success
                else f"❌ Fix failed: '{cmd_key}' — {output[:60]}"
            )
            self._set_cmd_notice(notice)
            # Clear notice after 30 seconds
            self.after(30000, lambda: self._cmd_label_text.set(""))

    def _ack_command(self, cmd_id: int, status: str, output: str):
        try:
            requests.post(
                f"{self.base_url}/commands/{platform.node()}/{cmd_id}/ack",
                json={"status": status, "output": output},
                headers={"X-API-Key": self.api_key},
                timeout=10,
                verify=False,
            )
        except Exception:
            pass

    # ── Result card update ────────────────────────────────────────────────
    def _update_result_card(self, result: dict):
        # Destroy old widgets
        for w in self.result_inner.winfo_children():
            w.destroy()

        risk_class = result.get("risk_class", "UNKNOWN")
        risk_score = result.get("risk_score", 0)
        flagged    = result.get("flagged", {})
        color = RISK_COLORS.get(risk_class, COLORS["subtle"])

        # Risk badge
        badge = tk.Frame(self.result_inner, bg=color, padx=14, pady=5)
        badge.pack(anchor="w", pady=(0, 10))
        tk.Label(badge, text=f"  {risk_class}  ",
                 font=("Segoe UI", 13, "bold"),
                 bg=color, fg="white").pack()

        # Score row
        row = tk.Frame(self.result_inner, bg=COLORS["card"])
        row.pack(anchor="w", pady=(0, 4))
        tk.Label(row, text="Risk Score: ",
                 font=("Segoe UI", 10),
                 bg=COLORS["card"], fg=COLORS["subtle"]).pack(side="left")
        tk.Label(row, text=f"{risk_score} / 100",
                 font=("Segoe UI", 10, "bold"),
                 bg=COLORS["card"], fg=color).pack(side="left")

        if isinstance(flagged, dict):
            total_flagged = sum(len(v) for v in flagged.values())
        else:
            total_flagged = len(flagged)

        tk.Label(self.result_inner,
                 text=f"Machine: {platform.node()}   |   {total_flagged} issues flagged",
                 font=("Segoe UI", 8),
                 bg=COLORS["card"], fg=COLORS["subtle"]).pack(anchor="w", pady=(0, 10))

        tk.Frame(self.result_inner, bg=COLORS["border"], height=1).pack(fill="x", pady=(0, 8))

        if total_flagged > 0:
            tk.Label(self.result_inner, text="⚠  Issues Detected:",
                     font=("Segoe UI", 9, "bold"),
                     bg=COLORS["card"], fg=COLORS["warning"]).pack(anchor="w", pady=(0, 4))

            if isinstance(flagged, dict):
                for phase, items in flagged.items():
                    if not items:
                        continue
                    tk.Label(self.result_inner, text=f"[{phase}]",
                             font=("Segoe UI", 8, "bold"),
                             bg=COLORS["card"], fg=COLORS["subtle"]).pack(anchor="w", pady=(6, 2))
                    for item in items:
                        r2 = tk.Frame(self.result_inner, bg=COLORS["card"])
                        r2.pack(anchor="w", pady=1)
                        tk.Label(r2, text="•",
                                 font=("Segoe UI", 9),
                                 bg=COLORS["card"], fg=color).pack(side="left", padx=(8, 4))
                        tk.Label(r2, text=item.replace("_", " ").title(),
                                 font=("Segoe UI", 9),
                                 bg=COLORS["card"], fg=COLORS["text"]).pack(side="left")
        else:
            tk.Label(self.result_inner, text="✅  No issues detected — system looks clean!",
                     font=("Segoe UI", 10),
                     bg=COLORS["card"], fg=COLORS["safe"]).pack(anchor="w")

        tk.Label(self.result_inner, text="✓ Results streaming to R3P admin dashboard",
                 font=("Segoe UI", 8),
                 bg=COLORS["card"], fg=COLORS["safe"]).pack(anchor="w", pady=(10, 0))

    def _on_close(self):
        self._stop_event.set()
        self.destroy()


# ── ENTRY POINT ───────────────────────────────────────────────────────────────
def main():
    # Register auto-start (only if .exe)
    register_auto_start()

    server_ip = load_server_ip()

    if not server_ip:
        dlg = SetupDialog()
        dlg.mainloop()
        server_ip = dlg.result
        if not server_ip:
            sys.exit(0)

    app = MonitorApp(server_ip)
    app.mainloop()


if __name__ == "__main__":
    main()