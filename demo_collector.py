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
import concurrent.futures
from datetime import datetime
import tkinter as tk
from tkinter import ttk
import pystray
from pystray import MenuItem as item
from PIL import Image, ImageDraw
import random
import string

FAKE_HOSTNAME = "DEMO-PC-" + "".join(random.choices(string.digits, k=4))
FAKE_IP = f"192.168.1.{random.randint(50, 200)}"
FAKE_OS = random.choice(["Windows 10 Pro", "Windows 11 Enterprise", "Windows Server 2022"])

MOCK_STATE = {
    "rdp_open": True,
    "smb_v1_enabled": True,
    "autorun_enabled": True,
    "open_network_shares": True,
    "macro_execution_enabled": True,
    "powershell_unrestricted": True,
    "uac_disabled": True,
    "applocker_absent": True,
    "defender_disabled": True,
    "firewall_on": False,
    "tamper_protection_off": True,
    "event_logging_disabled": True,
    "admin_shares_enabled": True,
    "lsass_protection_off": True,
    "guest_account_active": True,
    "vss_deleted": True,
    "backup_configured": False,
    "bitlocker_off": True,
    "wdigest_enabled": True,
    "laps_absent": True,
    "nla_disabled": True,
    "always_install_elevated": True
}
ABOUT_INFO = {
    "smb_v1_enabled": ("SMBv1 Enabled", "SMBv1 is the exploit vector used by WannaCry and NotPetya. Disabling it closes the most common ransomware propagation path."),
    "rdp_open": ("RDP Port 3389 Open", "An open RDP port allows brute-force and credential-stuffing attacks. Disabling the Remote Desktop service blocks this."),
    "autorun_enabled": ("USB AutoRun Enabled", "AutoRun allows malicious USB devices to execute code automatically on insert."),
    "powershell_unrestricted": ("PowerShell Unrestricted", "An Unrestricted or Bypass policy allows any script to run without warning."),
    "uac_disabled": ("UAC Disabled", "UAC prevents unauthorized privilege escalation. Without it, malware can silently gain SYSTEM privileges."),
    "defender_disabled": ("Defender Disabled", "Real-time protection is the primary anti-malware defence on Windows. Ransomware frequently disables it."),
    "firewall_on": ("Firewall Disabled", "The firewall blocks unsolicited inbound connections. Disabling it exposes every open port directly to the network."),
    "tamper_protection_off": ("Tamper Protection Off", "Tamper Protection prevents malware from disabling Defender settings via registry or PowerShell."),
    "event_logging_disabled": ("Event Logging Disabled", "The Event Log service records security events. Without it, attacks leave no trace."),
    "guest_account_active": ("Guest Account Active", "The Guest account provides unauthenticated network access, a trivial pivot point for lateral movement."),
    "lsass_protection_off": ("LSASS Protection Off", "LSASS stores credentials in memory. Without PPL protection, tools like Mimikatz can dump plaintext passwords."),
    "open_network_shares": ("Open Network Shares", "Open shares accessible to 'Everyone' allow ransomware to easily encrypt data across the entire network."),
    "macro_execution_enabled": ("Office Macros Enabled", "Malicious Office documents use macros to download and execute ransomware payloads."),
    "applocker_absent": ("AppLocker Absent", "AppLocker restricts which applications can run. Without it, unauthorized malware executables can run freely."),
    "admin_shares_enabled": ("Admin Shares Enabled", "Default hidden admin shares (C$, ADMIN$) are frequently used by ransomware to move laterally across the network."),
    "vss_deleted": ("Volume Shadow Copies Deleted", "Ransomware deletes Volume Shadow Copies to prevent you from easily restoring encrypted files."),
    "backup_configured": ("Backup Not Configured", "Without a working backup service, recovery after a ransomware encryption event is nearly impossible."),
    "bitlocker_off": ("BitLocker Encryption Off", "Without full disk encryption, physical theft or unauthorized access can easily compromise all stored data."),
    "wdigest_enabled": ("WDigest Credentials Enabled", "WDigest stores passwords in clear text in LSASS memory, allowing for easy credential dumping."),
    "laps_absent": ("LAPS Absent", "Without Microsoft LAPS, local admin passwords are often shared, enabling Pass-the-Hash lateral movement."),
    "nla_disabled": ("RDP NLA Disabled", "Without Network Level Authentication, RDP is vulnerable to pre-authentication attacks and DoS."),
    "always_install_elevated": ("AlwaysInstallElevated Enabled", "This policy allows any standard user to install MSI packages with SYSTEM privileges, a massive escalation vector.")
}

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
    "bg":       "#111111",
    "card":     "#111111",
    "border":   "#333333",
    "accent":   "#555555",
    "text":     "#dddddd",
    "subtle":   "#777777",
    "safe":     "#4caf50",
    "low":      "#ff9800",
    "high":     "#f44336",
    "critical": "#d32f2f",
    "warning":  "#ffeb3b",
    "info":     "#2196f3",
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
    "disable_wdigest": (
        "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' "
        "-Name 'UseLogonCredential' -Value 0 -Type DWord; "
        "Write-Output 'WDigest UseLogonCredential disabled.'"
    ),
    "enable_nla": (
        "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
        "-Name 'UserAuthentication' -Value 1 -Type DWord; "
        "Write-Output 'NLA enabled for RDP.'"
    ),
    "disable_always_install_elevated": (
        "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' "
        "-Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue; "
        "Remove-ItemProperty -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' "
        "-Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue; "
        "Write-Output 'AlwaysInstallElevated disabled.'"
    ),
}

PARAM_TO_CMD_KEY = {
    "smb_v1_enabled": "disable_smb1",
    "rdp_enabled": "block_rdp",
    "autorun_enabled": "disable_autorun",
    "powershell_unrestricted": "restrict_powershell",
    "uac_disabled": "enable_uac",
    "defender_disabled": "enable_defender",
    "firewall_disabled": "enable_firewall",
    "tamper_protection_off": "enable_tamper_protection",
    "event_logging_disabled": "enable_event_log",
    "guest_account_active": "disable_guest",
    "lsass_protection_off": "enable_lsass_protection",
    "wdigest_enabled": "disable_wdigest",
    "nla_disabled": "enable_nla",
    "always_install_elevated": "disable_always_install_elevated"
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
    Auto-start is now handled by setup_agent.bat via Windows Task Scheduler
    to ensure it runs with Administrator privileges silently.
    This function is intentionally a no-op.
    """
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
    return FAKE_OS


def get_local_ip() -> str:
    return FAKE_IP


# ── CHECK MANIFEST ─────────────────────────────────────────────────────────────
CHECKS_LABELS = {
    "rdp_open":                 "Checking RDP port 3389...",
    "smb_v1_enabled":           "Checking SMBv1 protocol...",
    "autorun_enabled":          "Checking AutoRun settings...",
    "open_network_shares":      "Checking open network shares...",
    "macro_execution_enabled":  "Checking Office macro settings...",
    "powershell_unrestricted":  "Checking PowerShell policy...",
    "uac_disabled":             "Checking UAC (User Account Control)...",
    "applocker_absent":         "Checking AppLocker policy...",
    "defender_disabled":        "Checking Windows Defender...",
    "firewall_on":              "Checking Windows Firewall...",
    "tamper_protection_off":    "Checking Tamper Protection...",
    "event_logging_disabled":   "Checking Event Log service...",
    "admin_shares_enabled":     "Checking default admin shares...",
    "lsass_protection_off":     "Checking LSASS protection...",
    "guest_account_active":     "Checking Guest account status...",
    "vss_deleted":              "Checking Volume Shadow Copies...",
    "backup_configured":        "Checking backup service...",
    "bitlocker_off":            "Checking BitLocker encryption...",
    "wdigest_enabled":          "Checking WDigest credentials...",
    "laps_absent":              "Checking LAPS installation...",
    "nla_disabled":             "Checking RDP NLA...",
    "always_install_elevated":  "Checking AlwaysInstallElevated..."
}

def run_all_checks(status_cb=None) -> dict:
    def _run_check(key, label):
        if status_cb:
            status_cb(label)
        time.sleep(0.05)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(_run_check, key, label) for key, label in CHECKS_LABELS.items()]
        concurrent.futures.wait(futures)

    return MOCK_STATE.copy()


# ── REMEDIATION EXECUTOR ──────────────────────────────────────────────────────
def execute_remediation(cmd_key: str) -> tuple[bool, str]:
    """Simulated Remediation Executor"""
    global MOCK_STATE
    time.sleep(1) # simulate work
    
    # Map command keys back to the mock state keys and apply the fix
    if cmd_key == "disable_smb1":
        MOCK_STATE["smb_v1_enabled"] = False
    elif cmd_key == "block_rdp":
        MOCK_STATE["rdp_open"] = False
    elif cmd_key == "disable_autorun":
        MOCK_STATE["autorun_enabled"] = False
    elif cmd_key == "restrict_powershell":
        MOCK_STATE["powershell_unrestricted"] = False
    elif cmd_key == "enable_uac":
        MOCK_STATE["uac_disabled"] = False
    elif cmd_key == "enable_defender":
        MOCK_STATE["defender_disabled"] = False
    elif cmd_key == "enable_firewall":
        MOCK_STATE["firewall_on"] = True
    elif cmd_key == "enable_tamper_protection":
        MOCK_STATE["tamper_protection_off"] = False
    elif cmd_key == "enable_event_log":
        MOCK_STATE["event_logging_disabled"] = False
    elif cmd_key == "disable_guest":
        MOCK_STATE["guest_account_active"] = False
    elif cmd_key == "enable_lsass_protection":
        MOCK_STATE["lsass_protection_off"] = False
    elif cmd_key == "disable_wdigest":
        MOCK_STATE["wdigest_enabled"] = False
    elif cmd_key == "enable_nla":
        MOCK_STATE["nla_disabled"] = False
    elif cmd_key == "disable_always_install_elevated":
        MOCK_STATE["always_install_elevated"] = False
    else:
        return False, f"Unknown demo command: {cmd_key}"
        
    return True, f"[SIMULATED] Successfully executed {cmd_key}"


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
        self._wake_event    = threading.Event()
        self._last_result   = None
        self._next_scan_at  = None
        self._cmd_label_text = tk.StringVar(value="")

        self.title("R3P — Continuous Security Monitor")
        self.configure(bg=COLORS["bg"])
        self.resizable(False, False)
        self._center(520, 560)
        self._build_ui()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Setup System Tray
        self._setup_tray()

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
        
        # Left side texts
        title_frame = tk.Frame(hdr, bg=COLORS["bg"])
        title_frame.pack(side="left")
        tk.Label(title_frame, text="🛡  R3P Monitor",
                 font=("Segoe UI", 17, "bold"),
                 bg=COLORS["bg"], fg=COLORS["text"]).pack(anchor="w")
        tk.Label(title_frame, text="Continuous Ransomware Readiness Monitoring",
                 font=("Segoe UI", 9), bg=COLORS["bg"], fg=COLORS["subtle"]).pack(anchor="w")
        
        # Right side info button
        about_btn = tk.Button(hdr, text="ⓘ", font=("Segoe UI", 16, "bold"),
                              bg=COLORS["bg"], fg=COLORS["info"], bd=0, 
                              activebackground=COLORS["bg"], activeforeground=COLORS["text"],
                              cursor="hand2", command=self._show_about)
        about_btn.pack(side="right", anchor="n")

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

        # Result card with scrollable canvas
        self.result_card = tk.Frame(self, bg=COLORS["card"],
                                    highlightthickness=1,
                                    highlightbackground=COLORS["border"])
        self.result_card.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        
        self.result_canvas = tk.Canvas(self.result_card, bg=COLORS["card"], highlightthickness=0)
        self.result_scrollbar = ttk.Scrollbar(self.result_card, orient="vertical", command=self.result_canvas.yview)
        
        self.result_inner = tk.Frame(self.result_canvas, bg=COLORS["card"], padx=10, pady=10)
        
        self.result_inner.bind(
            "<Configure>",
            lambda e: self.result_canvas.configure(scrollregion=self.result_canvas.bbox("all"))
        )
        
        self.result_canvas.create_window((0, 0), window=self.result_inner, anchor="nw", width=380)
        self.result_canvas.configure(yscrollcommand=self.result_scrollbar.set)
        
        self.result_canvas.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        self.result_scrollbar.pack(side="right", fill="y")
        
        self.scrollable_canvas = self.result_canvas
        self.bind_all("<MouseWheel>", self._on_mousewheel)

        tk.Label(self.result_inner, text="Waiting for first scan result…",
                 font=("Segoe UI", 10),
                 bg=COLORS["card"], fg=COLORS["subtle"]).pack(anchor="w")

        # Footer
        footer = tk.Frame(self, bg=COLORS["bg"], pady=8)
        footer.pack(fill="x")
        self.close_btn = tk.Button(footer, text="Hide to System Tray",
                                   font=("Segoe UI", 9),
                                   bg=COLORS["border"], fg=COLORS["text"],
                                   relief="flat", bd=0, padx=18, pady=6,
                                   cursor="hand2", command=self._on_close)
        self.close_btn.pack()

    # ── Helpers ───────────────────────────────────────────────────────────
    def _on_mousewheel(self, event):
        """Scroll the canvas that is currently hovered."""
        widget = self.winfo_containing(event.x_root, event.y_root)
        if widget:
            toplevel = widget.winfo_toplevel()
            if hasattr(toplevel, "scrollable_canvas"):
                toplevel.scrollable_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

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

    # ── System Tray Logic ─────────────────────────────────────────────────
    def _create_tray_image(self):
        # Create a simple shield/dot image for the tray
        img = Image.new('RGB', (64, 64), color=(13, 17, 23))
        d = ImageDraw.Draw(img)
        d.ellipse([16, 16, 48, 48], fill=(108, 99, 255))
        return img

    def _setup_tray(self):
        menu = pystray.Menu(
            item('Show Dashboard', self._show_window, default=True),
            item('Quit', self._quit_app)
        )
        self.tray_icon = pystray.Icon("R3P_Agent", self._create_tray_image(), "R3P Agent", menu)
        
        # Run tray in a separate thread so it doesn't block Tkinter
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def _show_window(self):
        self.after(0, self.deiconify)

    def _quit_app(self):
        self.tray_icon.stop()
        self._stop_event.set()
        self._wake_event.set()
        self.after(0, self.destroy)

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
            
            # Wait for wake event or timeout
            self._wake_event.wait(timeout=sleep_time)
            self._wake_event.clear()

    def _send_telemetry(self, data: dict) -> dict | None:
        # Simulate network delay for realism
        time.sleep(0.5)
        
        # Build flagged dict from MOCK_STATE directly (offline simulation)
        flagged = {
            "Entry Vector": [],
            "Execution": [],
            "Evasion & Persistence": [],
            "Lateral Movement": [],
            "Recovery Prevention": []
        }
        
        if MOCK_STATE["smb_v1_enabled"]: flagged["Entry Vector"].append("smb_v1_enabled")
        if MOCK_STATE["rdp_open"]: flagged["Entry Vector"].append("rdp_enabled")
        if MOCK_STATE["autorun_enabled"]: flagged["Entry Vector"].append("autorun_enabled")
        if MOCK_STATE["open_network_shares"]: flagged["Entry Vector"].append("open_network_shares")
        
        if MOCK_STATE["macro_execution_enabled"]: flagged["Execution"].append("macro_execution_enabled")
        if MOCK_STATE["powershell_unrestricted"]: flagged["Execution"].append("powershell_unrestricted")
        if MOCK_STATE["uac_disabled"]: flagged["Execution"].append("uac_disabled")
        if MOCK_STATE["applocker_absent"]: flagged["Execution"].append("applocker_absent")
        
        if MOCK_STATE["defender_disabled"]: flagged["Evasion & Persistence"].append("defender_disabled")
        if not MOCK_STATE["firewall_on"]: flagged["Evasion & Persistence"].append("firewall_disabled")
        if MOCK_STATE["tamper_protection_off"]: flagged["Evasion & Persistence"].append("tamper_protection_off")
        if MOCK_STATE["event_logging_disabled"]: flagged["Evasion & Persistence"].append("event_logging_disabled")
        
        if MOCK_STATE["admin_shares_enabled"]: flagged["Lateral Movement"].append("admin_shares_enabled")
        if MOCK_STATE["lsass_protection_off"]: flagged["Lateral Movement"].append("lsass_protection_off")
        if MOCK_STATE["guest_account_active"]: flagged["Lateral Movement"].append("guest_account_active")
        
        if MOCK_STATE["vss_deleted"]: flagged["Recovery Prevention"].append("vss_deleted")
        if not MOCK_STATE["backup_configured"]: flagged["Recovery Prevention"].append("backup_absent")
        if MOCK_STATE["bitlocker_off"]: flagged["Recovery Prevention"].append("bitlocker_off")
        
        # Clean empty phases
        flagged = {k: v for k, v in flagged.items() if v}
        
        # Calculate a mock score
        total_issues = sum(len(v) for v in flagged.values())
        if total_issues == 0:
            risk_score, risk_class = 0.0, "SAFE"
        else:
            # Quick mock formula
            risk_score = min(100.0, total_issues * 6.5)
            if risk_score < 20: risk_class = "SAFE"
            elif risk_score < 50: risk_class = "LOW RISK"
            elif risk_score < 80: risk_class = "HIGH RISK"
            else: risk_class = "CRITICAL"
        
        return {
            "message": "success",
            "hostname": FAKE_HOSTNAME,
            "risk_score": round(risk_score, 2),
            "risk_class": risk_class,
            "flagged": flagged
        }

    def _poll_and_execute_commands(self):
        """Offline demo: no remote polling."""
        pass

    def _ack_command(self, cmd_id: int, status: str, output: str):
        """Offline demo: no ACKs sent."""
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
                 text=f"Machine: {FAKE_HOSTNAME} (DEMO)  |   {total_flagged} issues flagged",
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
                        
                        cmd_key = PARAM_TO_CMD_KEY.get(item)
                        if cmd_key:
                            tk.Button(r2, text="Fix",
                                      font=("Segoe UI", 7, "bold"),
                                      bg=COLORS["accent"], fg="white",
                                      activebackground=COLORS["safe"], activeforeground="white",
                                      relief="flat", bd=0, padx=6, pady=2,
                                      cursor="hand2",
                                      command=lambda k=cmd_key: self._on_fix_clicked(k)).pack(side="right", padx=(0, 4))
        else:
            tk.Label(self.result_inner, text="✅  No issues detected — system looks clean!",
                     font=("Segoe UI", 10),
                     bg=COLORS["card"], fg=COLORS["safe"]).pack(anchor="w")

        tk.Label(self.result_inner, text="✓ Results streaming to R3P admin dashboard",
                 font=("Segoe UI", 8),
                 bg=COLORS["card"], fg=COLORS["safe"]).pack(anchor="w", pady=(10, 0))

    def _on_fix_clicked(self, cmd_key: str):
        # Run fix in a thread to prevent freezing the GUI
        threading.Thread(target=self._run_local_fix, args=(cmd_key,), daemon=True).start()

    def _run_local_fix(self, cmd_key: str):
        self._set_cmd_notice(f"⚙ Executing local fix: '{cmd_key}'…")
        success, output = execute_remediation(cmd_key)
        notice = (
            f"✅ Fix applied: '{cmd_key}'" if success
            else f"❌ Fix failed: '{cmd_key}' — {output[:60]}"
        )
        self._set_cmd_notice(notice)
        self.after(20000, lambda: self._cmd_label_text.set(""))
        
        # Trigger an immediate rescan
        self._wake_event.set()

    def _on_close(self):
        # Hide window instead of destroying it
        self.withdraw()

    def _show_about(self):
        """Displays an accordion-style modal explaining each security parameter."""
        about_win = tk.Toplevel(self)
        about_win.title("Security Parameters Explained")
        about_win.geometry("500x600")
        about_win.configure(bg=COLORS["bg"])
        about_win.attributes("-topmost", True)
        about_win.resizable(False, False)
        
        # Scrollable canvas for the accordion
        canvas = tk.Canvas(about_win, bg=COLORS["bg"], highlightthickness=0)
        about_win.scrollable_canvas = canvas
        
        scrollbar = ttk.Scrollbar(about_win, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=COLORS["bg"])
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw", width=460)
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        scrollbar.pack(side="right", fill="y")
        
        tk.Label(scrollable_frame, text="Security Configuration Guide",
                 font=("Segoe UI", 16, "bold"), bg=COLORS["bg"], fg=COLORS["text"]).pack(anchor="w", pady=(10, 20), padx=10)
        
        # Accordion Logic
        self.accordion_frames = {}
        self.accordion_labels = {}
        
        def toggle_accordion(key):
            # Close all
            for k, frame in self.accordion_frames.items():
                if k == key and not frame.winfo_ismapped():
                    frame.pack(fill="x", padx=10, pady=(0, 10))
                    self.accordion_labels[k].config(text=f"▼ {ABOUT_INFO[k][0]}")
                else:
                    frame.pack_forget()
                    self.accordion_labels[k].config(text=f"► {ABOUT_INFO[k][0]}")

        for key, (title, desc) in ABOUT_INFO.items():
            # Container for both button and content
            container = tk.Frame(scrollable_frame, bg=COLORS["bg"])
            container.pack(fill="x", padx=10, pady=(5, 0))
            
            # Header button
            btn = tk.Label(container, text=f"► {title}", font=("Segoe UI", 10, "bold"),
                           bg=COLORS["card"], fg=COLORS["text"], anchor="w", padx=10, pady=8, cursor="hand2")
            btn.pack(fill="x")
            btn.bind("<Button-1>", lambda e, k=key: toggle_accordion(k))
            self.accordion_labels[key] = btn
            
            # Content frame (hidden initially)
            content_frame = tk.Frame(container, bg=COLORS["bg"])
            desc_lbl = tk.Label(content_frame, text=desc, font=("Segoe UI", 9),
                                bg=COLORS["bg"], fg=COLORS["subtle"], wraplength=410, justify="left")
            desc_lbl.pack(anchor="w", padx=10, pady=10)
            
            self.accordion_frames[key] = content_frame


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