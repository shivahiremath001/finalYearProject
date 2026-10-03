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

# ── requests import with friendly error ───────────────────────────────────────
ABOUT_INFO = {
    "smb_v1_enabled": (
        "SMBv1 Enabled",
        "SMBv1 is the exploit vector used by WannaCry and NotPetya. Disabling it closes the most common ransomware propagation path.",
    ),
    "rdp_open": (
        "RDP Port 3389 Open",
        "An open RDP port allows brute-force and credential-stuffing attacks. Disabling the Remote Desktop service blocks this.",
    ),
    "autorun_enabled": (
        "USB AutoRun Enabled",
        "AutoRun allows malicious USB devices to execute code automatically on insert.",
    ),
    "powershell_unrestricted": (
        "PowerShell Unrestricted",
        "An Unrestricted or Bypass policy allows any script to run without warning.",
    ),
    "uac_disabled": (
        "UAC Disabled",
        "UAC prevents unauthorized privilege escalation. Without it, malware can silently gain SYSTEM privileges.",
    ),
    "defender_disabled": (
        "Defender Disabled",
        "Real-time protection is the primary anti-malware defence on Windows. Ransomware frequently disables it.",
    ),
    "firewall_on": (
        "Firewall Disabled",
        "The firewall blocks unsolicited inbound connections. Disabling it exposes every open port directly to the network.",
    ),
    "tamper_protection_off": (
        "Tamper Protection Off",
        "Tamper Protection prevents malware from disabling Defender settings via registry or PowerShell.",
    ),
    "event_logging_disabled": (
        "Event Logging Disabled",
        "The Event Log service records security events. Without it, attacks leave no trace.",
    ),
    "guest_account_active": (
        "Guest Account Active",
        "The Guest account provides unauthenticated network access, a trivial pivot point for lateral movement.",
    ),
    "lsass_protection_off": (
        "LSASS Protection Off",
        "LSASS stores credentials in memory. Without PPL protection, tools like Mimikatz can dump plaintext passwords.",
    ),
    "open_network_shares": (
        "Open Network Shares",
        "Open shares accessible to 'Everyone' allow ransomware to easily encrypt data across the entire network.",
    ),
    "macro_execution_enabled": (
        "Office Macros Enabled",
        "Malicious Office documents use macros to download and execute ransomware payloads.",
    ),
    "applocker_absent": (
        "AppLocker Absent",
        "AppLocker restricts which applications can run. Without it, unauthorized malware executables can run freely.",
    ),
    "admin_shares_enabled": (
        "Admin Shares Enabled",
        "Default hidden admin shares (C$, ADMIN$) are frequently used by ransomware to move laterally across the network.",
    ),
    "vss_deleted": (
        "Volume Shadow Copies Deleted",
        "Ransomware deletes Volume Shadow Copies to prevent you from easily restoring encrypted files.",
    ),
    "backup_configured": (
        "Backup Not Configured",
        "Without a working backup service, recovery after a ransomware encryption event is nearly impossible.",
    ),
    "bitlocker_off": (
        "BitLocker Encryption Off",
        "Without full disk encryption, physical theft or unauthorized access can easily compromise all stored data.",
    ),
    "wdigest_enabled": (
        "WDigest Credentials Enabled",
        "WDigest stores passwords in clear text in LSASS memory, allowing for easy credential dumping.",
    ),
    "laps_absent": (
        "LAPS Absent",
        "Without Microsoft LAPS, local admin passwords are often shared, enabling Pass-the-Hash lateral movement.",
    ),
    "nla_disabled": (
        "RDP NLA Disabled",
        "Without Network Level Authentication, RDP is vulnerable to pre-authentication attacks and DoS.",
    ),
    "always_install_elevated": (
        "AlwaysInstallElevated Enabled",
        "This policy allows any standard user to install MSI packages with SYSTEM privileges, a massive escalation vector.",
    ),
}

try:
    import requests
except ImportError:
    _root = tk.Tk()
    _root.withdraw()
    import tkinter.messagebox as mb

    mb.showerror(
        "Missing Library",
        "The 'requests' library is not installed.\n\nRun:  pip install requests",
    )
    sys.exit(1)

# ── CONSTANTS ──────────────────────────────────────────────────────────────────
SERVER_PORT = 8000

_BASE = os.path.dirname(
    sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__)
)
CONFIG_FILE = os.path.join(_BASE, "r3p_server.txt")
AGENT_CONFIG_FILE = os.path.join(_BASE, "agent_config.json")

COLORS = {
    "bg": "#111111",
    "card": "#111111",
    "border": "#333333",
    "accent": "#555555",
    "text": "#dddddd",
    "subtle": "#777777",
    "safe": "#4caf50",
    "low": "#ff9800",
    "high": "#f44336",
    "critical": "#d32f2f",
    "warning": "#ffeb3b",
    "info": "#2196f3",
}

RISK_COLORS = {
    "SAFE": COLORS["safe"],
    "LOW RISK": COLORS["low"],
    "HIGH RISK": COLORS["high"],
    "CRITICAL": COLORS["critical"],
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
        "Write-Output 'Tamper Protection change attempted; verify effective state.'"
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
    "always_install_elevated": "disable_always_install_elevated",
    "vulnerable_driver_blocklist_enabled": "enable_vulnerable_driver_blocklist",
    "hvci_enabled": "enable_hvci",
    "asr_rules_configured": "enable_asr_rules",
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
        "asset_type": "Workstation",
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
            capture_output=True,
            text=True,
            timeout=timeout,
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
    out = _ps(
        "(Get-MpComputerStatus -ErrorAction SilentlyContinue).RealTimeProtectionEnabled"
    )
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
        '    $path = "HKCU:\\SOFTWARE\\Microsoft\\Office\\$ver\\$app\\Security";'
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


def check_wdigest_enabled() -> bool:
    out = _ps(
        r"(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest' "
        r"-ErrorAction SilentlyContinue).UseLogonCredential"
    )
    return out.strip() == "1"


def check_laps_absent() -> bool:
    out = _ps(r"Get-Command -Module LAPS -ErrorAction SilentlyContinue")
    return out.strip() == ""


def check_nla_disabled() -> bool:
    out = _ps(
        r"(Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' "
        r"-ErrorAction SilentlyContinue).UserAuthentication"
    )
    return out.strip() == "0"


def check_always_install_elevated() -> bool:
    out = _ps(
        r"(Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' "
        r"-ErrorAction SilentlyContinue).AlwaysInstallElevated"
    )
    return out.strip() == "1"


def check_vulnerable_driver_blocklist_enabled() -> bool:
    out = _ps(
        r"(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' "
        r"-ErrorAction SilentlyContinue).VulnerableDriverBlocklistEnable"
    )
    return out.strip() == "1"


def check_hvci_enabled() -> bool:
    out = _ps(
        r"(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' "
        r"-ErrorAction SilentlyContinue).Enabled"
    )
    return out.strip() == "1"


def check_asr_rules_configured() -> bool:
    out = _ps(
        r"(Get-MpPreference -ErrorAction SilentlyContinue).AttackSurfaceReductionRules_Ids.Count"
    )
    try:
        return int(out.strip()) > 0
    except Exception:
        return False


# ── ACTIVE VALIDATION (MOCK ATTACKS) ───────────────────────────────────────────
def run_mock_attack_vss_enum() -> bool:
    """
    Simulates ransomware looking for Shadow Copies to delete.
    Returns True if BLOCKED (Safe), False if SUCCEEDED (Risky).
    """
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", "Get-WmiObject Win32_ShadowCopy -ErrorAction Stop"],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=flags,
        )
        if r.returncode != 0:
            return True # Blocked by ASR/EDR
        return False # Succeeded
    except Exception:
        return True


def run_mock_attack_mass_rename() -> bool:
    """
    Simulates ransomware rapidly renaming files to .locked.
    Returns True if BLOCKED/KILLED (Safe), False if ALL 100 renamed (Risky).
    """
    import tempfile
    import shutil

    try:
        temp_dir = os.path.join(tempfile.gettempdir(), "r3p_mock_attack")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
        os.makedirs(temp_dir, exist_ok=True)

        # Drop dummy files
        for i in range(100):
            with open(os.path.join(temp_dir, f"dummy_{i}.txt"), "w") as f:
                f.write("mock_data")

        script = f"""
        $files = Get-ChildItem -Path "{temp_dir}" -Filter "*.txt"
        foreach ($file in $files) {{
            Rename-Item -Path $file.FullName -NewName ($file.Name + ".locked") -ErrorAction SilentlyContinue
        }}
        """

        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        r = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ],
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=flags,
        )

        # Verify
        locked_files = [f for f in os.listdir(temp_dir) if f.endswith(".locked")]

        # Clean up
        shutil.rmtree(temp_dir, ignore_errors=True)

        if r.returncode != 0 or len(locked_files) < 100:
            return True  # Blocked or interrupted
        return False  # Successfully renamed all 100 files (EDR failed to block)

    except Exception:
        return True  # Something blocked or crashed it


# ── CHECK MANIFEST ─────────────────────────────────────────────────────────────
CHECKS = [
    ("rdp_open", "Checking RDP port 3389...", check_rdp_open),
    ("smb_v1_enabled", "Checking SMBv1 protocol...", check_smb_v1),
    ("autorun_enabled", "Checking AutoRun settings...", check_autorun_enabled),
    (
        "open_network_shares",
        "Checking open network shares...",
        check_open_network_shares,
    ),
    (
        "macro_execution_enabled",
        "Checking Office macro settings...",
        check_macro_execution_enabled,
    ),
    (
        "powershell_unrestricted",
        "Checking PowerShell policy...",
        check_powershell_unrestricted,
    ),
    ("uac_disabled", "Checking UAC (User Account Control)...", check_uac_disabled),
    ("applocker_absent", "Checking AppLocker policy...", check_applocker_absent),
    ("defender_disabled", "Checking Windows Defender...", check_defender_disabled),
    ("firewall_on", "Checking Windows Firewall...", check_firewall_on),
    (
        "tamper_protection_off",
        "Checking Tamper Protection...",
        check_tamper_protection_off,
    ),
    (
        "event_logging_disabled",
        "Checking Event Log service...",
        check_event_logging_disabled,
    ),
    ("admin_shares_enabled", "Checking default admin shares...", check_admin_shares),
    (
        "lsass_protection_off",
        "Checking LSASS protection...",
        check_lsass_protection_off,
    ),
    ("guest_account_active", "Checking Guest account status...", check_guest_account),
    ("vss_deleted", "Checking Volume Shadow Copies...", check_vss_deleted),
    ("backup_configured", "Checking backup service...", check_backup_configured),
    ("bitlocker_off", "Checking BitLocker encryption...", check_bitlocker_off),
    ("wdigest_enabled", "Checking WDigest credentials...", check_wdigest_enabled),
    ("laps_absent", "Checking LAPS installation...", check_laps_absent),
    ("nla_disabled", "Checking RDP NLA...", check_nla_disabled),
    (
        "always_install_elevated",
        "Checking AlwaysInstallElevated...",
        check_always_install_elevated,
    ),
    (
        "vulnerable_driver_blocklist_enabled",
        "Checking BYOVD Blocklist...",
        check_vulnerable_driver_blocklist_enabled,
    ),
    ("hvci_enabled", "Checking HVCI Memory Integrity...", check_hvci_enabled),
    ("asr_rules_configured", "Checking ASR Rules...", check_asr_rules_configured),
    (
        "mock_attack_vss_enum_blocked",
        "Running Mock Attack: VSS Enumeration...",
        run_mock_attack_vss_enum,
    ),
    (
        "mock_attack_mass_rename_blocked",
        "Running Mock Attack: Mass File Rename...",
        run_mock_attack_mass_rename,
    ),
]


def run_all_checks(status_cb=None) -> dict:
    results = {}

    def _run_check(key, label, fn):
        if status_cb:
            status_cb(label)
        try:
            return key, fn()
        except Exception:
            return key, False

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [
            executor.submit(_run_check, key, label, fn) for key, label, fn in CHECKS
        ]
        for future in concurrent.futures.as_completed(futures):
            k, v = future.result()
            results[k] = v

    return results


# ── REMEDIATION EXECUTOR ──────────────────────────────────────────────────────
AGENT_REMEDIATION = {
    "disable_smb1": "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force; Write-Output 'SMBv1 disabled successfully.'",
    "block_rdp": "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 1; Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue; Write-Output 'RDP disabled.'",
    "disable_autorun": "$path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer'; If (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord; Write-Output 'AutoRun disabled.'",
    "restrict_powershell": "Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force; Write-Output 'PowerShell policy updated.'",
    "enable_uac": "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -Value 1; Write-Output 'UAC enabled.'",
    "enable_defender": "Set-MpPreference -DisableRealtimeMonitoring $false; Start-Service -Name WinDefend -ErrorAction SilentlyContinue; Write-Output 'Defender enabled.'",
    "enable_firewall": "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True; Write-Output 'Firewall enabled.'",
    "enable_tamper_protection": "Set-MpPreference -DisableTamperProtection $false -ErrorAction SilentlyContinue; Write-Output 'Tamper Protection change attempted; verify effective state.'",
    "enable_event_log": "Set-Service -Name 'eventlog' -StartupType Automatic; Start-Service -Name 'eventlog'; Write-Output 'Event log started.'",
    "disable_guest": "Disable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue; Write-Output 'Guest disabled.'",
    "enable_lsass_protection": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL' -Value 1 -Type DWord; Write-Output 'LSASS protection enabled.'",
    "disable_wdigest": "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name 'UseLogonCredential' -Value 0 -Type DWord; Write-Output 'WDigest disabled.'",
    "enable_nla": "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 1 -Type DWord; Write-Output 'NLA enabled.'",
    "disable_always_install_elevated": "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue; Remove-ItemProperty -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue; Write-Output 'AlwaysInstallElevated disabled.'",
    "enable_vulnerable_driver_blocklist": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config' -Name 'VulnerableDriverBlocklistEnable' -Value 1 -Type DWord; Write-Output 'Blocklist enabled.'",
    "enable_hvci": "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity' -Name 'Enabled' -Value 1 -Type DWord; Write-Output 'HVCI enabled.'",
    "enable_asr_rules": "Add-MpPreference -AttackSurfaceReductionRules_Ids 'd4f940ab-401b-4efc-aadc-ad5f3c50688a' -AttackSurfaceReductionRules_Actions Enabled; Write-Output 'Basic ASR Rules enabled.'",
}


def execute_remediation(cmd_key: str) -> tuple[bool, str]:
    """
    Look up the PowerShell command from the LOCAL allowlist and execute it.
    Returns (success: bool, output: str).
    NEVER executes a command key not present in AGENT_REMEDIATION.
    """
    ps_cmd = AGENT_REMEDIATION.get(cmd_key)
    if ps_cmd is None:
        return (
            False,
            f"REJECTED: Unknown command key '{cmd_key}' not in local allowlist.",
        )

    try:
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        r = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                ps_cmd,
            ],
            capture_output=True,
            text=True,
            timeout=30,
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

        tk.Label(
            body,
            text="🛡  R3P Scanner",
            font=("Segoe UI", 15, "bold"),
            bg=COLORS["bg"],
            fg=COLORS["text"],
        ).pack(anchor="w")

        tk.Label(
            body,
            text="Enter your server IP or ngrok URL:",
            font=("Segoe UI", 9),
            bg=COLORS["bg"],
            fg=COLORS["subtle"],
            justify="left",
        ).pack(anchor="w", pady=(6, 2))

        examples = (
            "Examples:\n"
            "  Same network:  192.168.1.105\n"
            "  ngrok tunnel:  abc123.ngrok.io"
        )
        tk.Label(
            body,
            text=examples,
            font=("Consolas", 8),
            bg=COLORS["bg"],
            fg=COLORS["subtle"],
            justify="left",
        ).pack(anchor="w", pady=(0, 6))

        self.ip_var = tk.StringVar(value="")
        entry = tk.Entry(
            body,
            textvariable=self.ip_var,
            font=("Consolas", 12),
            bg=COLORS["card"],
            fg=COLORS["text"],
            insertbackground=COLORS["text"],
            relief="flat",
            bd=8,
            width=24,
            highlightthickness=1,
            highlightcolor=COLORS["accent"],
            highlightbackground=COLORS["border"],
        )
        entry.pack(anchor="w")
        entry.icursor(tk.END)
        entry.focus_set()
        entry.bind("<Return>", lambda _: self._submit())

        tk.Button(
            body,
            text="Connect & Start Monitoring  →",
            font=("Segoe UI", 10, "bold"),
            bg=COLORS["accent"],
            fg="white",
            activebackground="#7c73ff",
            activeforeground="white",
            relief="flat",
            bd=0,
            padx=18,
            pady=7,
            cursor="hand2",
            command=self._submit,
        ).pack(anchor="w", pady=(16, 0))

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
        self.server_ip = server_ip
        self.base_url = build_api_url(server_ip)
        self.config_data = load_agent_config()
        self.scan_interval = int(self.config_data.get("scan_interval_seconds", 60))
        self.api_key = self.config_data.get("api_key", "R3P-DEMO-KEY")
        self.cmd_poll_on = self.config_data.get("command_poll_enabled", True)

        self._stop_event = threading.Event()
        self._wake_event = threading.Event()
        self._last_result = None
        self._next_scan_at = None
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
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
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
        tk.Label(
            title_frame,
            text="🛡  R3P Monitor",
            font=("Segoe UI", 17, "bold"),
            bg=COLORS["bg"],
            fg=COLORS["text"],
        ).pack(anchor="w")
        tk.Label(
            title_frame,
            text="Continuous Ransomware Readiness Monitoring",
            font=("Segoe UI", 9),
            bg=COLORS["bg"],
            fg=COLORS["subtle"],
        ).pack(anchor="w")

        # Right side info button
        about_btn = tk.Button(
            hdr,
            text="ⓘ",
            font=("Segoe UI", 16, "bold"),
            bg=COLORS["bg"],
            fg=COLORS["info"],
            bd=0,
            activebackground=COLORS["bg"],
            activeforeground=COLORS["text"],
            cursor="hand2",
            command=self._show_about,
        )
        about_btn.pack(side="right", anchor="n")

        # Status card
        self.status_card = tk.Frame(
            self,
            bg=COLORS["card"],
            highlightthickness=1,
            highlightbackground=COLORS["border"],
        )
        self.status_card.pack(fill="x", padx=20, pady=(0, 6))
        inner_s = tk.Frame(self.status_card, bg=COLORS["card"], padx=22, pady=16)
        inner_s.pack(fill="x")

        # Live indicator dot
        dot_row = tk.Frame(inner_s, bg=COLORS["card"])
        dot_row.pack(anchor="w")
        self.dot_canvas = tk.Canvas(
            dot_row, bg=COLORS["card"], width=12, height=12, highlightthickness=0
        )
        self.dot_canvas.pack(side="left", padx=(0, 6))
        self._dot = self.dot_canvas.create_oval(
            2, 2, 10, 10, fill=COLORS["subtle"], outline=""
        )
        self.monitor_label = tk.Label(
            dot_row,
            text="Initializing…",
            font=("Segoe UI", 10, "bold"),
            bg=COLORS["card"],
            fg=COLORS["text"],
        )
        self.monitor_label.pack(side="left")

        self.status_lbl = tk.Label(
            inner_s,
            text="Starting first scan…",
            font=("Segoe UI", 9),
            bg=COLORS["card"],
            fg=COLORS["subtle"],
            anchor="w",
        )
        self.status_lbl.pack(anchor="w", pady=(4, 0), fill="x")

        # Timer row
        timer_row = tk.Frame(inner_s, bg=COLORS["card"])
        timer_row.pack(anchor="w", pady=(6, 0))
        tk.Label(
            timer_row,
            text="Next scan in:",
            font=("Segoe UI", 8),
            bg=COLORS["card"],
            fg=COLORS["subtle"],
        ).pack(side="left")
        self.countdown_lbl = tk.Label(
            timer_row,
            text="–",
            font=("Consolas", 9, "bold"),
            bg=COLORS["card"],
            fg=COLORS["accent"],
        )
        self.countdown_lbl.pack(side="left", padx=(6, 0))

        # Command notification label
        self.cmd_lbl = tk.Label(
            inner_s,
            textvariable=self._cmd_label_text,
            font=("Segoe UI", 8, "italic"),
            bg=COLORS["card"],
            fg=COLORS["info"],
            anchor="w",
            wraplength=440,
        )
        self.cmd_lbl.pack(anchor="w", pady=(4, 0), fill="x")

        # Result card with scrollable canvas
        self.result_card = tk.Frame(
            self,
            bg=COLORS["card"],
            highlightthickness=1,
            highlightbackground=COLORS["border"],
        )
        self.result_card.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        self.result_canvas = tk.Canvas(
            self.result_card, bg=COLORS["card"], highlightthickness=0
        )
        self.result_scrollbar = ttk.Scrollbar(
            self.result_card, orient="vertical", command=self.result_canvas.yview
        )

        self.result_inner = tk.Frame(
            self.result_canvas, bg=COLORS["card"], padx=10, pady=10
        )

        self.result_inner.bind(
            "<Configure>",
            lambda e: self.result_canvas.configure(
                scrollregion=self.result_canvas.bbox("all")
            ),
        )

        self.result_canvas.create_window(
            (0, 0), window=self.result_inner, anchor="nw", width=380
        )
        self.result_canvas.configure(yscrollcommand=self.result_scrollbar.set)

        self.result_canvas.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        self.result_scrollbar.pack(side="right", fill="y")

        self.scrollable_canvas = self.result_canvas
        self.bind_all("<MouseWheel>", self._on_mousewheel)

        tk.Label(
            self.result_inner,
            text="Waiting for first scan result…",
            font=("Segoe UI", 10),
            bg=COLORS["card"],
            fg=COLORS["subtle"],
        ).pack(anchor="w")

        # Footer
        footer = tk.Frame(self, bg=COLORS["bg"], pady=8)
        footer.pack(fill="x")
        self.close_btn = tk.Button(
            footer,
            text="Hide to System Tray",
            font=("Segoe UI", 9),
            bg=COLORS["border"],
            fg=COLORS["text"],
            relief="flat",
            bd=0,
            padx=18,
            pady=6,
            cursor="hand2",
            command=self._on_close,
        )
        self.close_btn.pack()

    # ── Helpers ───────────────────────────────────────────────────────────
    def _on_mousewheel(self, event):
        """Scroll the canvas that is currently hovered."""
        widget = self.winfo_containing(event.x_root, event.y_root)
        if widget:
            toplevel = widget.winfo_toplevel()
            if hasattr(toplevel, "scrollable_canvas"):
                toplevel.scrollable_canvas.yview_scroll(
                    int(-1 * (event.delta / 120)), "units"
                )

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
        img = Image.new("RGB", (64, 64), color=(13, 17, 23))
        d = ImageDraw.Draw(img)
        d.ellipse([16, 16, 48, 48], fill=(108, 99, 255))
        return img

    def _setup_tray(self):
        menu = pystray.Menu(
            item("Show Dashboard", self._show_window, default=True),
            item("Quit", self._quit_app),
        )
        self.tray_icon = pystray.Icon(
            "R3P_Agent", self._create_tray_image(), "R3P Agent", menu
        )

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
            self.after(
                0,
                lambda c=cycle: self.monitor_label.config(
                    text=f"🔄  Monitoring Active  [scan #{c}]"
                ),
            )
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
        payload = {
            "host_id": platform.node(),
            "os": get_os_info(),
            "asset_type": load_agent_config().get("asset_type", "Workstation"),
            "ip": get_local_ip(),
            "timestamp": datetime.now().isoformat(),
            "data": data,
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
            cmd_id = cmd.get("id")
            cmd_key = cmd.get("command_key", "")

            self._set_cmd_notice(f"⚙ Executing remote fix: '{cmd_key}'…")
            success, output = execute_remediation(cmd_key)

            self._ack_command(cmd_id, "done" if success else "failed", output)
            notice = (
                f"✅ Fix applied: '{cmd_key}'"
                if success
                else f"❌ Fix failed: '{cmd_key}' — {output[:60]}"
            )
            self._set_cmd_notice(notice)
            # Clear notice after 30 seconds
            self.after(30000, lambda: self._cmd_label_text.set(""))

        if commands:
            # Re-scan immediately after remote changes so the server response
            # verifies the resulting state instead of waiting a full interval.
            self._wake_event.set()

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
        flagged = result.get("flagged", {})
        color = RISK_COLORS.get(risk_class, COLORS["subtle"])

        # Risk badge
        badge = tk.Frame(self.result_inner, bg=color, padx=14, pady=5)
        badge.pack(anchor="w", pady=(0, 10))
        tk.Label(
            badge,
            text=f"  {risk_class}  ",
            font=("Segoe UI", 13, "bold"),
            bg=color,
            fg="white",
        ).pack()

        # Score row
        row = tk.Frame(self.result_inner, bg=COLORS["card"])
        row.pack(anchor="w", pady=(0, 4))
        tk.Label(
            row,
            text="Risk Score: ",
            font=("Segoe UI", 10),
            bg=COLORS["card"],
            fg=COLORS["subtle"],
        ).pack(side="left")
        tk.Label(
            row,
            text=f"{risk_score} / 100",
            font=("Segoe UI", 10, "bold"),
            bg=COLORS["card"],
            fg=color,
        ).pack(side="left")

        if isinstance(flagged, dict):
            total_flagged = sum(len(v) for v in flagged.values())
        else:
            total_flagged = len(flagged)

        tk.Label(
            self.result_inner,
            text=f"Machine: {platform.node()}   |   {total_flagged} issues flagged",
            font=("Segoe UI", 8),
            bg=COLORS["card"],
            fg=COLORS["subtle"],
        ).pack(anchor="w", pady=(0, 10))

        policy_exceptions = result.get("policy_exceptions", [])
        if policy_exceptions:
            tk.Label(
                self.result_inner,
                text=f"Policy exceptions ({len(policy_exceptions)}) — excluded from this score:",
                font=("Segoe UI", 9, "bold"),
                bg=COLORS["card"],
                fg=COLORS["info"],
            ).pack(anchor="w", pady=(0, 3))
            for exception in policy_exceptions:
                param = exception.get("param_key", "unknown").replace("_", " ").title()
                reason = exception.get("reason") or "No business justification provided"
                tk.Label(
                    self.result_inner,
                    text=f"• {param}: {reason}",
                    font=("Segoe UI", 8),
                    bg=COLORS["card"],
                    fg=COLORS["subtle"],
                    wraplength=360,
                    justify="left",
                ).pack(anchor="w", padx=(8, 0), pady=(0, 3))

        tk.Frame(self.result_inner, bg=COLORS["border"], height=1).pack(
            fill="x", pady=(0, 8)
        )

        if total_flagged > 0:
            tk.Label(
                self.result_inner,
                text="⚠  Issues Detected:",
                font=("Segoe UI", 9, "bold"),
                bg=COLORS["card"],
                fg=COLORS["warning"],
            ).pack(anchor="w", pady=(0, 4))

            if isinstance(flagged, dict):
                for phase, items in flagged.items():
                    if not items:
                        continue
                    tk.Label(
                        self.result_inner,
                        text=f"[{phase}]",
                        font=("Segoe UI", 8, "bold"),
                        bg=COLORS["card"],
                        fg=COLORS["subtle"],
                    ).pack(anchor="w", pady=(6, 2))
                    for flag_item in items:
                        r2 = tk.Frame(self.result_inner, bg=COLORS["card"])
                        r2.pack(anchor="w", pady=1)
                        tk.Label(
                            r2,
                            text="•",
                            font=("Segoe UI", 9),
                            bg=COLORS["card"],
                            fg=color,
                        ).pack(side="left", padx=(8, 4))

                        tk.Label(
                            r2,
                            text=flag_item.replace("_", " ").title(),
                            font=("Segoe UI", 9),
                            bg=COLORS["card"],
                            fg=COLORS["text"],
                        ).pack(side="left")

                        cmd_key = PARAM_TO_CMD_KEY.get(flag_item)
                        if cmd_key:
                            tk.Button(
                                r2,
                                text="Fix",
                                font=("Segoe UI", 7, "bold"),
                                bg=COLORS["accent"],
                                fg="white",
                                activebackground=COLORS["safe"],
                                activeforeground="white",
                                relief="flat",
                                bd=0,
                                padx=6,
                                pady=2,
                                cursor="hand2",
                                command=lambda k=cmd_key: self._on_fix_clicked(k),
                            ).pack(side="right", padx=(0, 4))
        else:
            tk.Label(
                self.result_inner,
                text="✅  No issues detected — system looks clean!",
                font=("Segoe UI", 10),
                bg=COLORS["card"],
                fg=COLORS["safe"],
            ).pack(anchor="w")

        tk.Label(
            self.result_inner,
            text="✓ Results streaming to R3P admin dashboard",
            font=("Segoe UI", 8),
            bg=COLORS["card"],
            fg=COLORS["safe"],
        ).pack(anchor="w", pady=(10, 0))

    def _on_fix_clicked(self, cmd_key: str):
        # Run fix in a thread to prevent freezing the GUI
        threading.Thread(
            target=self._run_local_fix, args=(cmd_key,), daemon=True
        ).start()

    def _run_local_fix(self, cmd_key: str):
        self._set_cmd_notice(f"⚙ Executing local fix: '{cmd_key}'…")
        success, output = execute_remediation(cmd_key)
        notice = (
            f"✅ Fix applied: '{cmd_key}'"
            if success
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
            "<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw", width=460)
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        scrollbar.pack(side="right", fill="y")

        tk.Label(
            scrollable_frame,
            text="Security Configuration Guide",
            font=("Segoe UI", 16, "bold"),
            bg=COLORS["bg"],
            fg=COLORS["text"],
        ).pack(anchor="w", pady=(10, 20), padx=10)

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
            btn = tk.Label(
                container,
                text=f"► {title}",
                font=("Segoe UI", 10, "bold"),
                bg=COLORS["card"],
                fg=COLORS["text"],
                anchor="w",
                padx=10,
                pady=8,
                cursor="hand2",
            )
            btn.pack(fill="x")
            btn.bind("<Button-1>", lambda e, k=key: toggle_accordion(k))
            self.accordion_labels[key] = btn

            # Content frame (hidden initially)
            content_frame = tk.Frame(container, bg=COLORS["bg"])
            desc_lbl = tk.Label(
                content_frame,
                text=desc,
                font=("Segoe UI", 9),
                bg=COLORS["bg"],
                fg=COLORS["subtle"],
                wraplength=410,
                justify="left",
            )
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
