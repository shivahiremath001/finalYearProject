"""
remediation_registry.py — Allowlist of approved remote fix commands.

SECURITY MODEL:
  Only the command_key string is ever transmitted over the network.
  The actual PowerShell is defined here on the server AND duplicated in
  collector.py on the agent. The agent validates the key exists in its
  own local copy before executing anything. No arbitrary code execution.

Each entry:
  label       : Human-readable name shown in the dashboard
  description : Why this misconfiguration is dangerous
  phase       : Kill-chain phase it belongs to
  severity    : CRITICAL / HIGH / MEDIUM / LOW
  param_key   : Matches the internal scoring parameter name
  powershell  : The exact command executed on the endpoint
  reboot_required: True if a reboot is needed for the fix to take effect
"""

REMEDIATION_COMMANDS: dict[str, dict] = {

    # ── Entry Vector ──────────────────────────────────────────────────────────

    "disable_smb1": {
        "label": "Disable SMBv1",
        "description": (
            "SMBv1 is the exploit vector used by WannaCry and NotPetya. "
            "Disabling it closes the most common ransomware propagation path."
        ),
        "phase": "Entry Vector",
        "severity": "CRITICAL",
        "param_key": "smb_v1_enabled",
        "powershell": (
            "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force; "
            "Write-Output 'SMBv1 disabled successfully.'"
        ),
        "reboot_required": False,
    },

    "block_rdp": {
        "label": "Disable RDP (Block Port 3389)",
        "description": (
            "An open RDP port allows brute-force and credential-stuffing attacks. "
            "This disables the Remote Desktop service and blocks port 3389 via firewall."
        ),
        "phase": "Entry Vector",
        "severity": "HIGH",
        "param_key": "rdp_enabled",
        "powershell": (
            "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' "
            "-Name 'fDenyTSConnections' -Value 1; "
            "Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue; "
            "Write-Output 'RDP disabled and firewall rule blocked.'"
        ),
        "reboot_required": False,
    },

    "disable_autorun": {
        "label": "Disable USB AutoRun",
        "description": (
            "AutoRun allows malicious USB devices to execute code automatically on insert. "
            "Setting NoDriveTypeAutoRun=255 disables it for all drive types."
        ),
        "phase": "Entry Vector",
        "severity": "MEDIUM",
        "param_key": "autorun_enabled",
        "powershell": (
            "$path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer'; "
            "If (!(Test-Path $path)) { New-Item -Path $path -Force }; "
            "Set-ItemProperty -Path $path -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord; "
            "Write-Output 'AutoRun disabled for all drive types.'"
        ),
        "reboot_required": False,
    },

    # ── Execution ─────────────────────────────────────────────────────────────

    "restrict_powershell": {
        "label": "Restrict PowerShell Execution Policy",
        "description": (
            "An Unrestricted or Bypass policy allows any script to run without warning. "
            "RemoteSigned requires downloaded scripts to be signed by a trusted publisher."
        ),
        "phase": "Execution",
        "severity": "HIGH",
        "param_key": "powershell_unrestricted",
        "powershell": (
            "Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force; "
            "Write-Output 'PowerShell execution policy set to RemoteSigned.'"
        ),
        "reboot_required": False,
    },

    "enable_uac": {
        "label": "Enable User Account Control (UAC)",
        "description": (
            "UAC prevents unauthorized privilege escalation. "
            "Without it, malware can silently gain SYSTEM privileges."
        ),
        "phase": "Execution",
        "severity": "MEDIUM",
        "param_key": "uac_disabled",
        "powershell": (
            "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
            "-Name 'EnableLUA' -Value 1; "
            "Write-Output 'UAC enabled. A reboot is required for full effect.'"
        ),
        "reboot_required": True,
    },

    # ── Evasion & Persistence ─────────────────────────────────────────────────

    "enable_defender": {
        "label": "Enable Windows Defender Real-Time Protection",
        "description": (
            "Real-time protection is the primary anti-malware defence on Windows. "
            "Ransomware frequently disables it as an early step — re-enable immediately."
        ),
        "phase": "Evasion & Persistence",
        "severity": "HIGH",
        "param_key": "defender_disabled",
        "powershell": (
            "Set-MpPreference -DisableRealtimeMonitoring $false; "
            "Start-Service -Name WinDefend -ErrorAction SilentlyContinue; "
            "Write-Output 'Windows Defender real-time protection enabled.'"
        ),
        "reboot_required": False,
    },

    "enable_firewall": {
        "label": "Enable Windows Firewall (All Profiles)",
        "description": (
            "The firewall blocks unsolicited inbound connections. "
            "Disabling it exposes every open port directly to the network."
        ),
        "phase": "Evasion & Persistence",
        "severity": "HIGH",
        "param_key": "firewall_disabled",
        "powershell": (
            "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True; "
            "Write-Output 'Windows Firewall enabled on all profiles.'"
        ),
        "reboot_required": False,
    },

    "enable_tamper_protection": {
        "label": "Enable Defender Tamper Protection",
        "description": (
            "Tamper Protection prevents malware from disabling Defender settings via registry or PowerShell. "
            "Note: This can only be fully enabled via Windows Security Center or Intune on managed devices."
        ),
        "phase": "Evasion & Persistence",
        "severity": "MEDIUM",
        "param_key": "tamper_protection_off",
        "powershell": (
            "# Best-effort via registry — full enforcement requires Windows Security Center UI "
            "Set-MpPreference -DisableTamperProtection $false -ErrorAction SilentlyContinue; "
            "Write-Output 'Tamper Protection registry value set. Verify in Windows Security Center.'"
        ),
        "reboot_required": False,
    },

    "enable_event_log": {
        "label": "Start Windows Event Log Service",
        "description": (
            "The Event Log service records security events, logons, and process creation. "
            "Without it, attacks leave no trace and incident response is impossible."
        ),
        "phase": "Evasion & Persistence",
        "severity": "MEDIUM",
        "param_key": "event_logging_disabled",
        "powershell": (
            "Set-Service -Name 'eventlog' -StartupType Automatic; "
            "Start-Service -Name 'eventlog'; "
            "Write-Output 'Windows Event Log service started and set to Automatic.'"
        ),
        "reboot_required": False,
    },

    # ── Lateral Movement ──────────────────────────────────────────────────────

    "disable_guest": {
        "label": "Disable Guest Account",
        "description": (
            "The Guest account provides unauthenticated network access. "
            "It is a trivial pivot point for lateral movement in ransomware campaigns."
        ),
        "phase": "Lateral Movement",
        "severity": "MEDIUM",
        "param_key": "guest_account_active",
        "powershell": (
            "Disable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue; "
            "Write-Output 'Guest account disabled.'"
        ),
        "reboot_required": False,
    },

    "enable_lsass_protection": {
        "label": "Enable LSASS PPL Protection",
        "description": (
            "LSASS stores credentials in memory. Without PPL protection, tools like Mimikatz "
            "can dump plaintext passwords. Enabling PPL blocks this."
        ),
        "phase": "Lateral Movement",
        "severity": "CRITICAL",
        "param_key": "lsass_protection_off",
        "powershell": (
            "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
            "-Name 'RunAsPPL' -Value 1 -Type DWord; "
            "Write-Output 'LSASS PPL protection enabled. Reboot required.'"
        ),
        "reboot_required": True,
    },
    
    "disable_wdigest": {
        "label": "Disable WDigest Cleartext Credentials",
        "description": (
            "WDigest stores credentials in clear text in LSASS memory, making them easily retrievable by attackers. "
            "Disabling it prevents cleartext credential dumping."
        ),
        "phase": "Lateral Movement",
        "severity": "CRITICAL",
        "param_key": "wdigest_enabled",
        "powershell": (
            "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' "
            "-Name 'UseLogonCredential' -Value 0 -Type DWord; "
            "Write-Output 'WDigest UseLogonCredential disabled.'"
        ),
        "reboot_required": False,
    },
    
    "enable_nla": {
        "label": "Enable Network Level Authentication for RDP",
        "description": (
            "Without NLA, RDP connections establish a full session before authentication, "
            "exposing the server to DoS and pre-authentication vulnerabilities."
        ),
        "phase": "Entry Vector",
        "severity": "HIGH",
        "param_key": "nla_disabled",
        "powershell": (
            "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' "
            "-Name 'UserAuthentication' -Value 1 -Type DWord; "
            "Write-Output 'NLA enabled for RDP.'"
        ),
        "reboot_required": False,
    },
    
    "disable_always_install_elevated": {
        "label": "Disable AlwaysInstallElevated Policy",
        "description": (
            "This policy allows standard users to install MSI packages with SYSTEM privileges. "
            "It is a major privilege escalation vector."
        ),
        "phase": "Execution",
        "severity": "CRITICAL",
        "param_key": "always_install_elevated",
        "powershell": (
            "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' "
            "-Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue; "
            "Remove-ItemProperty -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' "
            "-Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue; "
            "Write-Output 'AlwaysInstallElevated disabled.'"
        ),
        "reboot_required": False,
    },
}


def get_command(key: str) -> dict | None:
    """Returns command definition or None if key not in allowlist."""
    return REMEDIATION_COMMANDS.get(key)


def get_all_commands() -> dict[str, dict]:
    return REMEDIATION_COMMANDS


def get_commands_for_param(param_key: str) -> list[tuple[str, dict]]:
    """Returns list of (command_key, command_def) that fix a given parameter."""
    return [
        (k, v) for k, v in REMEDIATION_COMMANDS.items()
        if v.get("param_key") == param_key
    ]
