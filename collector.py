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
from tkinter import ttk, messagebox
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
    "mock_attack_vss_enum_succeeded": (
        "Mock Check: Shadow Copy Enumeration Allowed",
        "The agent's mock check performs a read-only WMI query to list Volume Shadow Copies. It does not delete snapshots, and an allowed query alone does not show that ransomware could remove backups.",
    ),
    "mock_attack_mass_rename_succeeded": (
        "Mock Check: Temporary File Rename Allowed",
        "The agent's mock check creates disposable files in its own %TEMP% subfolder and renames them. It does not encrypt user files; this limited simulation cannot prove how protection would respond to real ransomware.",
    ),
}

# Practical, non-destructive guidance for every finding the agent can report.
# Manual steps are ordered lists so the UI can render a genuinely usable guide.
# This data is explanatory only: it never executes commands or changes policy.
MANUAL_FIX_GUIDES = {
    "smb_v1_enabled": (
        [
            "Confirm with IT that no older file server, scanner, copier, or business application still requires SMBv1. Check the affected device's role before changing a fleet policy.",
            "On an unmanaged device, open Control Panel → Programs → Turn Windows features on or off and clear SMB 1.0/CIFS File Sharing Support if it is installed. On managed devices, remove the SMBv1 feature with the organization's device policy or approved Windows servicing method.",
            "Restart if Windows requests it. Do not disable SMBv2/SMBv3; modern SMB versions are separate and should normally remain available.",
        ],
        "In elevated PowerShell, run (Get-SmbServerConfiguration).EnableSMB1Protocol and confirm it returns False. Check client feature state with Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol where supported, then run a fresh R3P scan.",
        "Requires administrator rights. Pilot first: legacy dependencies may stop working. Use a maintenance window and retain an alternate management path.",
    ),
    "rdp_open": (
        [
            "Decide whether staff or support teams need Remote Desktop. If they do, keep it enabled only behind the approved VPN or remote-access gateway; do not expose TCP 3389 directly to the internet.",
            "Require Network Level Authentication, strong unique accounts, MFA through the gateway where available, and current security updates. Restrict the Windows Firewall Remote Desktop rules to approved management addresses.",
            "If RDP is not needed, arrange an approved change window, confirm another management route works, then turn it off in Settings → System → Remote Desktop or deploy the organization's policy.",
        ],
        "From an approved management host, verify only expected users and network routes can connect. If disabled, confirm the device remains manageable and TCP 3389 is no longer reachable from unapproved networks; then rescan.",
        "Disabling RDP or changing firewall scope can lock out support staff. Do not make this change over the only remote session without a tested fallback.",
    ),
    "autorun_enabled": (
        [
            "Open Group Policy Editor (gpedit.msc) or your endpoint management policy and go to Computer Configuration → Administrative Templates → Windows Components → AutoPlay Policies.",
            "Enable Turn off AutoPlay and select All drives. If the organization uses Intune or domain policy, make the change there so it is not overwritten locally.",
            "Apply policy with gpupdate /force on a test device, then repeat the change through central policy after validating business needs for removable media.",
        ],
        "Review the effective policy with gpresult /h <report.html> or Resultant Set of Policy and confirm AutoPlay is disabled for all drives. Run a fresh R3P scan.",
        "Policy names can vary slightly by Windows release. This disables automatic launch behavior; it does not prevent users from manually opening files on removable media.",
    ),
    "powershell_unrestricted": (
        [
            "Ask the security administrator which PowerShell execution policy is approved. Do not treat changing this setting as a substitute for application control: execution policy is not a security boundary and can be bypassed by an authorized user.",
            "For a standalone device, use an approved policy such as RemoteSigned. For a fleet, set policy through Group Policy or device management, and consider WDAC/AppLocker, script logging, and constrained language mode as stronger controls.",
            "Test scheduled tasks, signed scripts, deployment tools, and help-desk automation with the proposed policy before broad rollout.",
        ],
        "Run Get-ExecutionPolicy -List in PowerShell and compare all scopes with the approved baseline. Check central policy has applied, then rescan the endpoint.",
        "An execution policy can break legitimate automation. Do not promise that RemoteSigned or AllSigned alone blocks malware; deploy application control for enforcement.",
    ),
    "uac_disabled": (
        [
            "Open Control Panel → User Accounts → Change User Account Control settings and select the organization-approved notification level. Do not set UAC to Never notify as a workaround.",
            "For managed endpoints, set EnableLUA through the approved security baseline, Group Policy, or Intune configuration profile instead of changing an isolated registry value.",
            "Save work and restart when prompted; UAC changes may not take full effect until Windows restarts.",
        ],
        "After restart, confirm the approved UAC notification level is selected and verify EnableLUA is 1 in the effective system policy. Run a new R3P scan.",
        "Administrator rights and a restart may be required. Test line-of-business installers and elevation workflows before changing a managed fleet.",
    ),
    "defender_disabled": (
        [
            "Open Windows Security → Virus & threat protection and check which antivirus product is registered. If Microsoft Defender is the intended product, investigate why protection was turned off before re-enabling it.",
            "On an unmanaged device, open Manage settings and turn Real-time protection on. On a managed device, restore the setting in Microsoft Defender, Intune, or the organization's security policy and allow policy sync.",
            "Update security intelligence and investigate recent alerts or configuration changes that may have disabled protection.",
        ],
        "In Windows Security, confirm the intended antivirus reports active protection. For managed devices, verify the effective state in the Defender/management console, then run a fresh R3P scan.",
        "A registered third-party antivirus or centrally managed policy can control Defender state. Do not disable another protection product to make this check pass; coordinate changes with IT.",
    ),
    "firewall_disabled": (
        [
            "Open Windows Security → Firewall & network protection and inspect Domain, Private, and Public profiles. Identify which profiles are disabled and why.",
            "Restore the approved Windows Defender Firewall policy for each required profile. On managed devices, change the Intune, Group Policy, or security baseline setting rather than fighting central policy locally.",
            "Before applying the change, review inbound rules for remote management and business applications. Prefer narrow, named allow rules over turning off the firewall or broadly allowing inbound traffic.",
        ],
        "Run Get-NetFirewallProfile and confirm Enabled is True for the expected profiles. Test approved management and application traffic, then rescan.",
        "Enabling a firewall profile can expose missing allow rules and interrupt applications or remote administration. Pilot the change and keep a fallback management route.",
    ),
    "tamper_protection_off": (
        [
            "On an unmanaged device, open Windows Security → Virus & threat protection → Manage settings and turn Tamper Protection on.",
            "On a managed device, review the effective Microsoft Defender for Endpoint or Intune policy and correct it at the management source; a local change may be blocked or reverted.",
            "Allow the device to sync policy before judging the result. Also confirm real-time protection and cloud-delivered protection match the organization's required baseline.",
        ],
        "Confirm Tamper Protection is On in Windows Security or the Defender management console after policy sync. Run a new R3P scan.",
        "Administrator permissions or security-console access may be required. Do not attempt registry edits or exclusions to get around Tamper Protection.",
    ),
    "event_logging_disabled": (
        [
            "Open Services (services.msc), find Windows Event Log, and inspect its status and Startup type. Check whether a security baseline or service dependency intentionally controls it.",
            "If it should be enabled, set Startup type to Automatic and start the service, or ask IT to restore it through managed policy. Do not clear existing logs while troubleshooting.",
            "Confirm the Security, System, and required application logs have appropriate size and retention settings; forward important events to the organization's logging service if configured.",
        ],
        "Confirm Windows Event Log is running and recent events are being recorded. Review Services or Get-Service EventLog, then run a fresh R3P scan.",
        "Administrator rights may be required. Avoid changing log retention without an approved storage plan, and never clear logs as a remediation step.",
    ),
    "guest_account_active": (
        [
            "Open Computer Management → Local Users and Groups → Users (lusrmgr.msc) and identify the built-in Guest account. On domain-managed devices, review the domain policy that manages local accounts.",
            "Disable the Guest account using the approved local or central policy. Do not delete it, and do not disable other service accounts unless their owner confirms they are unused.",
            "Review network-share permissions and sign-in logs for any unexpected Guest use before closing the finding.",
        ],
        "Confirm the Guest account is disabled in Computer Management or with Get-LocalUser Guest. Verify approved user and service access still works, then rescan.",
        "Administrator rights are required. The Local Users and Groups console may not be available on every Windows edition; use the organization's management policy where needed.",
    ),
    "lsass_protection_off": (
        [
            "Check the Windows version, security baseline, and application compatibility. Coordinate with IT because credential providers, smart-card middleware, or security software may need compatibility validation.",
            "Enable Local Security Authority protection using the organization's supported Microsoft Defender, Intune, or Group Policy configuration. Avoid applying an unreviewed registry change to production systems.",
            "Pilot on representative devices, review Windows security events for incompatible plug-ins, and restart when policy or Windows requests it.",
        ],
        "After policy sync and any required restart, verify LSA protection is enabled in Windows Security/Defender or through the organization's baseline audit. Confirm sign-in and credential-management workflows, then rescan.",
        "May require administrator rights and a restart. Incompatible authentication plug-ins can fail; keep a recovery administrator account and test before fleet deployment.",
    ),
    "open_network_shares": (
        [
            "Open Computer Management → System Tools → Shared Folders → Shares, or run Get-SmbShare, and identify which shares expose broad access. Confirm the data owner and business purpose before editing a share.",
            "For each required share, open Share Permissions and remove Everyone or other broad principals unless explicitly required. Grant access to named, approved groups with the least privilege needed.",
            "Review the folder's Security (NTFS) permissions too: a user needs permission through both the share and NTFS layers. Remove unused shares only after checking application and backup dependencies.",
        ],
        "Use Get-SmbShareAccess -Name <ShareName> to inspect share access. Test from an approved account and an unapproved account, then confirm required applications still work and rescan.",
        "Permission changes can interrupt applications and users. Export/document current permissions and retain an administrator recovery path before changes.",
    ),
    "macro_execution_enabled": (
        [
            "In Microsoft Office, open File → Options → Trust Center → Trust Center Settings → Macro Settings. Check whether the finding refers to macros allowed from untrusted or internet-downloaded documents.",
            "Select the restrictive option approved by your organization, commonly disabling VBA macros with notification. For managed fleets, configure the Office policy centrally rather than per user.",
            "If a business process requires macros, prefer signed macros from a controlled publisher and verify certificate ownership/expiry. Do not broadly trust writable folders or enable all macros to fix a workflow.",
        ],
        "Review the effective Office policy and test approved signed business documents. Confirm untrusted macros follow the intended block/notification behavior, then rescan.",
        "This may affect finance, reporting, or legacy business workflows. Pilot with document owners and use centrally managed policy where available.",
    ),
    "applocker_absent": (
        [
            "Ask the Windows administrator to determine whether AppLocker or Windows Defender Application Control is the approved application-control solution for this Windows edition and device role.",
            "Inventory required applications and create the default allow rules before custom restrictions. Start in Audit mode so events show what would be blocked without interrupting users.",
            "Review audit events with application owners, refine signed-publisher rules, pilot enforcement on representative devices, then deploy through Group Policy or Intune in staged rings.",
        ],
        "Review AppLocker or WDAC audit/enforcement events. Confirm approved applications still launch and an intentionally unapproved test application is blocked in a controlled lab; run a new R3P scan.",
        "Application-control mistakes can prevent logon tools, updates, or business software from running. Requires administrator/security-owner planning; do not switch directly to enforcement on production endpoints.",
    ),
    "admin_shares_enabled": (
        [
            "Identify administrative shares such as C$ and ADMIN$ with Get-SmbShare, then check whether remote management, software deployment, backup, or help-desk tools depend on them.",
            "Prefer limiting inbound SMB (TCP 445) to approved management systems with Windows Firewall and network controls, and restrict who has local administrator rights.",
            "Only disable automatic administrative shares if the organization has approved it and confirmed all dependencies. Apply the relevant Windows policy centrally and schedule a maintenance window.",
        ],
        "Review Get-SmbShare and test approved management, deployment, and backup workflows from their intended hosts. Confirm unapproved networks cannot reach SMB, then rescan.",
        "Removing administrative shares can break remote administration and deployment. Do not disable them on a managed server or workstation without the service owner’s approval.",
    ),
    "vss_deleted": (
        [
            "Open System Protection by running systempropertiesprotection.exe. Select each required volume, choose Configure, enable protection, and allocate storage according to the recovery plan.",
            "Create a new restore point after protection is enabled. Previously deleted shadow copies cannot be recreated, so treat this as restoring future recovery points rather than recovering old ones.",
            "Configure independent backups as well, with at least one isolated or immutable copy and restricted deletion rights. Coordinate server backup schedules with the backup owner.",
        ],
        "Run vssadmin list shadows and confirm expected restore points exist. Check the backup console for a recent successful job and perform a controlled test restore to a safe location.",
        "System Restore is not a substitute for independent backups. Creating shadow copies consumes disk space; do not delete existing recovery data to make space without the recovery owner's approval.",
    ),
    "backup_configured": (
        [
            "Ask the data/application owner which files, system state, and recovery time objectives must be protected. Choose the organization-approved backup product for this Windows role.",
            "Configure scheduled backups and retention. Keep at least one copy isolated or immutable, encrypt it as required, and ensure endpoint administrator credentials cannot casually delete every backup copy.",
            "Alert on failed or stale jobs and assign an owner to investigate them. A configured backup job is not useful until it completes successfully and can be restored.",
        ],
        "Check the backup console for a recent successful run, then restore a representative file or system component to a separate safe location and confirm it opens correctly. Record the test and run a fresh R3P scan.",
        "Requires storage, retention, access-control, and recovery planning. Do not store recovery keys or backup credentials in the agent or guide; use approved secret management.",
    ),
    "bitlocker_off": (
        [
            "Before enabling encryption, confirm the device supports BitLocker and determine where the recovery key will be escrowed (for example, Microsoft Entra ID, Active Directory, or the organization's key-management system).",
            "Verify that the recovery key is already recoverable by an authorized administrator. Then deploy the approved BitLocker policy through Intune/Group Policy, or use Control Panel → System and Security → BitLocker Drive Encryption on an unmanaged device.",
            "Choose only the organization-approved encryption method and protectors. Allow encryption to finish while the device remains powered and connected; do not interrupt it or clear the TPM as a troubleshooting shortcut.",
        ],
        "Run manage-bde -status C: and confirm Protection Status is Protection On and conversion is complete. Confirm the escrowed recovery key can be retrieved through the approved process, then rescan.",
        "Never begin encryption until key escrow is verified. May require administrator rights, a restart, compatible hardware, and recovery access. Losing the key can make data inaccessible.",
    ),
    "wdigest_enabled": (
        [
            "Confirm this is a supported Windows version and review the domain/device security baseline. WDigest credential caching is controlled by the UseLogonCredential policy under HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest.",
            "Have the administrator set UseLogonCredential to 0 or remove any policy that explicitly sets it to 1. Prefer Group Policy, Intune, or the approved security baseline so the value stays consistent.",
            "Allow policy to apply and have users sign out/restart if required by the organization's procedure; investigate why plaintext credential caching was enabled.",
        ],
        "In elevated PowerShell, inspect the UseLogonCredential value and the effective policy. Confirm it is disabled/0 or absent as required by the baseline, then run a fresh R3P scan.",
        "Administrator rights and managed-policy review may be required. Do not copy credential material or expose passwords while investigating; older applications may depend on legacy authentication behavior.",
    ),
    "laps_absent": (
        [
            "Ask IT to choose Windows LAPS and its password-backup destination: Microsoft Entra ID or Active Directory Domain Services. Confirm device join type, supported Windows updates, and any AD schema/permission preparation.",
            "Configure the LAPS policy through Intune or Group Policy, including password length, complexity, age, account target, and backup directory. Delegate password retrieval only to approved support roles.",
            "Enable policy on a pilot group, confirm passwords rotate and back up successfully, then remove shared/static local administrator passwords from normal use.",
        ],
        "Confirm the device received LAPS policy and the selected directory shows a recent password backup/rotation timestamp. Test authorized retrieval using delegated access, then rescan.",
        "LAPS requires identity/directory configuration and administrator work; installing a feature alone does not complete deployment. Never paste or store a retrieved LAPS password in notes, chat, or screenshots.",
    ),
    "nla_disabled": (
        [
            "Confirm Remote Desktop is required and that all approved clients support Network Level Authentication (NLA). If the device is externally reachable, first restrict it to the approved VPN or gateway.",
            "On an unmanaged device, open Settings → System → Remote Desktop → Advanced settings and require Network Level Authentication. For managed devices, apply the equivalent approved RDP security policy centrally.",
            "Do not disable RDP merely to clear this finding if administrators depend on it; instead enable NLA and test the normal management connection from an approved client.",
        ],
        "Confirm the RDP-Tcp UserAuthentication setting is 1 or verify the effective management policy. Test sign-in from an approved client and run a fresh R3P scan.",
        "Older clients may not support NLA. Keep a tested alternate access path before changing remote settings; managed policy may override local configuration.",
    ),
    "always_install_elevated": (
        [
            "Open Group Policy Management or the local policy editor and inspect both Computer Configuration and User Configuration → Administrative Templates → Windows Components → Windows Installer → Always install with elevated privileges.",
            "Set the policy to Disabled or Not Configured according to the organization's baseline in both scopes. Remove only the corresponding AlwaysInstallElevated policy values through approved management; do not alter unrelated installer settings.",
            "Review software deployment workflows that may have been relying on elevated MSI installation and replace them with an approved deployment tool or administrator-mediated installation.",
        ],
        "Check both HKLM and HKCU Windows Installer policy values and confirm the effective configuration does not enable AlwaysInstallElevated. Run a new R3P scan.",
        "Requires administrator or policy-owner access. Changing installer policy may affect software deployment; validate on a pilot device and do not test with an untrusted MSI.",
    ),
    "vulnerable_driver_blocklist_enabled": (
        [
            "Confirm what this R3P version expects for the vulnerable-driver blocklist and check Windows edition/build and hardware compatibility with IT. The registry/policy signal may not match the effective control on every release.",
            "Enable Microsoft's vulnerable-driver blocklist through the supported Windows Security/Device Guard policy or the organization's Intune/Group Policy baseline. Avoid editing the registry by hand on a managed fleet.",
            "Pilot with affected hardware and security software. Review Windows Code Integrity events for blocked drivers and update/remove obsolete drivers through the hardware vendor.",
        ],
        "Verify the effective policy in Windows Security or the management console and inspect Code Integrity events after policy sync. Run a fresh R3P scan and confirm expected devices/drivers still work.",
        "Blocking vulnerable drivers may affect legacy hardware or software. Requires administrator/policy access; do not disable the blocklist to silence the finding.",
    ),
    "hvci_enabled": (
        [
            "Check Windows version, hardware support, and the installed driver inventory. Incompatible drivers can prevent Memory Integrity (HVCI) from turning on or cause device problems.",
            "On an unmanaged compatible device, open Windows Security → Device security → Core isolation details and turn Memory Integrity on. On managed devices, deploy the approved HVCI policy through Intune or Group Policy.",
            "Update or remove incompatible drivers using the device/vendor support process, then restart when prompted. Roll out to a pilot group before applying to a fleet.",
        ],
        "After restart and policy sync, confirm Memory Integrity shows On in Windows Security or the management console. Review Code Integrity events, test required peripherals/apps, then rescan.",
        "May require administrator rights, compatible hardware, current drivers, and a restart. It can affect legacy drivers; keep recovery access and do not force-enable on untested production devices.",
    ),
    "asr_rules_configured": (
        [
            "Ask the Defender/security administrator which Attack Surface Reduction rules are required for this organization. The R3P check may only detect whether rules exist; it does not necessarily validate that the right rules are enabled in Block mode.",
            "Deploy selected rules in Audit mode to a pilot group using Intune, Group Policy, Configuration Manager, or the Defender portal. Review audit events and application impact before enforcement.",
            "After tuning exclusions narrowly and with documented approval, move the approved rules to Block mode in staged rings. Keep policy centrally managed so settings do not drift.",
        ],
        "Review effective rule IDs and actions in the Defender management console or Get-MpPreference. Confirm required rules have the intended mode, review ASR events, and run a fresh R3P scan.",
        "Some rules can interrupt Office add-ins, scripts, or deployment tools. Audit first and pilot before enforcing; do not add broad exclusions to suppress alerts.",
    ),
    "mock_attack_vss_enum_succeeded": (
        [
            "Treat this as a probe result, not a missing Windows setting. The agent only runs a read-only WMI query to list shadow copies; it does not delete them.",
            "Review Defender/EDR alerts and the organization's ransomware behavior-protection policy with the security administrator. Use vendor-supported detection/validation procedures in an isolated lab if you need to demonstrate a block.",
            "Keep backup and WMI services enabled. After an approved EDR policy change, rerun the R3P scan and correlate the exact time with the security product's event log.",
        ],
        "Review the EDR/Defender event for this exact query and determine whether the product recorded an alert or block. Interpret R3P as only reporting whether its read-only query completed; verify recovery protection separately with a restore test.",
        "An allowed enumeration query does not prove shadow-copy deletion would succeed. Do not disable WMI or backups or add broad PowerShell exclusions to make this check pass.",
    ),
    "mock_attack_mass_rename_succeeded": (
        [
            "Treat this as a narrow behavior probe, not a missing Windows setting. The agent creates disposable files in its own %TEMP%\\r3p_mock_attack folder and renames them; it does not encrypt user documents.",
            "Review Defender/EDR telemetry and the organization's ransomware behavior protection. If you need to demonstrate Controlled Folder Access, use Microsoft's supported CFA test procedure against a protected test folder rather than assuming this temporary-folder probe exercises CFA.",
            "After any approved policy change, rerun R3P and correlate the scan time with the endpoint product's event log. Keep policies enabled and use a disposable VM for demonstrations.",
        ],
        "Confirm whether the endpoint product logged a block for this exact temporary-file action. Separately validate protected-folder behavior with a vendor-supported test, then run a fresh R3P scan.",
        "A successful rename probe does not prove that real encryption would evade protection; an interrupted probe does not prove an EDR block. Do not weaken defenses, add broad exclusions, or use real user data for testing.",
    ),
}
# Backend parameter names are the canonical keys shown in findings. Keep aliases
# for collector-side labels so the guide works across both response shapes.
MANUAL_FIX_GUIDES.update({
    "rdp_enabled": MANUAL_FIX_GUIDES["rdp_open"],
    "backup_absent": MANUAL_FIX_GUIDES["backup_configured"],
})
ABOUT_INFO.update({
    "rdp_enabled": ABOUT_INFO["rdp_open"],
    "firewall_disabled": ("Windows Firewall Disabled", ABOUT_INFO["firewall_on"][1]),
    "backup_absent": ("Backup Not Configured", ABOUT_INFO["backup_configured"][1]),
})

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
    # Solid equivalents of the web dashboard's Apple dark palette. Tkinter
    # cannot render backdrop blur reliably, so hierarchy comes from graphite
    # surfaces and hairline separators instead.
    "bg": "#0c0c0c",
    "card": "#1c1c1e",
    "card2": "#2c2c2e",
    "border": "#38383a",
    "accent": "#0a84ff",
    "text": "#ffffff",
    "subtle": "#a1a1a6",
    "safe": "#30d158",
    "low": "#ffd60a",
    "high": "#ff9f0a",
    "critical": "#ff453a",
    "warning": "#ffd60a",
    "info": "#0a84ff",
}

RISK_COLORS = {
    "SAFE": COLORS["safe"],
    "LOW RISK": COLORS["low"],
    "HIGH RISK": COLORS["high"],
    "CRITICAL": COLORS["critical"],
}
RISK_TINTS = {
    "SAFE": "#14251a",
    "LOW RISK": "#292512",
    "HIGH RISK": "#2b1d10",
    "CRITICAL": "#2b1716",
    "LOCAL SCAN": "#142033",
}


def configure_agent_styles(root):
    """Apply the same restrained dark treatment to native ttk controls."""
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure(
        "Vertical.TScrollbar",
        background=COLORS["card2"],
        troughcolor=COLORS["bg"],
        bordercolor=COLORS["bg"],
        arrowcolor=COLORS["subtle"],
        relief="flat",
        gripcount=0,
    )
    style.map(
        "Vertical.TScrollbar",
        background=[("active", COLORS["border"])],
        arrowcolor=[("active", COLORS["text"])],
    )


def agent_button(parent, *, primary=False, **options):
    """Build a flat button with a visible keyboard focus ring."""
    base = {
        "bg": COLORS["accent"] if primary else COLORS["card2"],
        "fg": COLORS["text"],
        "activebackground": "#0066cc" if primary else COLORS["border"],
        "activeforeground": COLORS["text"],
        "relief": "flat",
        "bd": 0,
        "highlightthickness": 2,
        "highlightbackground": COLORS["card"],
        "highlightcolor": COLORS["accent"],
        "takefocus": True,
    }
    base.update(options)
    return tk.Button(parent, **base)


class RoundedCard(tk.Frame):
    """A reusable, resize-safe Canvas-drawn card surface for Tk layouts."""

    def __init__(self, parent, *, radius=14, inset=10, fill=None, outline=None, **kwargs):
        super().__init__(parent, bg=COLORS["bg"], bd=0, **kwargs)
        self.radius = radius
        self.inset = inset
        self.fill = fill or COLORS["card"]
        self.outline = outline or COLORS["border"]
        self.canvas = tk.Canvas(self, bg=COLORS["bg"], highlightthickness=0, bd=0)
        self.canvas.place(x=0, y=0, relwidth=1, relheight=1)
        self.content = tk.Frame(self, bg=self.fill, bd=0)
        self.content.pack(fill="both", expand=True, padx=inset, pady=inset)
        self.bind("<Configure>", self._draw_surface, add="+")

    def _draw_surface(self, _event=None):
        width, height = self.winfo_width(), self.winfo_height()
        if width < 2 or height < 2:
            return
        radius = min(self.radius, width // 2, height // 2)
        points = [
            radius, 0, width - radius, 0, width, 0, width, radius,
            width, height - radius, width, height, width - radius, height,
            radius, height, 0, height, 0, height - radius, 0, radius,
            0, 0, radius, 0,
        ]
        self.canvas.delete("surface")
        self.canvas.create_polygon(
            points,
            smooth=True,
            splinesteps=12,
            fill=self.fill,
            outline=self.outline,
            width=1,
            tags="surface",
        )
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

# The server remains authoritative for weighted scoring, but the endpoint can
# still identify locally observed findings while offline. Keep these field
# translations aligned with backend/scoring.py::_translate.
LOCAL_FIELD_TO_FINDING = {
    "rdp_open": ("rdp_enabled", "Entry Vector"),
    "smb_v1_enabled": ("smb_v1_enabled", "Entry Vector"),
    "autorun_enabled": ("autorun_enabled", "Entry Vector"),
    "open_network_shares": ("open_network_shares", "Entry Vector"),
    "nla_disabled": ("nla_disabled", "Entry Vector"),
    "macro_execution_enabled": ("macro_execution_enabled", "Execution"),
    "powershell_unrestricted": ("powershell_unrestricted", "Execution"),
    "uac_disabled": ("uac_disabled", "Execution"),
    "applocker_absent": ("applocker_absent", "Execution"),
    "always_install_elevated": ("always_install_elevated", "Execution"),
    "defender_disabled": ("defender_disabled", "Evasion & Persistence"),
    "firewall_on": ("firewall_disabled", "Evasion & Persistence"),
    "tamper_protection_off": ("tamper_protection_off", "Evasion & Persistence"),
    "event_logging_disabled": ("event_logging_disabled", "Evasion & Persistence"),
    "vulnerable_driver_blocklist_enabled": ("vulnerable_driver_blocklist_enabled", "Evasion & Persistence"),
    "hvci_enabled": ("hvci_enabled", "Evasion & Persistence"),
    "asr_rules_configured": ("asr_rules_configured", "Evasion & Persistence"),
    "admin_shares_enabled": ("admin_shares_enabled", "Lateral Movement"),
    "lsass_protection_off": ("lsass_protection_off", "Lateral Movement"),
    "guest_account_active": ("guest_account_active", "Lateral Movement"),
    "wdigest_enabled": ("wdigest_enabled", "Lateral Movement"),
    "laps_absent": ("laps_absent", "Lateral Movement"),
    "vss_deleted": ("vss_deleted", "Recovery Prevention"),
    "backup_configured": ("backup_absent", "Recovery Prevention"),
    "bitlocker_off": ("bitlocker_off", "Recovery Prevention"),
    "mock_attack_vss_enum_blocked": ("mock_attack_vss_enum_succeeded", "Active Validation (Mock Attacks)"),
    "mock_attack_mass_rename_blocked": ("mock_attack_mass_rename_succeeded", "Active Validation (Mock Attacks)"),
}
LOCAL_INVERTED_FIELDS = {
    "firewall_on",
    "backup_configured",
    "vulnerable_driver_blocklist_enabled",
    "hvci_enabled",
    "asr_rules_configured",
}
LOCAL_BLOCK_RESULT_FIELDS = {
    "mock_attack_vss_enum_blocked",
    "mock_attack_mass_rename_blocked",
}


def build_local_scan_result(data: dict) -> dict:
    """Build displayable findings without inventing the server's risk score."""
    flagged = {}
    for raw_key, (finding_key, phase) in LOCAL_FIELD_TO_FINDING.items():
        if raw_key not in data or data[raw_key] is None:
            continue
        value = data[raw_key]
        if raw_key in LOCAL_BLOCK_RESULT_FIELDS:
            risky = value is False
        elif raw_key in LOCAL_INVERTED_FIELDS:
            risky = not bool(value)
        else:
            risky = bool(value)
        if risky:
            flagged.setdefault(phase, []).append(finding_key)

    return {
        "local_only": True,
        "risk_score": None,
        "risk_class": "LOCAL SCAN",
        "flagged": flagged,
        "policy_exceptions": [],
        "local_scan_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
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


def get_mac_address() -> str:
    """
    Returns the primary active network adapter MAC address in XX:XX:XX:XX:XX:XX format.
    Tries PowerShell Get-NetAdapter first (on Windows), then uuid.getnode() as universal fallback.
    """
    if platform.system() == "Windows":
        try:
            # Query active connected physical adapter
            cmd = '(Get-NetAdapter | Where-Object { $_.Status -eq "Up" -and $_.MacAddress -ne $null } | Select-Object -First 1).MacAddress'
            mac = _ps(cmd).strip().replace("-", ":").upper()
            if mac and len(mac) == 17:
                return mac
        except Exception:
            pass

    try:
        import uuid
        node = uuid.getnode()
        mac = ":".join(f"{(node >> (8 * (5 - i))) & 0xFF:02X}" for i in range(6))
        if mac and mac != "00:00:00:00:00:00":
            return mac
    except Exception:
        pass

    return "UNKNOWN"


def get_machine_guid() -> str:
    """
    Returns the persistent machine GUID / hardware UUID.
    On Windows, reads HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid or BIOS UUID.
    """
    if platform.system() == "Windows":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
                val, _ = winreg.QueryValueEx(key, "MachineGuid")
                if val:
                    return str(val).strip()
        except Exception:
            pass

        try:
            cmd = "(Get-CimInstance -Class Win32_ComputerSystemProduct).UUID"
            out = _ps(cmd).strip()
            if out and out.lower() != "none" and len(out) > 8:
                return out
        except Exception:
            pass

    # Linux fallback (/etc/machine-id)
    for p in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            if os.path.exists(p):
                with open(p, "r") as f:
                    content = f.read().strip()
                    if content:
                        return content
        except Exception:
            pass

    return "UNKNOWN"


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


# ── ACTIVE VALIDATION (BENIGN BEHAVIOR PROBES) ─────────────────────────────────
def run_mock_attack_vss_enum() -> bool:
    """
    Runs a read-only WMI inventory query for shadow copies.
    True means the query did not complete; False means it was allowed.
    A failure is not necessarily proof that endpoint protection blocked it.
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
            return True  # Query did not complete; cause may not be endpoint protection.
        return False  # Read-only inventory query was allowed.
    except Exception:
        return True


def run_mock_attack_mass_rename() -> bool:
    """
    Renames 100 disposable files in the agent's temporary test directory.
    True means the full operation did not complete; False means all renames worked.
    A partial run or error is not necessarily proof that endpoint protection blocked it.
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
            return True  # Incomplete; the cause may be an error or interruption.
        return False  # All disposable test-file renames were allowed.

    except Exception:
        return True  # Incomplete; the cause may not be endpoint protection.


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
        configure_agent_styles(self)
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
        tk.Frame(self, bg=COLORS["border"], height=1).pack(fill="x")
        body = tk.Frame(self, bg=COLORS["bg"], padx=36, pady=28)
        body.pack(fill="both", expand=True)

        title_row = tk.Frame(body, bg=COLORS["bg"])
        title_row.pack(anchor="w")
        mark = tk.Canvas(title_row, width=18, height=20, bg=COLORS["bg"], highlightthickness=0)
        mark.pack(side="left", padx=(0, 7))
        mark.create_polygon(9, 1, 16, 4, 15, 12, 9, 19, 3, 12, 2, 4, fill=COLORS["accent"], outline="")
        tk.Label(
            title_row,
            text="R3P Scanner",
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

        agent_button(
            body,
            primary=True,
            text="Connect & Start Monitoring  →",
            font=("Segoe UI", 10, "bold"),
            bg=COLORS["accent"],
            fg="white",
            activebackground="#0066cc",
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
        configure_agent_styles(self)
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
        self.minsize(520, 500)
        self.resizable(True, True)
        self._center(600, 700)
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
        tk.Frame(self, bg=COLORS["border"], height=1).pack(fill="x")

        # Header
        hdr = tk.Frame(self, bg=COLORS["bg"], pady=18)
        hdr.pack(fill="x", padx=24)

        # Left side texts
        title_frame = tk.Frame(hdr, bg=COLORS["bg"])
        title_frame.pack(side="left")
        title_row = tk.Frame(title_frame, bg=COLORS["bg"])
        title_row.pack(anchor="w")
        mark = tk.Canvas(title_row, width=20, height=22, bg=COLORS["bg"], highlightthickness=0)
        mark.pack(side="left", padx=(0, 7))
        mark.create_polygon(10, 1, 18, 4, 17, 13, 10, 21, 3, 13, 2, 4, fill=COLORS["accent"], outline="")
        tk.Label(
            title_row,
            text="R3P Monitor",
            font=("Segoe UI", 18, "bold"),
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
        about_btn = agent_button(
            hdr,
            text="About",
            font=("Segoe UI", 9, "bold"),
            bg=COLORS["card"],
            fg=COLORS["text"],
            bd=0,
            activebackground=COLORS["card2"],
            activeforeground=COLORS["text"],
            cursor="hand2",
            command=self._show_about,
            padx=12,
            pady=7,
        )
        about_btn.pack(side="right", anchor="n")
        agent_button(
            hdr,
            primary=True,
            text="Fix guide",
            font=("Segoe UI", 9, "bold"),
            bg=COLORS["accent"],
            fg="white",
            activebackground="#0066cc",
            activeforeground="white",
            relief="flat",
            bd=0,
            cursor="hand2",
            command=self._show_all_fix_guides,
            padx=12,
            pady=7,
        ).pack(side="right", anchor="n", padx=(0, 8))

        # Status card
        self.status_card = RoundedCard(self)
        self.status_card.pack(fill="x", padx=20, pady=(0, 10))
        inner_s = tk.Frame(self.status_card.content, bg=COLORS["card"], padx=14, pady=14)
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
            font=("Segoe UI", 9, "bold"),
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
        self.result_card = RoundedCard(self)
        self.result_card.pack(fill="both", expand=True, padx=20, pady=(0, 12))

        self.result_canvas = tk.Canvas(
            self.result_card.content, bg=COLORS["card"], highlightthickness=0
        )
        self.result_scrollbar = ttk.Scrollbar(
            self.result_card.content, orient="vertical", command=self.result_canvas.yview
        )

        self.result_inner = tk.Frame(
            self.result_canvas, bg=COLORS["card"], padx=14, pady=14
        )

        self.result_inner.bind(
            "<Configure>",
            lambda e: self.result_canvas.configure(
                scrollregion=self.result_canvas.bbox("all")
            ),
        )

        self._result_window = self.result_canvas.create_window(
            (0, 0), window=self.result_inner, anchor="nw", width=380
        )
        self.result_canvas.bind(
            "<Configure>",
            lambda event: self.result_canvas.itemconfigure(
                self._result_window, width=max(380, event.width - 4)
            ),
        )
        self.result_canvas.configure(yscrollcommand=self.result_scrollbar.set)

        self.result_canvas.pack(side="left", fill="both", expand=True, padx=4, pady=4)
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
        self.close_btn = agent_button(
            footer,
            text="Hide to System Tray",
            font=("Segoe UI", 9),
            bg=COLORS["card2"],
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
        img = Image.new("RGB", (64, 64), color=(16, 25, 35))
        d = ImageDraw.Draw(img)
        d.ellipse([16, 16, 48, 48], fill=(21, 154, 156))
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
                local_result = build_local_scan_result(data)
                self._last_result = local_result
                local_findings = sum(len(items) for items in local_result["flagged"].values())
                self.after(0, self._update_result_card, local_result)
                self._set_status(
                    f"Scan #{cycle} complete on this device — {local_findings} findings; not synced to server"
                )
                self._set_dot(COLORS["warning"])

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
            "mac_address": get_mac_address(),
            "machine_guid": get_machine_guid(),
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

        local_only = result.get("local_only", False)
        risk_class = "LOCAL SCAN" if local_only else result.get("risk_class", "UNKNOWN")
        risk_score = result.get("risk_score")
        flagged = result.get("flagged", {})
        color = COLORS["info"] if local_only else RISK_COLORS.get(risk_class, COLORS["subtle"])

        # Risk badge
        badge = RoundedCard(
            self.result_inner,
            radius=12,
            inset=5,
            fill=RISK_TINTS.get(risk_class, COLORS["card2"]),
            outline=color,
        )
        badge.pack(anchor="w", pady=(0, 10))
        tk.Label(
            badge.content,
            text=risk_class,
            font=("Segoe UI", 9, "bold"),
            bg=RISK_TINTS.get(risk_class, COLORS["card2"]),
            fg=color,
            padx=8,
            pady=2,
        ).pack()

        if local_only:
            tk.Label(
                self.result_inner,
                text=(
                    "This scan is shown from local checks and has not reached the server. "
                    "A server-calculated score and policy exceptions are unavailable offline; "
                    "some listed findings may be excepted in the dashboard."
                ),
                font=("Segoe UI", 8),
                bg=COLORS["card2"],
                fg=COLORS["text"],
                wraplength=390,
                justify="left",
                padx=10,
                pady=8,
            ).pack(fill="x", pady=(0, 8))

        # Score row
        row = tk.Frame(self.result_inner, bg=COLORS["card"])
        row.pack(anchor="w", pady=(0, 4))
        tk.Label(
            row,
            text="Risk Score: " if not local_only else "Server Risk Score: ",
            font=("Segoe UI", 10),
            bg=COLORS["card"],
            fg=COLORS["subtle"],
        ).pack(side="left")
        tk.Label(
            row,
            text=(f"{risk_score} / 100" if risk_score is not None else "Unavailable offline"),
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
                        card = RoundedCard(
                            self.result_inner,
                            radius=10,
                            inset=7,
                            fill=COLORS["card2"],
                        )
                        card.pack(fill="x", padx=2, pady=4)
                        title_label = tk.Label(
                            card.content,
                            text=flag_item.replace("_", " ").title(),
                            font=("Segoe UI", 9, "bold"),
                            bg=COLORS["card2"],
                            fg=color,
                            anchor="w",
                            justify="left",
                            wraplength=380,
                        )
                        title_label.pack(fill="x", anchor="w")
                        title_label.bind(
                            "<Configure>",
                            lambda event, label=title_label: label.configure(
                                wraplength=max(180, event.width)
                            ),
                        )

                        actions = tk.Frame(card.content, bg=COLORS["card2"])
                        actions.pack(fill="x", pady=(6, 0))
                        cmd_key = PARAM_TO_CMD_KEY.get(flag_item)
                        has_fix = cmd_key in AGENT_REMEDIATION
                        if has_fix:
                            agent_button(
                                actions,
                                text="Apply fix",
                                font=("Segoe UI", 8),
                                bg=COLORS["card"],
                                fg=COLORS["text"],
                                activebackground="#0066cc",
                                activeforeground="white",
                                relief="flat",
                                bd=0,
                                padx=9,
                                pady=4,
                                cursor="hand2",
                                command=lambda k=cmd_key: self._on_fix_clicked(k),
                            ).pack(side="right", padx=(5, 0))
                        agent_button(
                            actions,
                            primary=True,
                            text="How to fix",
                            font=("Segoe UI", 8, "bold"),
                            bg=COLORS["accent"],
                            fg="white",
                            activebackground="#0066cc",
                            activeforeground="white",
                            relief="flat",
                            bd=0,
                            padx=10,
                            pady=4,
                            cursor="hand2",
                            command=lambda k=flag_item: self._show_fix_guide(k),
                        ).pack(side="right")
        else:
            tk.Label(
                self.result_inner,
                text=(
                    "No locally flagged findings in this scan."
                    if local_only
                    else "✅  No issues detected — system looks clean!"
                ),
                font=("Segoe UI", 10),
                bg=COLORS["card"],
                fg=COLORS["safe"],
            ).pack(anchor="w")

        tk.Label(
            self.result_inner,
            text=(
                "⚠ Not synced — findings are available on this device only"
                if local_only
                else "✓ Results sent to R3P admin dashboard"
            ),
            font=("Segoe UI", 8),
            bg=COLORS["card"],
            fg=COLORS["warning"] if local_only else COLORS["safe"],
        ).pack(anchor="w", pady=(10, 0))

    def _show_fix_guide(self, param_key: str):
        """Show safe manual guidance; opening this guide never applies a fix."""
        title, description = ABOUT_INFO.get(
            param_key,
            (param_key.replace("_", " ").title(),
             "This finding needs review against the effective Windows and organization policy."),
        )
        steps, verify, caution = MANUAL_FIX_GUIDES.get(
            param_key,
            ("Review the setting with your Windows or security administrator and use the approved baseline for this device. Avoid changing a managed endpoint without authorization.",
             "Confirm the effective setting in Windows or the management console, then run a fresh R3P scan.",
             "The parameter mapping may vary by Windows edition or organization policy."),
        )
        cmd_key = PARAM_TO_CMD_KEY.get(param_key)
        has_fix = cmd_key in AGENT_REMEDIATION
        dialog = tk.Toplevel(self)
        dialog.title(f"How to fix — {title}")
        dialog.configure(bg=COLORS["bg"])
        dialog.geometry("600x620")
        dialog.minsize(500, 440)
        dialog.transient(self)
        dialog.grab_set()
        dialog.scrollable_canvas = tk.Canvas(dialog, bg=COLORS["bg"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(dialog, orient="vertical", command=dialog.scrollable_canvas.yview)
        body = tk.Frame(dialog.scrollable_canvas, bg=COLORS["bg"], padx=24, pady=20)
        body.bind("<Configure>", lambda _e: dialog.scrollable_canvas.configure(scrollregion=dialog.scrollable_canvas.bbox("all")))
        body_window = dialog.scrollable_canvas.create_window((0, 0), window=body, anchor="nw")
        dialog.scrollable_canvas.bind("<Configure>", lambda event: dialog.scrollable_canvas.itemconfigure(body_window, width=event.width))
        dialog.scrollable_canvas.configure(yscrollcommand=scrollbar.set)
        dialog.scrollable_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        wrap_targets = []

        def section(label, text, color=None, numbered=False):
            tk.Label(
                body,
                text=label.upper(),
                font=("Segoe UI", 9, "bold"),
                bg=COLORS["bg"],
                fg=color or COLORS["info"],
            ).pack(anchor="w", pady=(14, 5))
            if numbered:
                for index, instruction in enumerate(text, start=1):
                    step_row = tk.Frame(body, bg=COLORS["card"], padx=10, pady=8)
                    step_row.pack(fill="x", pady=3)
                    instruction_label = tk.Label(
                        step_row,
                        text=f"{index:02d}",
                        font=("Segoe UI", 9, "bold"),
                        bg=COLORS["card"],
                        fg=COLORS["accent"],
                        anchor="n",
                    ).pack(side="left", padx=(0, 9))
                    tk.Label(
                        step_row,
                        text=instruction,
                        font=("Segoe UI", 10),
                        bg=COLORS["card"],
                        fg=COLORS["text"],
                        wraplength=420,
                        justify="left",
                        anchor="w",
                    )
                    instruction_label.pack(side="left", fill="x", expand=True)
                    wrap_targets.append(instruction_label)
            else:
                body_label = tk.Label(
                    body,
                    text=text,
                    font=("Segoe UI", 10),
                    bg=COLORS["bg"],
                    fg=COLORS["text"],
                    wraplength=440,
                    justify="left",
                    anchor="w",
                )
                body_label.pack(fill="x")
                wrap_targets.append(body_label)

        title_label = tk.Label(body, text=title, font=("Segoe UI", 17, "bold"), bg=COLORS["bg"], fg=COLORS["text"], wraplength=480, justify="left")
        title_label.pack(anchor="w")
        wrap_targets.append(title_label)
        section("Why this matters", description)
        section(
            "Before you start",
            "Confirm this is the correct endpoint and check whether its settings come from Intune, Group Policy, or another central manager. On a work or school device, follow the approved change process. Record the current state, preserve a working support/recovery path, and apply one change at a time so you can identify side effects.",
            COLORS["subtle"],
        )
        section("Manual steps", steps, numbered=True)
        section("Verify", verify, COLORS["safe"])
        section("Caution", caution, COLORS["warning"])
        if has_fix:
            section("R3P automated option", "An allowlisted Apply fix action is available for this parameter. It runs a predefined local command only after explicit confirmation; it is separate from these manual instructions.", COLORS["accent"])
        else:
            section("R3P automated option", "No allowlisted one-click fix is available for this parameter. Use the manual guidance and your approved endpoint-management workflow.", COLORS["subtle"])
        agent_button(body, text="Close", font=("Segoe UI", 9, "bold"), bg=COLORS["card2"], fg=COLORS["text"], activebackground=COLORS["border"], activeforeground=COLORS["text"], relief="flat", padx=16, pady=7, cursor="hand2", command=dialog.destroy).pack(anchor="e", pady=(18, 0))
        dialog.bind(
            "<Configure>",
            lambda event: [
                label.configure(wraplength=max(240, event.width - 86))
                for label in wrap_targets
                if label.winfo_exists()
            ] if event.widget is dialog else None,
        )
        dialog.bind("<Escape>", lambda _e: dialog.destroy())
        dialog.focus_set()

    def _show_all_fix_guides(self):
        """Offer a searchable, phase-grouped guide directory before a scan."""
        dialog = tk.Toplevel(self)
        dialog.title("R3P finding fix guide")
        dialog.configure(bg=COLORS["bg"])
        dialog.geometry("580x640")
        dialog.minsize(500, 460)
        dialog.transient(self)
        dialog.scrollable_canvas = tk.Canvas(dialog, bg=COLORS["bg"], highlightthickness=0)
        scrollbar = ttk.Scrollbar(dialog, orient="vertical", command=dialog.scrollable_canvas.yview)
        body = tk.Frame(dialog.scrollable_canvas, bg=COLORS["bg"], padx=20, pady=18)
        body.bind("<Configure>", lambda _e: dialog.scrollable_canvas.configure(scrollregion=dialog.scrollable_canvas.bbox("all")))
        body_window = dialog.scrollable_canvas.create_window((0, 0), window=body, anchor="nw")
        dialog.scrollable_canvas.bind("<Configure>", lambda event: dialog.scrollable_canvas.itemconfigure(body_window, width=event.width))
        dialog.scrollable_canvas.configure(yscrollcommand=scrollbar.set)
        dialog.scrollable_canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        tk.Label(body, text="Finding fix guide", font=("Segoe UI", 17, "bold"), bg=COLORS["bg"], fg=COLORS["text"]).pack(anchor="w")
        description = tk.Label(body, text="Choose a finding to see safe manual steps, verification, and any available allowlisted fix.", font=("Segoe UI", 10), bg=COLORS["bg"], fg=COLORS["subtle"], wraplength=460, justify="left")
        description.pack(anchor="w", pady=(5, 14))
        tk.Label(body, text="SEARCH FINDINGS", font=("Segoe UI", 8, "bold"), bg=COLORS["bg"], fg=COLORS["subtle"]).pack(anchor="w", pady=(0, 4))
        query = tk.StringVar()
        search = tk.Entry(body, textvariable=query, font=("Segoe UI", 10), bg=COLORS["card"], fg=COLORS["text"], insertbackground=COLORS["text"], relief="flat", highlightthickness=1, highlightbackground=COLORS["border"], highlightcolor=COLORS["accent"])
        search.pack(fill="x", ipady=7, pady=(0, 12))
        results = tk.Frame(body, bg=COLORS["bg"])
        results.pack(fill="x")

        groups = {
            "Entry & execution": ["smb_v1_enabled", "rdp_enabled", "autorun_enabled", "macro_execution_enabled", "powershell_unrestricted"],
            "Access & privilege": ["open_network_shares", "admin_shares_enabled", "nla_disabled", "guest_account_active", "uac_disabled", "always_install_elevated", "wdigest_enabled", "lsass_protection_off", "laps_absent"],
            "Protection controls": ["defender_disabled", "firewall_disabled", "tamper_protection_off", "event_logging_disabled", "applocker_absent", "vulnerable_driver_blocklist_enabled", "hvci_enabled", "asr_rules_configured"],
            "Recovery & resilience": ["vss_deleted", "backup_absent", "bitlocker_off"],
            "Active validation (mock checks)": ["mock_attack_vss_enum_succeeded", "mock_attack_mass_rename_succeeded"],
        }

        def render_guides(*_args):
            for child in results.winfo_children():
                child.destroy()
            needle = query.get().strip().casefold()
            shown = 0
            for category, keys in groups.items():
                matching = []
                for key in keys:
                    if key not in MANUAL_FIX_GUIDES:
                        continue
                    title = ABOUT_INFO.get(key, (key.replace("_", " ").title(),))[0]
                    cmd = PARAM_TO_CMD_KEY.get(key)
                    automated = cmd in AGENT_REMEDIATION
                    search_text = f"{title} {key} {category} {'automated fix' if automated else 'manual only'}".casefold()
                    if not needle or needle in search_text:
                        matching.append((key, title, automated))
                if not matching:
                    continue
                tk.Label(results, text=category.upper(), font=("Segoe UI", 8, "bold"), bg=COLORS["bg"], fg=COLORS["info"]).pack(anchor="w", pady=(8, 4))
                for key, title, automated in matching:
                    row = RoundedCard(results, radius=10, inset=5, fill=COLORS["card"])
                    row.pack(fill="x", pady=2)
                    agent_button(row.content, text=title, font=("Segoe UI", 9, "bold"), bg=COLORS["card"], fg=COLORS["text"], activebackground=COLORS["card2"], activeforeground=COLORS["text"], anchor="w", relief="flat", bd=0, cursor="hand2", command=lambda k=key: self._show_fix_guide(k)).pack(side="left", fill="x", expand=True)
                    status = "AUTOMATED FIX" if automated else "MANUAL ONLY"
                    status_color = COLORS["accent"] if automated else COLORS["subtle"]
                    tk.Label(row.content, text=status, font=("Segoe UI", 7, "bold"), bg=COLORS["card"], fg=status_color).pack(side="right", padx=(7, 0))
                    shown += 1
            if shown == 0:
                tk.Label(results, text="No matching guides. Try a shorter search.", font=("Segoe UI", 9), bg=COLORS["bg"], fg=COLORS["subtle"]).pack(anchor="w", pady=12)

        query.trace_add("write", render_guides)
        render_guides()
        dialog.bind(
            "<Configure>",
            lambda event: description.configure(wraplength=max(240, event.width - 76))
            if event.widget is dialog else None,
        )
        dialog.bind("<Escape>", lambda _e: dialog.destroy())
        dialog.after_idle(search.focus_set)

    def _on_fix_clicked(self, cmd_key: str):
        """Require an explicit confirmation before a local allowlisted change."""
        if cmd_key not in AGENT_REMEDIATION:
            messagebox.showerror("Fix unavailable", "This fix is not in the agent's local allowlist.", parent=self)
            return
        confirmed = messagebox.askyesno(
            "Confirm configuration change",
            f"Apply the predefined '{cmd_key}' fix on this endpoint now?\n\n"
            "This may change Windows settings and may require administrator rights or a restart. Review the How to fix guide first.",
            icon="warning",
            parent=self,
        )
        if not confirmed:
            return
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
        about_win.geometry("560x640")
        about_win.configure(bg=COLORS["bg"])
        about_win.transient(self)
        about_win.resizable(True, True)
        about_win.minsize(460, 440)

        # Scrollable canvas for the accordion
        canvas = tk.Canvas(about_win, bg=COLORS["bg"], highlightthickness=0)
        about_win.scrollable_canvas = canvas

        scrollbar = ttk.Scrollbar(about_win, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=COLORS["bg"])

        scrollable_frame.bind(
            "<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        content_window = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw", width=520)
        canvas.bind(
            "<Configure>",
            lambda event: canvas.itemconfigure(content_window, width=max(360, event.width - 20)),
        )
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
        about_wrap_targets = []

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
            btn = agent_button(
                container,
                text=f"► {title}",
                font=("Segoe UI", 10, "bold"),
                bg=COLORS["card"],
                fg=COLORS["text"],
                activebackground=COLORS["card2"],
                activeforeground=COLORS["text"],
                anchor="w",
                padx=10,
                pady=8,
                cursor="hand2",
                command=lambda k=key: toggle_accordion(k),
            )
            btn.pack(fill="x")
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
            about_wrap_targets.append(desc_lbl)

            self.accordion_frames[key] = content_frame

        about_win.bind(
            "<Configure>",
            lambda event: [
                label.configure(wraplength=max(240, event.width - 100))
                for label in about_wrap_targets
                if label.winfo_exists()
            ] if event.widget is about_win else None,
        )
        about_win.bind("<Escape>", lambda _e: about_win.destroy())
        about_win.focus_set()


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
