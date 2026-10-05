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
MANUAL_FIX_GUIDES = {   'admin_shares_enabled': {   'caution': 'Disabling admin shares may disrupt remote management software (SCCM, PDQ) '
                                           'or agentless backup tools. Coordinate with system administrators.',
                                'summary': 'Restrict or disable default administrative hidden shares (C$, ADMIN$) to '
                                           'prevent attackers from executing remote tools like PsExec across the '
                                           'subnet.',
                                'tabs': {   'server': {   'cli': 'Set-ItemProperty -Path '
                                                                 "'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' "
                                                                 "-Name 'AutoShareServer' -Value 0 -Type DWord; "
                                                                 'Restart-Service LanmanServer -Force',
                                                          'gui': [   'On servers, administrative shares are commonly '
                                                                     'used by backup and deployment agents.',
                                                                     'Best practice is to restrict inbound SMB (Port '
                                                                     '445) to dedicated management IPs in Windows '
                                                                     'Firewall.',
                                                                     'If policy requires disabling server auto-shares '
                                                                     'completely, apply the AutoShareServer registry '
                                                                     'key.'],
                                                          'label': 'Windows Server'},
                                            'win10': {   'cli': 'Set-ItemProperty -Path '
                                                                "'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' "
                                                                "-Name 'AutoShareWks' -Value 0 -Type DWord; "
                                                                'Restart-Service LanmanServer -Force',
                                                         'gui': [   'Open Windows Defender Firewall with Advanced '
                                                                    "Security ('wf.msc').",
                                                                    'Scope Inbound SMB (TCP port 445) rules to '
                                                                    'management IP subnets only.',
                                                                    'To disable auto-shares completely on '
                                                                    'workstations, run the PowerShell command below.'],
                                                         'label': 'Windows 10'},
                                            'win11': {   'cli': 'Set-ItemProperty -Path '
                                                                "'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' "
                                                                "-Name 'AutoShareWks' -Value 0 -Type DWord; "
                                                                'Restart-Service LanmanServer -Force',
                                                         'gui': [   "Press Win + R, type 'wf.msc' (Windows Firewall "
                                                                    'with Advanced Security) and press Enter.',
                                                                    "Click Inbound Rules, locate 'File and Printer "
                                                                    "Sharing (SMB-In)', and restrict the Remote IP "
                                                                    'Address scope to approved admin workstations '
                                                                    'only.',
                                                                    'Alternatively, disable client auto-shares via the '
                                                                    'registry command below.'],
                                                         'label': 'Windows 11'}},
                                'verify': "Run 'Get-SmbShare' in PowerShell. Administrative shares C$ and ADMIN$ "
                                          'should be removed or inaccessible from unapproved hosts.'},
    'always_install_elevated': {   'caution': 'Standard users will require administrator elevation or an automated '
                                              'software distribution tool to install system software.',
                                   'summary': 'Disable AlwaysInstallElevated to stop standard unprivileged users from '
                                              'installing malicious MSI packages with SYSTEM rights.',
                                   'tabs': {   'server': {   'cli': 'Remove-ItemProperty -Path '
                                                                    "'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' "
                                                                    "-Name 'AlwaysInstallElevated' -ErrorAction "
                                                                    'SilentlyContinue; Remove-ItemProperty -Path '
                                                                    "'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' "
                                                                    "-Name 'AlwaysInstallElevated' -ErrorAction "
                                                                    'SilentlyContinue',
                                                             'gui': [   'Open Group Policy Management Console or '
                                                                        "'gpedit.msc'.",
                                                                        "Set 'Always install with elevated privileges' "
                                                                        'to Disabled under both Computer Configuration '
                                                                        'and User Configuration.',
                                                                        'Run the CLI cleanup command to purge registry '
                                                                        'values.'],
                                                             'label': 'Windows Server'},
                                               'win10': {   'cli': 'Remove-ItemProperty -Path '
                                                                   "'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' "
                                                                   "-Name 'AlwaysInstallElevated' -ErrorAction "
                                                                   'SilentlyContinue; Remove-ItemProperty -Path '
                                                                   "'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' "
                                                                   "-Name 'AlwaysInstallElevated' -ErrorAction "
                                                                   'SilentlyContinue',
                                                            'gui': [   "Open 'gpedit.msc'.",
                                                                       'Go to Computer Configuration & User '
                                                                       'Configuration > Admin Templates > Windows '
                                                                       'Components > Windows Installer.',
                                                                       "Set 'Always install with elevated privileges' "
                                                                       'to Disabled in both locations.',
                                                                       "Run 'gpupdate /force'."],
                                                            'label': 'Windows 10'},
                                               'win11': {   'cli': 'Remove-ItemProperty -Path '
                                                                   "'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' "
                                                                   "-Name 'AlwaysInstallElevated' -ErrorAction "
                                                                   'SilentlyContinue; Remove-ItemProperty -Path '
                                                                   "'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' "
                                                                   "-Name 'AlwaysInstallElevated' -ErrorAction "
                                                                   'SilentlyContinue',
                                                            'gui': [   "Press Win + R, type 'gpedit.msc' and press "
                                                                       'Enter.',
                                                                       'Navigate to: Computer Configuration > '
                                                                       'Administrative Templates > Windows Components '
                                                                       '> Windows Installer.',
                                                                       "Double-click 'Always install with elevated "
                                                                       "privileges' and set it to 'Disabled'.",
                                                                       'Repeat the step under User Configuration > '
                                                                       'Administrative Templates > Windows Components '
                                                                       '> Windows Installer.'],
                                                            'label': 'Windows 11'}},
                                   'verify': "Run 'Get-ItemProperty -Path "
                                             'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer -Name '
                                             "AlwaysInstallElevated -ErrorAction SilentlyContinue'. It must return "
                                             'null or 0.'},
    'applocker_absent': {   'caution': 'CRITICAL: Always generate Default Rules (allowing %WINDIR% and %PROGRAMFILES%) '
                                       'before switching from Audit to Enforce mode to avoid blocking essential system '
                                       'binaries.',
                            'summary': 'Configure AppLocker application control policies to ensure only verified, '
                                       'authorized executables can launch on the endpoint.',
                            'tabs': {   'server': {   'cli': 'Set-Service -Name AppIDSvc -StartupType Automatic; '
                                                             'Start-Service AppIDSvc',
                                                      'gui': [   'Server Manager > Tools > Local Security Policy (or '
                                                                 'Group Policy Management for fleet).',
                                                                 'Navigate to Application Control Policies > '
                                                                 'AppLocker.',
                                                                 'Create Default Rules under Executable Rules and '
                                                                 'Packaged App Rules.',
                                                                 'Set Application Identity service to Automatic and '
                                                                 'start it.'],
                                                      'label': 'Windows Server'},
                                        'win10': {   'cli': 'Set-Service -Name AppIDSvc -StartupType Automatic; '
                                                            'Start-Service AppIDSvc',
                                                     'gui': [   "Press Win + R, type 'secpol.msc' and navigate to "
                                                                'Application Control Policies > AppLocker.',
                                                                'Right-click Executable Rules > Create Default Rules.',
                                                                'Enable rule enforcement in Audit mode first.',
                                                                'Ensure the Application Identity service is started '
                                                                'and set to Automatic.'],
                                                     'label': 'Windows 10'},
                                        'win11': {   'cli': 'Set-Service -Name AppIDSvc -StartupType Automatic; '
                                                            'Start-Service AppIDSvc',
                                                     'gui': [   "Press Win + R, type 'secpol.msc' and press Enter.",
                                                                'Navigate to Application Control Policies > AppLocker.',
                                                                "Click 'Configure rule enforcement' and check "
                                                                "'Configured' under Executable rules (start with "
                                                                "'Audit only').",
                                                                "Right-click Executable Rules > 'Create Default Rules' "
                                                                'to ensure Windows and Program Files remain '
                                                                'accessible.',
                                                                'Start the Application Identity service: Win + R > '
                                                                'services.msc > Application Identity > Set to '
                                                                'Automatic and Start.'],
                                                     'label': 'Windows 11'}},
                            'verify': "Run 'Get-Service AppIDSvc' in elevated PowerShell. Confirm Status is 'Running'. "
                                      'Check Event Viewer > Applications and Services Logs > Microsoft > Windows > '
                                      'AppLocker.'},
    'asr_rules_configured': {   'caution': 'In organizations with specialized Office macro add-ins, test ASR rules in '
                                           'Audit mode first to verify compatibility before enforcing.',
                                'summary': 'Configure Microsoft Defender Attack Surface Reduction (ASR) rules to block '
                                           'common malware exploitation pathways.',
                                'tabs': {   'server': {   'cli': 'Add-MpPreference -AttackSurfaceReductionRules_Ids '
                                                                 "'d4f940ab-401b-4efc-aadc-ad5f3c50688a','be9ba2d9-53ea-44a7-9161-ab422405a9c6' "
                                                                 '-AttackSurfaceReductionRules_Actions Enabled',
                                                          'gui': [   'Configure through Microsoft Intune / Defender '
                                                                     'for Endpoint security portal for fleet '
                                                                     'deployment.',
                                                                     'On standalone servers with Defender, run the '
                                                                     'PowerShell command below.'],
                                                          'label': 'Windows Server'},
                                            'win10': {   'cli': 'Add-MpPreference -AttackSurfaceReductionRules_Ids '
                                                                "'d4f940ab-401b-4efc-aadc-ad5f3c50688a','be9ba2d9-53ea-44a7-9161-ab422405a9c6','92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' "
                                                                '-AttackSurfaceReductionRules_Actions Enabled',
                                                         'gui': [   "Open 'gpedit.msc' > Computer Configuration > "
                                                                    'Admin Templates > Windows Components > Microsoft '
                                                                    'Defender Antivirus > Attack Surface Reduction.',
                                                                    "Open 'Configure Attack Surface Reduction rules', "
                                                                    'set to Enabled, and add the rule GUIDs.',
                                                                    'Or run the PowerShell command directly as '
                                                                    'Administrator.'],
                                                         'label': 'Windows 10'},
                                            'win11': {   'cli': 'Add-MpPreference -AttackSurfaceReductionRules_Ids '
                                                                "'d4f940ab-401b-4efc-aadc-ad5f3c50688a','be9ba2d9-53ea-44a7-9161-ab422405a9c6','92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' "
                                                                '-AttackSurfaceReductionRules_Actions Enabled',
                                                         'gui': [   'Open Terminal (PowerShell Admin).',
                                                                    'Run the CLI command below to enable core ASR '
                                                                    'rules protecting against ransomware (blocking '
                                                                    'child processes from Office apps and blocking '
                                                                    'credential stealing).'],
                                                         'label': 'Windows 11'}},
                                'verify': "Run 'Get-MpPreference | Select-Object -ExpandProperty "
                                          "AttackSurfaceReductionRules_Ids' in PowerShell. Rule GUIDs must be listed."},
    'autorun_enabled': {   'caution': 'This disables automatic launching; users can still manually open files in File '
                                      'Explorer.',
                           'summary': 'Disable USB AutoRun and AutoPlay so connected removable drives cannot '
                                      'automatically execute rogue binaries.',
                           'tabs': {   'server': {   'cli': '$path = '
                                                            "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer'; "
                                                            'if (!(Test-Path $path)) { New-Item -Path $path -Force }; '
                                                            "Set-ItemProperty -Path $path -Name 'NoDriveTypeAutoRun' "
                                                            '-Value 255 -Type DWord',
                                                     'gui': [   "Press Win + R, type 'gpedit.msc' and press Enter.",
                                                                'Navigate to Computer Configuration > Administrative '
                                                                'Templates > Windows Components > AutoPlay Policies.',
                                                                "Double-click 'Turn off AutoPlay', select 'Enabled', "
                                                                "choose 'All drives', and click OK."],
                                                     'label': 'Windows Server'},
                                       'win10': {   'cli': '$path = '
                                                           "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer'; "
                                                           'if (!(Test-Path $path)) { New-Item -Path $path -Force }; '
                                                           "Set-ItemProperty -Path $path -Name 'NoDriveTypeAutoRun' "
                                                           '-Value 255 -Type DWord',
                                                    'gui': [   'Open Settings (Win + I) and navigate to Devices > '
                                                               'AutoPlay.',
                                                               "Toggle 'Use AutoPlay for all media and devices' to "
                                                               'OFF.',
                                                               "Set dropdowns for removable drives to 'Take no "
                                                               "action'."],
                                                    'label': 'Windows 10'},
                                       'win11': {   'cli': '$path = '
                                                           "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer'; "
                                                           'if (!(Test-Path $path)) { New-Item -Path $path -Force }; '
                                                           "Set-ItemProperty -Path $path -Name 'NoDriveTypeAutoRun' "
                                                           '-Value 255 -Type DWord',
                                                    'gui': [   'Open Settings (Win + I) and navigate to Bluetooth & '
                                                               'devices > AutoPlay.',
                                                               "Toggle 'Use AutoPlay for all media and devices' to "
                                                               'OFF.',
                                                               'Set Removable drive and Memory card default actions to '
                                                               "'Take no action'."],
                                                    'label': 'Windows 11'}},
                           'verify': "Run 'Get-ItemPropertyValue -Path "
                                     'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer -Name '
                                     "NoDriveTypeAutoRun'. It should return '255'."},
    'backup_absent': {   'caution': 'Ensure at least one backup tier is air-gapped, immutable, or stored offsite so '
                                    'attackers cannot delete backups prior to triggering ransomware.',
                         'summary': 'Configure scheduled, resilient backups to provide a dependable fail-safe against '
                                    'total data loss during encryption events.',
                         'tabs': {   'server': {   'cli': 'Install-WindowsFeature Windows-Server-Backup; Start-Service '
                                                          "-Name 'wbengine' -ErrorAction SilentlyContinue",
                                                   'gui': [   'Open Server Manager > Manage > Add Roles and Features > '
                                                              "Features > Check 'Windows Server Backup' > Install.",
                                                              "Open Tools > Windows Server Backup ('wbadmin.msc').",
                                                              "Click 'Backup Schedule Wizard' in the Actions pane and "
                                                              'configure a daily automated backup to dedicated '
                                                              'storage.'],
                                                   'label': 'Windows Server'},
                                     'win10': {   'cli': "Set-Service -Name 'fhsvc' -StartupType Automatic "
                                                         "-ErrorAction SilentlyContinue; Start-Service 'fhsvc' "
                                                         '-ErrorAction SilentlyContinue',
                                                  'gui': [   'Open Settings (Win + I) > Update & Security > Backup.',
                                                             "Click 'Add a drive' under 'Back up using File History' "
                                                             'and select a dedicated backup drive.',
                                                             "Click 'More options' and verify backup frequency (e.g. "
                                                             'Every hour or daily).'],
                                                  'label': 'Windows 10'},
                                     'win11': {   'cli': "Set-Service -Name 'fhsvc' -StartupType Automatic "
                                                         "-ErrorAction SilentlyContinue; Start-Service 'fhsvc' "
                                                         '-ErrorAction SilentlyContinue',
                                                  'gui': [   'Open Settings (Win + I) > System > Storage > Advanced '
                                                             'storage settings > Backup options.',
                                                             'Configure File History with an external hard drive or '
                                                             'setup automatic OneDrive / enterprise cloud sync.',
                                                             'Alternatively, deploy and schedule an approved '
                                                             'enterprise backup agent (e.g. Veeam, Acronis).'],
                                                  'label': 'Windows 11'}},
                         'verify': "Run 'wbadmin get status' or inspect your backup software console to confirm recent "
                                   'successful backup jobs.'},
    'backup_configured': {   'caution': 'Ensure at least one backup tier is air-gapped, immutable, or stored offsite '
                                        'so attackers cannot delete backups prior to triggering ransomware.',
                             'summary': 'Configure scheduled, resilient backups to provide a dependable fail-safe '
                                        'against total data loss during encryption events.',
                             'tabs': {   'server': {   'cli': 'Install-WindowsFeature Windows-Server-Backup; '
                                                              "Start-Service -Name 'wbengine' -ErrorAction "
                                                              'SilentlyContinue',
                                                       'gui': [   'Open Server Manager > Manage > Add Roles and '
                                                                  "Features > Features > Check 'Windows Server Backup' "
                                                                  '> Install.',
                                                                  "Open Tools > Windows Server Backup ('wbadmin.msc').",
                                                                  "Click 'Backup Schedule Wizard' in the Actions pane "
                                                                  'and configure a daily automated backup to dedicated '
                                                                  'storage.'],
                                                       'label': 'Windows Server'},
                                         'win10': {   'cli': "Set-Service -Name 'fhsvc' -StartupType Automatic "
                                                             "-ErrorAction SilentlyContinue; Start-Service 'fhsvc' "
                                                             '-ErrorAction SilentlyContinue',
                                                      'gui': [   'Open Settings (Win + I) > Update & Security > '
                                                                 'Backup.',
                                                                 "Click 'Add a drive' under 'Back up using File "
                                                                 "History' and select a dedicated backup drive.",
                                                                 "Click 'More options' and verify backup frequency "
                                                                 '(e.g. Every hour or daily).'],
                                                      'label': 'Windows 10'},
                                         'win11': {   'cli': "Set-Service -Name 'fhsvc' -StartupType Automatic "
                                                             "-ErrorAction SilentlyContinue; Start-Service 'fhsvc' "
                                                             '-ErrorAction SilentlyContinue',
                                                      'gui': [   'Open Settings (Win + I) > System > Storage > '
                                                                 'Advanced storage settings > Backup options.',
                                                                 'Configure File History with an external hard drive '
                                                                 'or setup automatic OneDrive / enterprise cloud sync.',
                                                                 'Alternatively, deploy and schedule an approved '
                                                                 'enterprise backup agent (e.g. Veeam, Acronis).'],
                                                      'label': 'Windows 11'}},
                             'verify': "Run 'wbadmin get status' or inspect your backup software console to confirm "
                                       'recent successful backup jobs.'},
    'bitlocker_off': {   'caution': 'MANDATORY: Always backup and confirm retrieval of the 48-digit BitLocker recovery '
                                    'key to Active Directory or a secure vault before initiating encryption.',
                         'summary': 'Enable BitLocker full-disk encryption to prevent offline data theft, physical '
                                    'drive extraction, and extortion.',
                         'tabs': {   'server': {   'cli': 'Install-WindowsFeature BitLocker -IncludeManagementTools; '
                                                          "Enable-BitLocker -MountPoint 'C:' -TpmProtector",
                                                   'gui': [   'Server Manager > Add Roles and Features > Features > '
                                                              "Check 'BitLocker Drive Encryption' > Install (reboot "
                                                              'required).',
                                                              'After reboot, open File Explorer, right-click Drive C: '
                                                              "> 'Turn on BitLocker'.",
                                                              'Escrow the recovery key into Active Directory Domain '
                                                              'Services.'],
                                                   'label': 'Windows Server'},
                                     'win10': {   'cli': "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod "
                                                         'XtsAes256 -UsedSpaceOnly -TpmProtector',
                                                  'gui': [   'Open Control Panel > System and Security > BitLocker '
                                                             'Drive Encryption.',
                                                             "Click 'Turn on BitLocker' next to the operating system "
                                                             'drive.',
                                                             'Save the 48-digit recovery key in a secure location.',
                                                             'Follow the setup wizard to complete drive encryption.'],
                                                  'label': 'Windows 10'},
                                     'win11': {   'cli': "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod "
                                                         'XtsAes256 -UsedSpaceOnly -TpmProtector',
                                                  'gui': [   'Open Settings (Win + I) > Privacy & security > Device '
                                                             'encryption (or Control Panel > BitLocker Drive '
                                                             'Encryption).',
                                                             "Click 'Turn on BitLocker' for Drive C:.",
                                                             'Choose how to back up your recovery key (Microsoft '
                                                             'Account, Entra ID, or Print/Save file).',
                                                             "Choose 'Encrypt used disk space only' and 'New "
                                                             "encryption mode', then start encryption."],
                                                  'label': 'Windows 11'}},
                         'verify': "Run 'manage-bde -status C:' in elevated command prompt. 'Protection Status' must "
                                   "show 'Protection On'."},
    'defender_disabled': {   'caution': 'If an authorized third-party enterprise EDR (e.g. CrowdStrike, SentinelOne) '
                                        'is deployed, Defender may operate in passive mode. Coordinate with your IT '
                                        'security team.',
                             'summary': 'Enable Windows Defender real-time antivirus protection to detect and '
                                        'quarantine malware signatures and heuristic threats.',
                             'tabs': {   'server': {   'cli': 'Set-MpPreference -DisableRealtimeMonitoring $false; '
                                                              'Start-Service WinDefend -ErrorAction SilentlyContinue',
                                                       'gui': [   'Open Server Manager > Local Server.',
                                                                  'Verify Windows Defender is installed (if not, add '
                                                                  'feature via Add Roles and Features > Windows '
                                                                  'Defender Antivirus).',
                                                                  'Open Windows Security from Start menu > Virus & '
                                                                  'threat protection > Turn ON Real-time protection.'],
                                                       'label': 'Windows Server'},
                                         'win10': {   'cli': 'Set-MpPreference -DisableRealtimeMonitoring $false; '
                                                             'Start-Service WinDefend -ErrorAction SilentlyContinue',
                                                      'gui': [   'Open Settings (Win + I) > Update & Security > '
                                                                 'Windows Security.',
                                                                 "Click 'Virus & threat protection' > 'Manage "
                                                                 "settings'.",
                                                                 "Toggle 'Real-time protection' to ON."],
                                                      'label': 'Windows 10'},
                                         'win11': {   'cli': 'Set-MpPreference -DisableRealtimeMonitoring $false; '
                                                             'Start-Service WinDefend -ErrorAction SilentlyContinue',
                                                      'gui': [   'Open Settings (Win + I) > Privacy & security > '
                                                                 'Windows Security.',
                                                                 "Click 'Virus & threat protection', then click "
                                                                 "'Manage settings' under Virus & threat protection "
                                                                 'settings.',
                                                                 "Toggle 'Real-time protection' to ON.",
                                                                 "Also toggle 'Cloud-delivered protection' and "
                                                                 "'Automatic sample submission' to ON."],
                                                      'label': 'Windows 11'}},
                             'verify': "Run '(Get-MpComputerStatus).RealTimeProtectionEnabled' in PowerShell. It must "
                                       "return 'True'."},
    'event_logging_disabled': {   'caution': 'Never clear event logs as a diagnostic step, as doing so destroys '
                                             'critical forensic traces during an ongoing security incident.',
                                  'summary': 'Start and configure the Windows Event Log service so all logon, process '
                                             'execution, and security events are recorded for forensics.',
                                  'tabs': {   'server': {   'cli': "Set-Service -Name 'eventlog' -StartupType "
                                                                   "Automatic; Start-Service -Name 'eventlog'",
                                                            'gui': [   'Server Manager > Tools > Services.',
                                                                       "Locate 'Windows Event Log', open Properties.",
                                                                       "Set Startup type to 'Automatic' and click "
                                                                       "'Start'."],
                                                            'label': 'Windows Server'},
                                              'win10': {   'cli': "Set-Service -Name 'eventlog' -StartupType "
                                                                  "Automatic; Start-Service -Name 'eventlog'",
                                                           'gui': [   "Press Win + R, type 'services.msc' and press "
                                                                      'Enter.',
                                                                      "Double-click 'Windows Event Log' in the list.",
                                                                      "Set Startup type to 'Automatic', click 'Start', "
                                                                      'and click OK.'],
                                                           'label': 'Windows 10'},
                                              'win11': {   'cli': "Set-Service -Name 'eventlog' -StartupType "
                                                                  "Automatic; Start-Service -Name 'eventlog'",
                                                           'gui': [   "Press Win + R, type 'services.msc' and press "
                                                                      'Enter.',
                                                                      "Scroll down to 'Windows Event Log'.",
                                                                      'Right-click > Properties > Set Startup type to '
                                                                      "'Automatic'.",
                                                                      "Click 'Start' if the service is stopped, then "
                                                                      'click OK.'],
                                                           'label': 'Windows 11'}},
                                  'verify': "Run 'Get-Service eventlog' in PowerShell. Status must be 'Running' and "
                                            "StartType must be 'Automatic'."},
    'firewall_disabled': {   'caution': 'Ensure required line-of-business services have specific inbound port allow '
                                        'rules before turning on the firewall to prevent connection drops.',
                             'summary': 'Enable Windows Defender Firewall across Domain, Private, and Public profiles '
                                        'to block unauthorized inbound connections and scanning.',
                             'tabs': {   'server': {   'cli': 'Set-NetFirewallProfile -Profile Domain,Public,Private '
                                                              '-Enabled True',
                                                       'gui': [   "Server Manager > Local Server > Click 'Windows "
                                                                  "Defender Firewall'.",
                                                                  "Click 'Turn Windows Defender Firewall on or off' in "
                                                                  'the left pane.',
                                                                  "Select 'Turn on Windows Defender Firewall' for all "
                                                                  'network locations and click OK.'],
                                                       'label': 'Windows Server'},
                                         'win10': {   'cli': 'Set-NetFirewallProfile -Profile Domain,Public,Private '
                                                             '-Enabled True',
                                                      'gui': [   'Open Settings (Win + I) > Update & Security > '
                                                                 'Windows Security > Firewall & network protection.',
                                                                 'Click each profile (Domain, Private, Public) and '
                                                                 'toggle the firewall to ON.'],
                                                      'label': 'Windows 10'},
                                         'win11': {   'cli': 'Set-NetFirewallProfile -Profile Domain,Public,Private '
                                                             '-Enabled True',
                                                      'gui': [   'Open Settings (Win + I) > Privacy & security > '
                                                                 'Windows Security > Firewall & network protection.',
                                                                 'Click on Domain network, Private network, and Public '
                                                                 'network.',
                                                                 "Toggle 'Microsoft Defender Firewall' to ON for all "
                                                                 'three profiles.'],
                                                      'label': 'Windows 11'}},
                             'verify': "Run 'Get-NetFirewallProfile | Select-Object Name, Enabled' in PowerShell. All "
                                       'three profiles must report Enabled: True.'},
    'firewall_on': {   'caution': 'Ensure required line-of-business services have specific inbound port allow rules '
                                  'before turning on the firewall to prevent connection drops.',
                       'summary': 'Enable Windows Defender Firewall across Domain, Private, and Public profiles to '
                                  'block unauthorized inbound connections and scanning.',
                       'tabs': {   'server': {   'cli': 'Set-NetFirewallProfile -Profile Domain,Public,Private '
                                                        '-Enabled True',
                                                 'gui': [   "Server Manager > Local Server > Click 'Windows Defender "
                                                            "Firewall'.",
                                                            "Click 'Turn Windows Defender Firewall on or off' in the "
                                                            'left pane.',
                                                            "Select 'Turn on Windows Defender Firewall' for all "
                                                            'network locations and click OK.'],
                                                 'label': 'Windows Server'},
                                   'win10': {   'cli': 'Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled '
                                                       'True',
                                                'gui': [   'Open Settings (Win + I) > Update & Security > Windows '
                                                           'Security > Firewall & network protection.',
                                                           'Click each profile (Domain, Private, Public) and toggle '
                                                           'the firewall to ON.'],
                                                'label': 'Windows 10'},
                                   'win11': {   'cli': 'Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled '
                                                       'True',
                                                'gui': [   'Open Settings (Win + I) > Privacy & security > Windows '
                                                           'Security > Firewall & network protection.',
                                                           'Click on Domain network, Private network, and Public '
                                                           'network.',
                                                           "Toggle 'Microsoft Defender Firewall' to ON for all three "
                                                           'profiles.'],
                                                'label': 'Windows 11'}},
                       'verify': "Run 'Get-NetFirewallProfile | Select-Object Name, Enabled' in PowerShell. All three "
                                 'profiles must report Enabled: True.'},
    'guest_account_active': {   'caution': 'Never delete the Guest account (it is a built-in operating system security '
                                           'principal); keep it disabled.',
                                'summary': 'Disable the built-in Guest account to eliminate unauthenticated local and '
                                           'network logon opportunities for intruders.',
                                'tabs': {   'server': {   'cli': "Disable-LocalUser -Name 'Guest' -ErrorAction "
                                                                 'SilentlyContinue',
                                                          'gui': [   'Server Manager > Tools > Computer Management > '
                                                                     'Local Users and Groups > Users.',
                                                                     'Right-click Guest > Properties.',
                                                                     "Ensure 'Account is disabled' is checked and "
                                                                     'click OK.'],
                                                          'label': 'Windows Server'},
                                            'win10': {   'cli': "Disable-LocalUser -Name 'Guest' -ErrorAction "
                                                                'SilentlyContinue',
                                                         'gui': [   "Press Win + R, type 'lusrmgr.msc' and press "
                                                                    'Enter.',
                                                                    'Open Users, right-click Guest > Properties.',
                                                                    "Check 'Account is disabled' and click Apply > "
                                                                    'OK.'],
                                                         'label': 'Windows 10'},
                                            'win11': {   'cli': "Disable-LocalUser -Name 'Guest' -ErrorAction "
                                                                'SilentlyContinue',
                                                         'gui': [   "Press Win + R, type 'lusrmgr.msc' and press "
                                                                    'Enter.',
                                                                    "Click 'Users' in the left pane.",
                                                                    "Right-click 'Guest' and select Properties.",
                                                                    "Check the box 'Account is disabled', then click "
                                                                    'OK.'],
                                                         'label': 'Windows 11'}},
                                'verify': "Run '(Get-LocalUser -Name Guest).Enabled' in PowerShell. It must return "
                                          "'False'."},
    'hvci_enabled': {   'caution': 'Requires CPU virtualization (Intel VT-x / AMD-V) enabled in BIOS/UEFI. '
                                   'Incompatible legacy hardware drivers must be updated before Memory Integrity will '
                                   'turn on.',
                        'summary': 'Enable HVCI (Hypervisor-Protected Code Integrity / Memory Integrity) to prevent '
                                   'unsigned kernel-mode rootkits and driver exploits.',
                        'tabs': {   'server': {   'cli': 'Set-ItemProperty -Path '
                                                         "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity' "
                                                         "-Name 'Enabled' -Value 1 -Type DWord",
                                                  'gui': [   "Open 'gpedit.msc' > Computer Configuration > "
                                                             'Administrative Templates > System > Device Guard.',
                                                             "Double-click 'Turn On Virtualization Based Security', "
                                                             'select Enabled.',
                                                             "Under 'Virtualization Based Protection of Code "
                                                             "Integrity', select 'Enabled with UEFI lock'.",
                                                             'Click OK and schedule a reboot.'],
                                                  'label': 'Windows Server'},
                                    'win10': {   'cli': 'Set-ItemProperty -Path '
                                                        "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity' "
                                                        "-Name 'Enabled' -Value 1 -Type DWord",
                                                 'gui': [   'Open Settings (Win + I) > Update & Security > Windows '
                                                            'Security > Device security.',
                                                            "Click 'Core isolation details'.",
                                                            "Toggle 'Memory integrity' to ON.",
                                                            'Restart your PC.'],
                                                 'label': 'Windows 10'},
                                    'win11': {   'cli': 'Set-ItemProperty -Path '
                                                        "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity' "
                                                        "-Name 'Enabled' -Value 1 -Type DWord",
                                                 'gui': [   'Open Settings (Win + I) > Privacy & security > Windows '
                                                            'Security > Device security.',
                                                            "Click 'Core isolation details'.",
                                                            "Toggle 'Memory integrity' to ON.",
                                                            'Restart your PC.'],
                                                 'label': 'Windows 11'}},
                        'verify': "Run 'Get-CimInstance -ClassName Win32_DeviceGuard -Namespace "
                                  "root\\Microsoft\\Windows\\DeviceGuard | Select-Object SecurityServicesRunning'. It "
                                  "should include '2' (HVCI)."},
    'laps_absent': {   'caution': 'Requires directory permissions and schema support so workstations can securely '
                                  'escrow random passwords into Active Directory or Entra ID.',
                       'summary': 'Deploy Windows LAPS to randomize and manage local administrator passwords, blocking '
                                  'pass-the-hash lateral traversal.',
                       'tabs': {   'server': {   'cli': 'Get-Command *Laps* -ErrorAction SilentlyContinue',
                                                 'gui': [   'Windows Server 2019/2022 includes native Windows LAPS '
                                                            'with current cumulative updates.',
                                                            'Open Domain Group Policy Management, configure LAPS under '
                                                            'Computer Configuration > Policies > Admin Templates > '
                                                            'System > LAPS.',
                                                            'Set the backup directory to Active Directory and assign '
                                                            'delegated read rights to IT administrators.'],
                                                 'label': 'Windows Server'},
                                   'win10': {   'cli': 'Get-Item C:\\Windows\\System32\\Laps.dll -ErrorAction '
                                                       'SilentlyContinue',
                                                'gui': [   'On updated Windows 10 (April 2023 update or later), native '
                                                           'Windows LAPS is installed.',
                                                           'For older builds, download and install the Microsoft LAPS '
                                                           'MSI package from Microsoft Download Center.',
                                                           "Configure policy via 'gpedit.msc' under System > LAPS."],
                                                'label': 'Windows 10'},
                                   'win11': {   'cli': 'Get-Item C:\\Windows\\System32\\Laps.dll -ErrorAction '
                                                       'SilentlyContinue',
                                                'gui': [   'Windows 11 (22H2+) includes native Windows LAPS built into '
                                                           'the OS!',
                                                           "Press Win + R, type 'gpedit.msc' > Computer Configuration "
                                                           '> Administrative Templates > System > LAPS.',
                                                           "Enable 'Configure password backup directory' and select "
                                                           "'Microsoft Entra ID' or 'Active Directory'.",
                                                           'Configure password complexity and age requirements.'],
                                                'label': 'Windows 11'}},
                       'verify': "Inspect 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\LAPS\\Config' or check "
                                 'Active Directory computer object for the msLAPS-Password attribute.'},
    'lsass_protection_off': {   'caution': 'Requires a system reboot. Verify that custom third-party smart card or '
                                           'biometric credential providers are digitally signed and compatible.',
                                'summary': 'Enable LSASS Protected Process Light (RunAsPPL) to prevent memory-dumping '
                                           'tools like Mimikatz from stealing credentials and Kerberos tickets.',
                                'tabs': {   'server': {   'cli': 'Set-ItemProperty -Path '
                                                                 "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
                                                                 "-Name 'RunAsPPL' -Value 1 -Type DWord",
                                                          'gui': [   "Open 'gpedit.msc' (or Group Policy Management "
                                                                     'Console).',
                                                                     'Navigate to Computer Configuration > '
                                                                     'Administrative Templates > System > Local '
                                                                     'Security Authority.',
                                                                     "Open 'Configures LSASS to run as a protected "
                                                                     "process', set to Enabled, and choose 'Enabled "
                                                                     "without UEFI lock' or 'Enabled with UEFI lock'.",
                                                                     'Restart the server during a scheduled '
                                                                     'maintenance window.'],
                                                          'label': 'Windows Server'},
                                            'win10': {   'cli': 'Set-ItemProperty -Path '
                                                                "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
                                                                "-Name 'RunAsPPL' -Value 1 -Type DWord",
                                                         'gui': [   "Press Win + R, type 'regedit' and press Enter.",
                                                                    'Navigate to '
                                                                    "'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa'.",
                                                                    'Right-click Lsa > New > DWORD (32-bit) Value, '
                                                                    "name it 'RunAsPPL' and set value to '1'.",
                                                                    'Restart the computer.'],
                                                         'label': 'Windows 10'},
                                            'win11': {   'cli': 'Set-ItemProperty -Path '
                                                                "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
                                                                "-Name 'RunAsPPL' -Value 1 -Type DWord",
                                                         'gui': [   'Open Settings (Win + I) > Privacy & security > '
                                                                    'Windows Security > Device security.',
                                                                    "Click 'Core isolation details'.",
                                                                    "Locate 'Local Security Authority protection' and "
                                                                    'toggle it to ON.',
                                                                    'Restart the computer when prompted.'],
                                                         'label': 'Windows 11'}},
                                'verify': "Run 'Get-ItemPropertyValue -Path "
                                          "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa -Name RunAsPPL' in "
                                          "PowerShell. It should return '1' or '2'. Check Event ID 3065 in "
                                          'Microsoft-Windows-CodeIntegrity/Operational.'},
    'macro_execution_enabled': {   'caution': 'If accounting or reporting processes use internal macros, sign them '
                                              'with an internal code-signing certificate rather than allowing unsigned '
                                              'macros.',
                                   'summary': 'Block unprompted execution of Microsoft Office VBA macros to eliminate '
                                              'a primary malware and ransomware downloader vector.',
                                   'tabs': {   'server': {   'cli': 'Set-ItemProperty -Path '
                                                                    "'HKCU:\\Software\\Microsoft\\Office\\16.0\\Word\\Security' "
                                                                    "-Name 'VBAWarnings' -Value 4 -Type DWord; "
                                                                    'Set-ItemProperty -Path '
                                                                    "'HKCU:\\Software\\Microsoft\\Office\\16.0\\Excel\\Security' "
                                                                    "-Name 'VBAWarnings' -Value 4 -Type DWord",
                                                             'gui': [   "For RDS/Terminal servers, open 'gpedit.msc' "
                                                                        'or Domain Group Policy.',
                                                                        'Navigate to User Configuration > '
                                                                        'Administrative Templates > Microsoft Office > '
                                                                        'Security Settings.',
                                                                        "Set 'VBA Macro Notification Settings' to "
                                                                        "Enabled and choose 'Disable all with "
                                                                        "notification'."],
                                                             'label': 'Windows Server'},
                                               'win10': {   'cli': 'Set-ItemProperty -Path '
                                                                   "'HKCU:\\Software\\Microsoft\\Office\\16.0\\Word\\Security' "
                                                                   "-Name 'VBAWarnings' -Value 4 -Type DWord; "
                                                                   'Set-ItemProperty -Path '
                                                                   "'HKCU:\\Software\\Microsoft\\Office\\16.0\\Excel\\Security' "
                                                                   "-Name 'VBAWarnings' -Value 4 -Type DWord",
                                                            'gui': [   'Open Word or Excel > File > Options.',
                                                                       'Navigate to Trust Center > Trust Center '
                                                                       'Settings > Macro Settings.',
                                                                       "Select 'Disable VBA macros with notification'.",
                                                                       'Click OK to save changes.'],
                                                            'label': 'Windows 10'},
                                               'win11': {   'cli': 'Set-ItemProperty -Path '
                                                                   "'HKCU:\\Software\\Microsoft\\Office\\16.0\\Word\\Security' "
                                                                   "-Name 'VBAWarnings' -Value 4 -Type DWord; "
                                                                   'Set-ItemProperty -Path '
                                                                   "'HKCU:\\Software\\Microsoft\\Office\\16.0\\Excel\\Security' "
                                                                   "-Name 'VBAWarnings' -Value 4 -Type DWord",
                                                            'gui': [   'Open Microsoft Word or Excel, then click File '
                                                                       '> Options.',
                                                                       'Click Trust Center > Trust Center Settings > '
                                                                       'Macro Settings.',
                                                                       "Select 'Disable VBA macros with notification' "
                                                                       "(or 'Disable all macros without "
                                                                       "notification').",
                                                                       "Check 'Enable macros in digitally signed "
                                                                       "documents' if your organization signs internal "
                                                                       'scripts, then click OK.'],
                                                            'label': 'Windows 11'}},
                                   'verify': 'Open Word/Excel > File > Options > Trust Center > Macro Settings. Verify '
                                             "'Disable VBA macros with notification' is selected."},
    'mock_attack_mass_rename_succeeded': {   'caution': 'Controlled folder access guards Documents, Pictures, and '
                                                        'Desktop folders. Legitimate custom apps writing to these '
                                                        "folders can be added via 'Add-MpPreference "
                                                        "-ControlledFolderAccessAllowedApplications'.",
                                             'summary': 'Active Validation Finding: The host permitted rapid file '
                                                        'renaming and extension modification in a short interval (the '
                                                        'hallmark of live ransomware encryption).',
                                             'tabs': {   'server': {   'cli': 'Set-MpPreference '
                                                                              '-EnableControlledFolderAccess Enabled',
                                                                       'gui': [   'On Windows Server with Defender, '
                                                                                  'enable Controlled folder access via '
                                                                                  'PowerShell or deploy '
                                                                                  'anti-ransomware heuristic policies '
                                                                                  'through your central EDR console.'],
                                                                       'label': 'Windows Server'},
                                                         'win10': {   'cli': 'Set-MpPreference '
                                                                             '-EnableControlledFolderAccess Enabled',
                                                                      'gui': [   'Open Settings (Win + I) > Update & '
                                                                                 'Security > Windows Security > Virus '
                                                                                 '& threat protection.',
                                                                                 "Click 'Manage ransomware "
                                                                                 "protection'.",
                                                                                 "Toggle 'Controlled folder access' to "
                                                                                 'ON.'],
                                                                      'label': 'Windows 10'},
                                                         'win11': {   'cli': 'Set-MpPreference '
                                                                             '-EnableControlledFolderAccess Enabled',
                                                                      'gui': [   'Open Settings (Win + I) > Privacy & '
                                                                                 'security > Windows Security > Virus '
                                                                                 '& threat protection.',
                                                                                 "Scroll down to 'Ransomware "
                                                                                 "protection' and click 'Manage "
                                                                                 "ransomware protection'.",
                                                                                 "Toggle 'Controlled folder access' to "
                                                                                 'ON to block unauthorized '
                                                                                 'applications from mass-altering '
                                                                                 'files.'],
                                                                      'label': 'Windows 11'}},
                                             'verify': "Run '(Get-MpPreference).EnableControlledFolderAccess' in "
                                                       "PowerShell. It should return '1' (Enabled). Perform a rescan "
                                                       'in R3P Agent.'},
    'mock_attack_vss_enum_succeeded': {   'caution': 'The R3P check is a safe, read-only simulation. Do not disable '
                                                     'WMI or Shadow Copy service to suppress this finding.',
                                          'summary': 'Active Validation Finding: The host permitted a WMI enumeration '
                                                     'query against Volume Shadow Copies without behavioral alert or '
                                                     'blocking.',
                                          'tabs': {   'server': {   'cli': 'Set-MpPreference '
                                                                           '-DisableBehaviorMonitoring $false',
                                                                    'gui': [   'In Microsoft Defender for Endpoint / '
                                                                               'third-party EDR, create an alert rule '
                                                                               'for suspicious discovery queries '
                                                                               'targeting Win32_ShadowCopy.',
                                                                               'Ensure behavioral monitoring is '
                                                                               'enabled on the server.'],
                                                                    'label': 'Windows Server'},
                                                      'win10': {   'cli': 'Set-MpPreference -DisableBehaviorMonitoring '
                                                                          '$false; Add-MpPreference '
                                                                          '-AttackSurfaceReductionRules_Ids '
                                                                          "'e6db77e5-3df2-4cf1-b95a-63e5dd9f9353' "
                                                                          '-AttackSurfaceReductionRules_Actions '
                                                                          'Enabled',
                                                                   'gui': [   'Open Settings > Update & Security > '
                                                                              'Windows Security > Virus & threat '
                                                                              'protection > Manage settings.',
                                                                              'Verify Real-time protection is ON.',
                                                                              'Execute the PowerShell command below to '
                                                                              'ensure behavior monitoring is active.'],
                                                                   'label': 'Windows 10'},
                                                      'win11': {   'cli': 'Set-MpPreference -DisableBehaviorMonitoring '
                                                                          '$false; Add-MpPreference '
                                                                          '-AttackSurfaceReductionRules_Ids '
                                                                          "'e6db77e5-3df2-4cf1-b95a-63e5dd9f9353' "
                                                                          '-AttackSurfaceReductionRules_Actions '
                                                                          'Enabled',
                                                                   'gui': [   'Open Windows Security > Virus & threat '
                                                                              'protection > Manage settings.',
                                                                              "Ensure 'Cloud-delivered protection' and "
                                                                              "'Automatic sample submission' are "
                                                                              'active.',
                                                                              'Enable Defender behavioral monitoring '
                                                                              'and WMI event persistence blocking via '
                                                                              'the PowerShell CLI below.'],
                                                                   'label': 'Windows 11'}},
                                          'verify': "Run '(Get-MpPreference).DisableBehaviorMonitoring' in PowerShell. "
                                                    "It must return 'False'. Perform a rescan in R3P Agent."},
    'nla_disabled': {   'caution': 'Pre-NLA legacy remote desktop clients will no longer be able to establish '
                                   'connections.',
                        'summary': 'Enforce Network Level Authentication (NLA) for Remote Desktop to mitigate '
                                   'pre-authentication vulnerabilities and denial-of-service risks.',
                        'tabs': {   'server': {   'cli': 'Set-ItemProperty -Path '
                                                         "'HKLM:\\System\\CurrentControlSet\\Control\\Terminal "
                                                         "Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' "
                                                         '-Value 1 -Type DWord',
                                                  'gui': [   'Server Manager > Local Server > Click on Remote Desktop '
                                                             'setting.',
                                                             "In System Properties, ensure 'Allow connections only "
                                                             'from computers running Remote Desktop with Network Level '
                                                             "Authentication' is checked.",
                                                             'Click OK.'],
                                                  'label': 'Windows Server'},
                                    'win10': {   'cli': 'Set-ItemProperty -Path '
                                                        "'HKLM:\\System\\CurrentControlSet\\Control\\Terminal "
                                                        "Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' "
                                                        '-Value 1 -Type DWord',
                                                 'gui': [   'Open Settings (Win + I) > System > Remote Desktop > Click '
                                                            "'Advanced settings'.",
                                                            "Check the box: 'Require computers to use Network Level "
                                                            "Authentication to connect'.",
                                                            'Return to Settings.'],
                                                 'label': 'Windows 10'},
                                    'win11': {   'cli': 'Set-ItemProperty -Path '
                                                        "'HKLM:\\System\\CurrentControlSet\\Control\\Terminal "
                                                        "Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' "
                                                        '-Value 1 -Type DWord',
                                                 'gui': [   "Press Win + R, type 'sysdm.cpl' and press Enter.",
                                                            "Select the 'Remote' tab.",
                                                            "Under Remote Desktop, check the box: 'Allow remote "
                                                            'connections only with Network Level Authentication '
                                                            "(recommended)'.",
                                                            'Click Apply > OK.'],
                                                 'label': 'Windows 11'}},
                        'verify': "Run 'Get-ItemPropertyValue -Path "
                                  '"HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" '
                                  "-Name UserAuthentication'. It must return '1'."},
    'open_network_shares': {   'caution': 'Review NTFS security permissions alongside share permissions. Ensure '
                                          'legitimate applications and employees retain necessary access.',
                               'summary': "Restrict network shares granting access to 'Everyone' to prevent ransomware "
                                          'from encrypting departmental shared folders.',
                               'tabs': {   'server': {   'cli': "Revoke-SmbShareAccess -Name '<ShareName>' "
                                                                "-AccountName 'Everyone' -Force",
                                                         'gui': [   'Open Server Manager > File and Storage Services > '
                                                                    'Shares.',
                                                                    'Right-click the share > Properties > Permissions '
                                                                    'tab.',
                                                                    "Click Customize permissions, select 'Everyone', "
                                                                    'and click Remove. Add authorized Active Directory '
                                                                    'security groups.'],
                                                         'label': 'Windows Server'},
                                           'win10': {   'cli': "Revoke-SmbShareAccess -Name '<ShareName>' -AccountName "
                                                               "'Everyone' -Force",
                                                        'gui': [   "Press Win + R, type 'fsmgmt.msc' or 'compmgmt.msc' "
                                                                   'and press Enter.',
                                                                   'Select Shares, right-click the open share, and '
                                                                   'choose Properties.',
                                                                   "Under the Share Permissions tab, remove 'Everyone' "
                                                                   'and grant permissions only to authorized user '
                                                                   'accounts.',
                                                                   'Check the Security (NTFS) tab to ensure underlying '
                                                                   'folder permissions match.'],
                                                        'label': 'Windows 10'},
                                           'win11': {   'cli': "Revoke-SmbShareAccess -Name '<ShareName>' -AccountName "
                                                               "'Everyone' -Force",
                                                        'gui': [   "Press Win + R, type 'compmgmt.msc' and press "
                                                                   'Enter.',
                                                                   'Navigate to System Tools > Shared Folders > '
                                                                   'Shares.',
                                                                   'Right-click the exposed share > Properties > Share '
                                                                   'Permissions tab.',
                                                                   "Select 'Everyone' and click Remove. Click Add to "
                                                                   'specify only authorized users or domain security '
                                                                   'groups with Least Privilege.'],
                                                        'label': 'Windows 11'}},
                               'verify': "Run 'Get-SmbShareAccess -Name <ShareName>' in PowerShell. Confirm 'Everyone' "
                                         'is absent from the access control list.'},
    'powershell_unrestricted': {   'caution': 'Execution policy is a safety guardrail, not an impenetrable security '
                                              'barrier. For comprehensive application control, deploy AppLocker or '
                                              'WDAC.',
                                   'summary': 'Enforce RemoteSigned execution policy to prevent unapproved external '
                                              'PowerShell scripts from running automatically.',
                                   'tabs': {   'server': {   'cli': 'Set-ExecutionPolicy RemoteSigned -Scope '
                                                                    'LocalMachine -Force',
                                                             'gui': [   "Open 'gpedit.msc' > Computer Configuration > "
                                                                        'Administrative Templates > Windows Components '
                                                                        '> Windows PowerShell.',
                                                                        "Double-click 'Turn on Script Execution', set "
                                                                        "to Enabled, and choose 'Allow only signed "
                                                                        "scripts' or 'Allow local scripts and remote "
                                                                        "signed scripts'.",
                                                                        "Click OK and run 'gpupdate /force'."],
                                                             'label': 'Windows Server'},
                                               'win10': {   'cli': 'Set-ExecutionPolicy RemoteSigned -Scope '
                                                                   'LocalMachine -Force',
                                                            'gui': [   "Click Start, type 'PowerShell', right-click "
                                                                       "'Windows PowerShell' and select 'Run as "
                                                                       "Administrator'.",
                                                                       'Execute: Set-ExecutionPolicy RemoteSigned '
                                                                       '-Scope LocalMachine -Force',
                                                                       'Confirm the prompt.'],
                                                            'label': 'Windows 10'},
                                               'win11': {   'cli': 'Set-ExecutionPolicy RemoteSigned -Scope '
                                                                   'LocalMachine -Force',
                                                            'gui': [   'Right-click the Start button and choose '
                                                                       "'Terminal (Admin)' or 'PowerShell (Admin)'.",
                                                                       'Execute: Set-ExecutionPolicy RemoteSigned '
                                                                       '-Scope LocalMachine -Force',
                                                                       "Type 'Y' if prompted for confirmation."],
                                                            'label': 'Windows 11'}},
                                   'verify': "Run 'Get-ExecutionPolicy -List' in PowerShell. Confirm 'LocalMachine' is "
                                             "set to 'RemoteSigned' or 'Restricted'."},
    'rdp_enabled': {   'caution': 'Disabling RDP immediately drops active remote sessions. Only execute if you have '
                                  'physical or out-of-band console access. If RDP is needed, place it behind a VPN and '
                                  'require NLA.',
                       'summary': 'Close or restrict exposed Remote Desktop Protocol (port 3389) to prevent automated '
                                  'brute-force and credential stuffing attacks.',
                       'tabs': {   'server': {   'cli': 'Set-ItemProperty -Path '
                                                        "'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' "
                                                        "-Name 'fDenyTSConnections' -Value 1; Disable-NetFirewallRule "
                                                        "-DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue",
                                                 'gui': [   'Open Server Manager > Local Server.',
                                                            "Click 'Enabled' next to Remote Desktop to open System "
                                                            'Properties.',
                                                            "Select 'Don't allow remote connections to this computer' "
                                                            "and click OK (or run 'sconfig' and choose Option 7 > D)."],
                                                 'label': 'Windows Server'},
                                   'win10': {   'cli': 'Set-ItemProperty -Path '
                                                       "'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' "
                                                       "-Name 'fDenyTSConnections' -Value 1; Disable-NetFirewallRule "
                                                       "-DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue",
                                                'gui': [   'Open Settings (Win + I) and select System > Remote '
                                                           'Desktop.',
                                                           "Toggle 'Enable Remote Desktop' to OFF.",
                                                           'Click Confirm in the confirmation dialog.'],
                                                'label': 'Windows 10'},
                                   'win11': {   'cli': 'Set-ItemProperty -Path '
                                                       "'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' "
                                                       "-Name 'fDenyTSConnections' -Value 1; Disable-NetFirewallRule "
                                                       "-DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue",
                                                'gui': [   'Open Settings (Win + I) and select System > Remote '
                                                           'Desktop.',
                                                           "Toggle the 'Remote Desktop' switch to OFF.",
                                                           'Click Confirm when asked to disable Remote Desktop.'],
                                                'label': 'Windows 11'}},
                       'verify': "Run 'Test-NetConnection -ComputerName 127.0.0.1 -Port 3389' in PowerShell. "
                                 "'TcpTestSucceeded' must be False."},
    'rdp_open': {   'caution': 'Disabling RDP immediately drops active remote sessions. Only execute if you have '
                               'physical or out-of-band console access. If RDP is needed, place it behind a VPN and '
                               'require NLA.',
                    'summary': 'Close or restrict exposed Remote Desktop Protocol (port 3389) to prevent automated '
                               'brute-force and credential stuffing attacks.',
                    'tabs': {   'server': {   'cli': 'Set-ItemProperty -Path '
                                                     "'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' "
                                                     "-Name 'fDenyTSConnections' -Value 1; Disable-NetFirewallRule "
                                                     "-DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue",
                                              'gui': [   'Open Server Manager > Local Server.',
                                                         "Click 'Enabled' next to Remote Desktop to open System "
                                                         'Properties.',
                                                         "Select 'Don't allow remote connections to this computer' and "
                                                         "click OK (or run 'sconfig' and choose Option 7 > D)."],
                                              'label': 'Windows Server'},
                                'win10': {   'cli': 'Set-ItemProperty -Path '
                                                    "'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' "
                                                    "-Name 'fDenyTSConnections' -Value 1; Disable-NetFirewallRule "
                                                    "-DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue",
                                             'gui': [   'Open Settings (Win + I) and select System > Remote Desktop.',
                                                        "Toggle 'Enable Remote Desktop' to OFF.",
                                                        'Click Confirm in the confirmation dialog.'],
                                             'label': 'Windows 10'},
                                'win11': {   'cli': 'Set-ItemProperty -Path '
                                                    "'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' "
                                                    "-Name 'fDenyTSConnections' -Value 1; Disable-NetFirewallRule "
                                                    "-DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue",
                                             'gui': [   'Open Settings (Win + I) and select System > Remote Desktop.',
                                                        "Toggle the 'Remote Desktop' switch to OFF.",
                                                        'Click Confirm when asked to disable Remote Desktop.'],
                                             'label': 'Windows 11'}},
                    'verify': "Run 'Test-NetConnection -ComputerName 127.0.0.1 -Port 3389' in PowerShell. "
                              "'TcpTestSucceeded' must be False."},
    'smb_v1_enabled': {   'caution': 'Legacy network copiers or ancient NAS devices from before 2010 may require '
                                     'firmware upgrades to support modern SMBv2 or SMBv3.',
                          'summary': 'Disable SMBv1 network file sharing protocol to block remote code execution '
                                     'vulnerabilities like EternalBlue/WannaCry.',
                          'tabs': {   'server': {   'cli': 'Remove-WindowsFeature FS-SMB1; Set-SmbServerConfiguration '
                                                           '-EnableSMB1Protocol $false -Force',
                                                    'gui': [   'Open Server Manager > Manage > Remove Roles and '
                                                               'Features.',
                                                               "Click Next until reaching the 'Features' screen.",
                                                               "Expand 'SMB 1.0/CIFS File Sharing Support' and uncheck "
                                                               'it.',
                                                               'Click Next and then Remove. Restart the server during '
                                                               'an approved maintenance window.'],
                                                    'label': 'Windows Server'},
                                      'win10': {   'cli': 'Disable-WindowsOptionalFeature -Online -FeatureName '
                                                          'SMB1Protocol -NoRestart',
                                                   'gui': [   "Press Win + R, type 'optionalfeatures.exe' and press "
                                                              'Enter.',
                                                              "Scroll down to locate 'SMB 1.0/CIFS File Sharing "
                                                              "Support'.",
                                                              "Uncheck 'SMB 1.0/CIFS File Sharing Support' (including "
                                                              'client and server sub-items).',
                                                              'Click OK and restart the computer when prompted.'],
                                                   'label': 'Windows 10'},
                                      'win11': {   'cli': 'Disable-WindowsOptionalFeature -Online -FeatureName '
                                                          'SMB1Protocol -NoRestart',
                                                   'gui': [   'Open Settings (Win + I) and navigate to Apps > Optional '
                                                              'features.',
                                                              "Scroll to the bottom and click 'More Windows features'.",
                                                              "In the Windows Features dialog, locate 'SMB 1.0/CIFS "
                                                              "File Sharing Support' and uncheck the entire box.",
                                                              'Click OK, wait for Windows to remove the feature files, '
                                                              "and click 'Restart now' when prompted."],
                                                   'label': 'Windows 11'}},
                          'verify': "Run '(Get-SmbServerConfiguration).EnableSMB1Protocol' in elevated PowerShell. It "
                                    "must return 'False'."},
    'tamper_protection_off': {   'caution': 'On managed domain or Entra-joined machines, local UI changes may be '
                                            'overridden by central Group Policy or Intune profiles.',
                                 'summary': 'Turn on Defender Tamper Protection to prevent ransomware and malware from '
                                            'manipulating registry keys or stopping antivirus services.',
                                 'tabs': {   'server': {   'cli': 'Set-MpPreference -DisableTamperProtection $false '
                                                                  '-ErrorAction SilentlyContinue',
                                                           'gui': [   'On Windows Server 2019/2022/2025, Tamper '
                                                                      'Protection is managed centrally through '
                                                                      'Microsoft Defender for Endpoint / Intune '
                                                                      'Security Center.',
                                                                      'On standalone servers, enable it via elevated '
                                                                      'PowerShell using the command below.'],
                                                           'label': 'Windows Server'},
                                             'win10': {   'cli': 'Set-MpPreference -DisableTamperProtection $false '
                                                                 '-ErrorAction SilentlyContinue',
                                                          'gui': [   'Open Settings (Win + I) > Update & Security > '
                                                                     'Windows Security > Virus & threat protection.',
                                                                     "Click 'Manage settings' under Virus & threat "
                                                                     'protection settings.',
                                                                     "Toggle 'Tamper Protection' to ON."],
                                                          'label': 'Windows 10'},
                                             'win11': {   'cli': 'Set-MpPreference -DisableTamperProtection $false '
                                                                 '-ErrorAction SilentlyContinue',
                                                          'gui': [   'Open Settings (Win + I) > Privacy & security > '
                                                                     'Windows Security > Virus & threat protection.',
                                                                     "Under 'Virus & threat protection settings', "
                                                                     "click 'Manage settings'.",
                                                                     "Scroll down to 'Tamper Protection' and toggle it "
                                                                     'to ON.'],
                                                          'label': 'Windows 11'}},
                                 'verify': "Run '(Get-MpComputerStatus).IsTamperProtected' in PowerShell. It should "
                                           "return 'True'."},
    'uac_disabled': {   'caution': 'A system restart is required for User Account Control to take full effect across '
                                   'all processes.',
                        'summary': 'Enable User Account Control (UAC) to stop malicious processes from silently '
                                   'escalating to SYSTEM privileges without administrator consent.',
                        'tabs': {   'server': {   'cli': 'Set-ItemProperty -Path '
                                                         "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
                                                         "-Name 'EnableLUA' -Value 1 -Type DWord",
                                                  'gui': [   "Open 'secpol.msc' > Local Policies > Security Options.",
                                                             "Locate 'User Account Control: Run all administrators in "
                                                             "Admin Approval Mode'.",
                                                             'Set it to Enabled, click OK, and schedule a system '
                                                             'reboot.'],
                                                  'label': 'Windows Server'},
                                    'win10': {   'cli': 'Set-ItemProperty -Path '
                                                        "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
                                                        "-Name 'EnableLUA' -Value 1 -Type DWord",
                                                 'gui': [   "Press Win + R, type 'UserAccountControlSettings.exe' and "
                                                            'press Enter.',
                                                            'Move the slider up to the recommended level (second from '
                                                            'top) or top level.',
                                                            'Click OK and restart the system when prompted.'],
                                                 'label': 'Windows 10'},
                                    'win11': {   'cli': 'Set-ItemProperty -Path '
                                                        "'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
                                                        "-Name 'EnableLUA' -Value 1 -Type DWord",
                                                 'gui': [   "Press Win + R, type 'UserAccountControlSettings.exe' and "
                                                            'press Enter.',
                                                            "Move the slider to the default position ('Notify me only "
                                                            "when apps try to make changes') or to the top ('Always "
                                                            "notify').",
                                                            'Click OK, confirm the UAC prompt, and restart the '
                                                            'computer.'],
                                                 'label': 'Windows 11'}},
                        'verify': "Run 'Get-ItemPropertyValue -Path "
                                  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name '
                                  "EnableLUA'. It must return '1'."},
    'vss_deleted': {   'caution': 'Previously deleted shadow copies cannot be restored by turning the service back on; '
                                  'this creates new recovery points going forward. Pair with offline backups.',
                       'summary': 'Enable System Protection and Volume Shadow Copies to guarantee rapid local snapshot '
                                  'rollbacks after ransomware attacks.',
                       'tabs': {   'server': {   'cli': 'vssadmin create shadow /for=C:',
                                                 'gui': [   'Open File Explorer, right-click the volume (C:) and '
                                                            "choose 'Configure Shadow Copies...'.",
                                                            "Select the volume, click 'Settings' to allocate storage, "
                                                            "then click 'Enable'.",
                                                            "Click 'Create Now' to establish an immediate "
                                                            'point-in-time snapshot.'],
                                                 'label': 'Windows Server'},
                                   'win10': {   'cli': "Enable-ComputerRestore -Drive 'C:\\'; Checkpoint-Computer "
                                                       "-Description 'R3P_Baseline_RestorePoint' -RestorePointType "
                                                       "'MODIFY_SETTINGS'",
                                                'gui': [   "Press Win + R, type 'systempropertiesprotection.exe' and "
                                                           'press Enter.',
                                                           "Select drive C: > Configure > Select 'Turn on system "
                                                           "protection' > Allocate 5-10% disk space > OK.",
                                                           "Click 'Create' to generate an immediate initial restore "
                                                           'point.'],
                                                'label': 'Windows 10'},
                                   'win11': {   'cli': "Enable-ComputerRestore -Drive 'C:\\'; Checkpoint-Computer "
                                                       "-Description 'R3P_Baseline_RestorePoint' -RestorePointType "
                                                       "'MODIFY_SETTINGS'",
                                                'gui': [   "Press Win + R, type 'sysdm.cpl' and press Enter.",
                                                           "Select the 'System Protection' tab, select your system "
                                                           "drive (C:), and click 'Configure'.",
                                                           "Choose 'Turn on system protection', adjust Max Usage to "
                                                           '5-10% of disk space, and click OK.',
                                                           "Click 'Create...' and name the new restore point (e.g. "
                                                           "'R3P_Secure_Baseline')."],
                                                'label': 'Windows 11'}},
                       'verify': "Run 'vssadmin list shadows' in elevated CMD/PowerShell. Confirm active shadow copies "
                                 'are listed for volume C:.'},
    'vulnerable_driver_blocklist_enabled': {   'caution': 'Requires a system reboot. Blocks known vulnerable '
                                                          'third-party hardware drivers that have been weaponized by '
                                                          'ransomware syndicates.',
                                               'summary': 'Enable Microsoft Vulnerable Driver Blocklist to neutralize '
                                                          'BYOVD (Bring Your Own Vulnerable Driver) attacks that '
                                                          'terminate EDR defenses.',
                                               'tabs': {   'server': {   'cli': 'Set-ItemProperty -Path '
                                                                                "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config' "
                                                                                '-Name '
                                                                                "'VulnerableDriverBlocklistEnable' "
                                                                                '-Value 1 -Type DWord',
                                                                         'gui': [   'On Windows Server 2022/2025, '
                                                                                    'enable via elevated PowerShell '
                                                                                    'command below.',
                                                                                    'Alternatively, deploy a custom '
                                                                                    'Windows Defender Application '
                                                                                    'Control (WDAC) policy containing '
                                                                                    "Microsoft's driver blocklist.",
                                                                                    'Restart the server.'],
                                                                         'label': 'Windows Server'},
                                                           'win10': {   'cli': 'Set-ItemProperty -Path '
                                                                               "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config' "
                                                                               '-Name '
                                                                               "'VulnerableDriverBlocklistEnable' "
                                                                               '-Value 1 -Type DWord',
                                                                        'gui': [   'Ensure Windows 10 is updated with '
                                                                                   'KB5018410 or newer.',
                                                                                   'Open elevated PowerShell and run '
                                                                                   'the CLI fix command below to '
                                                                                   'enable blocklist enforcement.',
                                                                                   'Restart the computer.'],
                                                                        'label': 'Windows 10'},
                                                           'win11': {   'cli': 'Set-ItemProperty -Path '
                                                                               "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config' "
                                                                               '-Name '
                                                                               "'VulnerableDriverBlocklistEnable' "
                                                                               '-Value 1 -Type DWord',
                                                                        'gui': [   'Open Settings (Win + I) > Privacy '
                                                                                   '& security > Windows Security > '
                                                                                   'Device security.',
                                                                                   "Click 'Core isolation details'.",
                                                                                   "Locate 'Microsoft Vulnerable "
                                                                                   "Driver Blocklist' and toggle it to "
                                                                                   'ON.',
                                                                                   'Restart the computer when '
                                                                                   'prompted.'],
                                                                        'label': 'Windows 11'}},
                                               'verify': "Run 'Get-ItemPropertyValue -Path "
                                                         'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config -Name '
                                                         "VulnerableDriverBlocklistEnable'. It must return '1'."},
    'wdigest_enabled': {   'caution': 'Currently logged-in users must sign out and sign back in to purge existing '
                                      'plaintext credentials from LSASS memory.',
                           'summary': 'Disable WDigest cleartext credential caching to prevent attackers from reading '
                                      'plaintext passwords out of memory.',
                           'tabs': {   'server': {   'cli': 'Set-ItemProperty -Path '
                                                            "'HKLM:\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' "
                                                            "-Name 'UseLogonCredential' -Value 0 -Type DWord",
                                                     'gui': [   "Open 'gpedit.msc' or Domain Group Policy.",
                                                                'Navigate to Computer Configuration > Administrative '
                                                                'Templates > System > Credentials Delegation.',
                                                                'Or apply the registry setting directly using the CLI '
                                                                'command below.'],
                                                     'label': 'Windows Server'},
                                       'win10': {   'cli': 'Set-ItemProperty -Path '
                                                           "'HKLM:\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' "
                                                           "-Name 'UseLogonCredential' -Value 0 -Type DWord",
                                                    'gui': [   "Press Win + R, type 'regedit' and press Enter.",
                                                               'Navigate to: '
                                                               'HKLM\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest.',
                                                               "Set DWORD 'UseLogonCredential' to 0.",
                                                               'Click OK.'],
                                                    'label': 'Windows 10'},
                                       'win11': {   'cli': 'Set-ItemProperty -Path '
                                                           "'HKLM:\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' "
                                                           "-Name 'UseLogonCredential' -Value 0 -Type DWord",
                                                    'gui': [   "Press Win + R, type 'regedit' and press Enter.",
                                                               'Navigate to: '
                                                               'HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest.',
                                                               "Double-click 'UseLogonCredential' and set its value to "
                                                               "'0' (or delete the DWORD).",
                                                               'Click OK.'],
                                                    'label': 'Windows 11'}},
                           'verify': "Run 'Get-ItemPropertyValue -Path "
                                     'HKLM:\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest -Name '
                                     "UseLogonCredential'. It must return '0'."}}

# Backend parameter aliases
MANUAL_FIX_GUIDES.update({
    'rdp_enabled': MANUAL_FIX_GUIDES['rdp_open'],
    'backup_absent': MANUAL_FIX_GUIDES['backup_configured'],
    'firewall_disabled': MANUAL_FIX_GUIDES['firewall_on'],
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
        """Show safe manual guidance with interactive Windows version tabs; opening this guide never applies a fix."""
        title, description = ABOUT_INFO.get(
            param_key,
            (param_key.replace("_", " ").title(),
             "This finding needs review against the effective Windows and organization policy."),
        )
        guide_data = MANUAL_FIX_GUIDES.get(param_key)

        # Normalize guide data across both dict and legacy tuple shapes
        if isinstance(guide_data, dict):
            summary = guide_data.get("summary", description)
            tabs = guide_data.get("tabs", {})
            verify = guide_data.get("verify", "Confirm the effective setting in Windows or the management console, then run a fresh R3P scan.")
            caution = guide_data.get("caution", "Requires administrator rights.")
        elif isinstance(guide_data, (tuple, list)):
            steps, verify, caution = guide_data
            summary = description
            tabs = {
                "win11": {"label": "Windows 11", "gui": steps, "cli": ""},
                "win10": {"label": "Windows 10", "gui": steps, "cli": ""},
                "server": {"label": "Windows Server", "gui": steps, "cli": ""},
            }
        else:
            summary = description
            tabs = {
                "win11": {"label": "Windows 11", "gui": ["Review the setting with your Windows or security administrator."], "cli": ""},
                "win10": {"label": "Windows 10", "gui": ["Review the setting with your Windows or security administrator."], "cli": ""},
                "server": {"label": "Windows Server", "gui": ["Review the setting with your Windows or security administrator."], "cli": ""},
            }
            verify = "Confirm the effective setting in Windows or the management console, then run a fresh R3P scan."
            caution = "The parameter mapping may vary by Windows edition or organization policy."

        cmd_key = PARAM_TO_CMD_KEY.get(param_key)
        has_fix = cmd_key in AGENT_REMEDIATION

        dialog = tk.Toplevel(self)
        dialog.title(f"How to fix — {title}")
        dialog.configure(bg=COLORS["bg"])
        dialog.geometry("640x700")
        dialog.minsize(540, 500)
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

        # Title
        title_label = tk.Label(body, text=title, font=("Segoe UI", 16, "bold"), bg=COLORS["bg"], fg=COLORS["text"], wraplength=520, justify="left", anchor="w")
        title_label.pack(anchor="w")
        wrap_targets.append(title_label)

        # Summary
        summary_label = tk.Label(body, text=summary, font=("Segoe UI", 10), bg=COLORS["bg"], fg=COLORS["subtle"], wraplength=520, justify="left", anchor="w")
        summary_label.pack(anchor="w", pady=(6, 12))
        wrap_targets.append(summary_label)

        # Before you start box
        before_frame = tk.Frame(body, bg=COLORS["card"], padx=12, pady=10, highlightthickness=1, highlightbackground=COLORS["border"])
        before_frame.pack(fill="x", pady=(0, 14))
        tk.Label(before_frame, text="BEFORE YOU START", font=("Segoe UI", 8, "bold"), bg=COLORS["card"], fg=COLORS["info"]).pack(anchor="w")
        before_lbl = tk.Label(
            before_frame,
            text="Confirm this is the correct endpoint and check whether its settings come from Intune, Group Policy, or another central manager. Apply one change at a time, retain an alternate management path, and run a fresh R3P scan to verify.",
            font=("Segoe UI", 9),
            bg=COLORS["card"],
            fg=COLORS["text"],
            wraplength=500,
            justify="left",
            anchor="w"
        )
        before_lbl.pack(anchor="w", pady=(3, 0), fill="x")
        wrap_targets.append(before_lbl)

        # OS Version Selector
        tk.Label(body, text="SELECT WINDOWS VERSION:", font=("Segoe UI", 8, "bold"), bg=COLORS["bg"], fg=COLORS["subtle"]).pack(anchor="w", pady=(0, 6))
        tabs_frame = tk.Frame(body, bg=COLORS["bg"])
        tabs_frame.pack(fill="x", pady=(0, 10))

        tab_buttons = {}
        content_frame = tk.Frame(body, bg=COLORS["bg"])
        content_frame.pack(fill="x")

        def render_os_content(selected_os):
            # Update tab buttons appearance
            for os_k, btn in tab_buttons.items():
                if os_k == selected_os:
                    btn.configure(bg=COLORS["accent"], fg="#ffffff")
                else:
                    btn.configure(bg=COLORS["card2"], fg=COLORS["subtle"])

            # Clean out previous tab widgets
            for child in content_frame.winfo_children():
                child.destroy()

            os_info = tabs.get(selected_os, {})
            gui_steps = os_info.get("gui", [])
            cli_cmd = os_info.get("cli", "")

            # GUI Walkthrough header
            tk.Label(
                content_frame,
                text=f"GUI STEP-BY-STEP ({os_info.get('label', selected_os).upper()}):",
                font=("Segoe UI", 8, "bold"),
                bg=COLORS["bg"],
                fg=COLORS["info"],
            ).pack(anchor="w", pady=(4, 6))

            # Step items
            for idx, instruction in enumerate(gui_steps, start=1):
                step_row = tk.Frame(content_frame, bg=COLORS["card"], padx=10, pady=8, highlightthickness=1, highlightbackground=COLORS["border"])
                step_row.pack(fill="x", pady=2)
                tk.Label(
                    step_row,
                    text=f"{idx:02d}",
                    font=("Segoe UI", 9, "bold"),
                    bg=COLORS["card"],
                    fg=COLORS["accent"],
                    anchor="n",
                ).pack(side="left", padx=(0, 10))
                s_lbl = tk.Label(
                    step_row,
                    text=instruction,
                    font=("Segoe UI", 9),
                    bg=COLORS["card"],
                    fg=COLORS["text"],
                    wraplength=460,
                    justify="left",
                    anchor="w",
                )
                s_lbl.pack(side="left", fill="x", expand=True)
                wrap_targets.append(s_lbl)

            # Quick CLI Box
            if cli_cmd:
                cli_hdr_row = tk.Frame(content_frame, bg=COLORS["bg"])
                cli_hdr_row.pack(fill="x", pady=(12, 4))
                tk.Label(
                    cli_hdr_row,
                    text="QUICK POWERSHELL FIX (RUN AS ADMIN):",
                    font=("Segoe UI", 8, "bold"),
                    bg=COLORS["bg"],
                    fg=COLORS["safe"],
                ).pack(side="left")

                copy_status_lbl = tk.Label(cli_hdr_row, text="", font=("Segoe UI", 8, "bold"), bg=COLORS["bg"], fg=COLORS["safe"])
                copy_status_lbl.pack(side="right", padx=(0, 6))

                def copy_cli():
                    try:
                        dialog.clipboard_clear()
                        dialog.clipboard_append(cli_cmd)
                        copy_status_lbl.config(text="✓ Copied to clipboard!")
                        dialog.after(2000, lambda: copy_status_lbl.config(text=""))
                    except Exception:
                        copy_status_lbl.config(text="Copy failed")

                copy_btn = agent_button(
                    cli_hdr_row,
                    text="📋 Copy Command",
                    font=("Segoe UI", 8, "bold"),
                    bg=COLORS["card2"],
                    fg=COLORS["text"],
                    activebackground=COLORS["border"],
                    padx=10,
                    pady=2,
                    relief="flat",
                    cursor="hand2",
                    command=copy_cli
                )
                copy_btn.pack(side="right")

                term_box = tk.Frame(content_frame, bg="#090d16", padx=10, pady=8, highlightthickness=1, highlightbackground="#1f293d")
                term_box.pack(fill="x", pady=(2, 6))
                cli_lbl = tk.Label(
                    term_box,
                    text=f"PS C:\\\\> {cli_cmd}",
                    font=("Consolas", 8, "bold"),
                    bg="#090d16",
                    fg="#30d158",
                    wraplength=470,
                    justify="left",
                    anchor="w",
                )
                cli_lbl.pack(fill="x")
                wrap_targets.append(cli_lbl)

        # Tab buttons
        for os_key, os_data in tabs.items():
            btn = agent_button(
                tabs_frame,
                text=os_data.get("label", os_key),
                font=("Segoe UI", 9, "bold"),
                bg=COLORS["card2"],
                fg=COLORS["subtle"],
                activebackground=COLORS["accent"],
                activeforeground="#ffffff",
                padx=14,
                pady=6,
                relief="flat",
                cursor="hand2",
                command=lambda k=os_key: render_os_content(k)
            )
            btn.pack(side="left", padx=(0, 8))
            tab_buttons[os_key] = btn

        # Render default tab
        initial_os = "win11" if "win11" in tabs else list(tabs.keys())[0]
        render_os_content(initial_os)

        # Verification & Caution Cards
        bottom_frame = tk.Frame(body, bg=COLORS["bg"])
        bottom_frame.pack(fill="x", pady=(14, 0))

        v_card = tk.Frame(bottom_frame, bg=COLORS["card"], padx=12, pady=10, highlightthickness=1, highlightbackground=COLORS["safe"])
        v_card.pack(fill="x", pady=4)
        tk.Label(v_card, text="✓ HOW TO VERIFY", font=("Segoe UI", 8, "bold"), bg=COLORS["card"], fg=COLORS["safe"]).pack(anchor="w")
        v_lbl = tk.Label(v_card, text=verify, font=("Segoe UI", 9), bg=COLORS["card"], fg=COLORS["text"], wraplength=490, justify="left", anchor="w")
        v_lbl.pack(anchor="w", pady=(3, 0), fill="x")
        wrap_targets.append(v_lbl)

        c_card = tk.Frame(bottom_frame, bg=COLORS["card"], padx=12, pady=10, highlightthickness=1, highlightbackground=COLORS["warning"])
        c_card.pack(fill="x", pady=4)
        tk.Label(c_card, text="⚠ IMPORTANT CAUTION & NOTES", font=("Segoe UI", 8, "bold"), bg=COLORS["card"], fg=COLORS["warning"]).pack(anchor="w")
        c_lbl = tk.Label(c_card, text=caution, font=("Segoe UI", 9), bg=COLORS["card"], fg=COLORS["text"], wraplength=490, justify="left", anchor="w")
        c_lbl.pack(anchor="w", pady=(3, 0), fill="x")
        wrap_targets.append(c_lbl)

        if has_fix:
            auto_lbl = tk.Label(bottom_frame, text="⚡ R3P Automated Option: An allowlisted 'Apply fix' action is available for this parameter. It runs a predefined local command only after explicit confirmation.", font=("Segoe UI", 8), bg=COLORS["bg"], fg=COLORS["accent"], wraplength=510, justify="left")
            auto_lbl.pack(anchor="w", pady=(8, 0))
            wrap_targets.append(auto_lbl)

        agent_button(bottom_frame, text="Close", font=("Segoe UI", 9, "bold"), bg=COLORS["card2"], fg=COLORS["text"], activebackground=COLORS["border"], padx=18, pady=7, cursor="hand2", command=dialog.destroy).pack(anchor="e", pady=(14, 0))

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
