// ── API config ────────────────────────────────────────────────────────────────
export const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

// Add ngrok bypass header for all fetch requests (no-op when not using ngrok)
export const FETCH_HEADERS = { 'ngrok-skip-browser-warning': 'true' }

export const SEVERITY_COLOR = {
  CRITICAL: 'sev-critical',
  HIGH: 'sev-high',
  MEDIUM: 'sev-medium',
  LOW: 'sev-low',
}

export const RISK_CLASS_COLOR = {
  'CRITICAL': 'risk-critical',
  'HIGH RISK': 'risk-high',
  'LOW RISK': 'risk-low',
  'SAFE': 'risk-safe',
}

export const PARAM_LABELS = {
  rdp_enabled: 'RDP Port 3389 Open',
  smb_v1_enabled: 'SMBv1 Protocol Enabled',
  autorun_enabled: 'USB AutoRun Enabled',
  open_network_shares: 'Open Network Shares',
  macro_execution_enabled: 'Office Macros Enabled',
  powershell_unrestricted: 'PowerShell Unrestricted',
  uac_disabled: 'UAC Disabled',
  applocker_absent: 'No AppLocker Policy',
  defender_disabled: 'Windows Defender Off',
  firewall_disabled: 'Windows Firewall Disabled',
  tamper_protection_off: 'Tamper Protection Off',
  event_logging_disabled: 'Event Logging Disabled',
  admin_shares_enabled: 'Admin Shares (C$, ADMIN$) Active',
  lsass_protection_off: 'LSASS Not Protected (PPL Off)',
  guest_account_active: 'Guest Account Enabled',
  vss_deleted: 'No Volume Shadow Copies',
  backup_absent: 'Backup Not Configured',
  bitlocker_off: 'BitLocker Encryption Off',
  wdigest_enabled: 'WDigest Credentials Enabled',
  laps_absent: 'LAPS Not Installed',
  nla_disabled: 'NLA Disabled for RDP',
  always_install_elevated: 'AlwaysInstallElevated Policy Active',
  vulnerable_driver_blocklist_enabled: 'Vulnerable Driver Blocklist Disabled (BYOVD Risk)',
  hvci_enabled: 'HVCI Memory Integrity Disabled',
  asr_rules_configured: 'ASR Rules Not Configured',
  mock_attack_vss_enum_succeeded: 'Mock Attack: VSS Enumeration Succeeded',
  mock_attack_mass_rename_succeeded: 'Mock Attack: Mass Rename Succeeded',
}

export const PARAM_SEVERITY = {
  smb_v1_enabled: 'CRITICAL', lsass_protection_off: 'CRITICAL',
  vss_deleted: 'CRITICAL', backup_absent: 'CRITICAL', bitlocker_off: 'CRITICAL',
  rdp_enabled: 'HIGH', macro_execution_enabled: 'HIGH',
  powershell_unrestricted: 'HIGH', defender_disabled: 'HIGH', firewall_disabled: 'HIGH',
  uac_disabled: 'MEDIUM', tamper_protection_off: 'MEDIUM',
  event_logging_disabled: 'MEDIUM', admin_shares_enabled: 'MEDIUM',
  open_network_shares: 'MEDIUM', guest_account_active: 'MEDIUM',
  autorun_enabled: 'LOW', applocker_absent: 'LOW', laps_absent: 'MEDIUM',
  nla_disabled: 'HIGH', wdigest_enabled: 'CRITICAL', always_install_elevated: 'CRITICAL',
  vulnerable_driver_blocklist_enabled: 'CRITICAL', hvci_enabled: 'HIGH', asr_rules_configured: 'HIGH',
  mock_attack_vss_enum_succeeded: 'CRITICAL', mock_attack_mass_rename_succeeded: 'CRITICAL'
}

// Numeric scoring weights mirrored from backend/scoring.py for the About view.
export const SCORING_SEVERITY = {
  smb_v1_enabled: 5, rdp_enabled: 4, autorun_enabled: 2, open_network_shares: 3,
  macro_execution_enabled: 4, powershell_unrestricted: 4, uac_disabled: 3, applocker_absent: 2,
  defender_disabled: 4, firewall_disabled: 4, tamper_protection_off: 3, event_logging_disabled: 2,
  admin_shares_enabled: 3, lsass_protection_off: 5, guest_account_active: 2,
  vss_deleted: 5, backup_absent: 5, bitlocker_off: 5, nla_disabled: 4,
  always_install_elevated: 5, wdigest_enabled: 5, laps_absent: 3,
  vulnerable_driver_blocklist_enabled: 5, hvci_enabled: 4, asr_rules_configured: 4,
  mock_attack_vss_enum_succeeded: 5, mock_attack_mass_rename_succeeded: 5,
}

export const SCORING_LIKELIHOOD = {
  smb_v1_enabled: 0.4, rdp_enabled: 0.9, autorun_enabled: 0.3, open_network_shares: 0.7,
  macro_execution_enabled: 0.8, powershell_unrestricted: 1.0, uac_disabled: 0.6, applocker_absent: 0.5,
  defender_disabled: 0.9, firewall_disabled: 0.6, tamper_protection_off: 0.8, event_logging_disabled: 0.7,
  admin_shares_enabled: 0.8, lsass_protection_off: 0.9, guest_account_active: 0.4,
  vss_deleted: 1.0, backup_absent: 0.8, bitlocker_off: 0.5, nla_disabled: 0.8,
  always_install_elevated: 0.6, wdigest_enabled: 0.7, laps_absent: 0.8,
  vulnerable_driver_blocklist_enabled: 0.9, hvci_enabled: 0.8, asr_rules_configured: 0.8,
  mock_attack_vss_enum_succeeded: 1.0, mock_attack_mass_rename_succeeded: 1.0,
}

export const PARAM_DESCRIPTIONS = {
  smb_v1_enabled: 'SMBv1 is the WannaCry/NotPetya exploit vector. Disable immediately.',
  lsass_protection_off: 'Mimikatz can dump plaintext passwords from LSASS memory.',
  vss_deleted: 'No shadow copies = no local recovery after ransomware.',
  backup_absent: 'Backup service is not running — data loss risk.',
  bitlocker_off: 'Drive is unencrypted. Stolen drives expose all data.',
  rdp_enabled: 'Open RDP port exposes the machine to brute-force attacks.',
  macro_execution_enabled: 'Office macros run without prompt — common malware loader.',
  powershell_unrestricted: 'Any script can run. Attackers love unrestricted PowerShell.',
  defender_disabled: 'Real-time AV is off — malware can run without detection.',
  firewall_disabled: 'All ports exposed to the network with no filtering.',
  uac_disabled: 'Malware can silently elevate to SYSTEM without UAC prompt.',
  tamper_protection_off: 'Defender settings can be changed by malware.',
  event_logging_disabled: 'No logs = blind to attacks. Incident response impossible.',
  admin_shares_enabled: 'C$ and ADMIN$ shares allow network-wide lateral movement.',
  open_network_shares: 'Shares accessible to Everyone — ransomware spreads via shares.',
  guest_account_active: 'Unauthenticated access to the machine.',
  autorun_enabled: 'Malicious USB drives auto-execute on insert.',
  applocker_absent: 'Any executable can run — no application whitelisting.',
  wdigest_enabled: 'WDigest stores passwords in clear text in LSASS memory.',
  laps_absent: 'Without LAPS, local admin passwords can be used for Pass-the-Hash.',
  nla_disabled: 'RDP is exposed to pre-authentication and DoS attacks.',
  always_install_elevated: 'Standard users can install malicious MSI packages as SYSTEM.',
  vulnerable_driver_blocklist_enabled: 'Attackers can load signed vulnerable drivers to kill EDR (BYOVD).',
  hvci_enabled: 'HVCI ensures kernel-mode integrity; disabling it allows kernel exploits.',
  asr_rules_configured: 'ASR rules prevent common malware techniques used in Office and scripts.',
  mock_attack_vss_enum_succeeded: 'Active Validation Failed: System allowed a simulated ransomware backup deletion attempt.',
  mock_attack_mass_rename_succeeded: 'Active Validation Failed: System allowed a rapid mass file rename operation (Ransomware Behavior).',
}

export const PARAM_EXTENDED_INFO = {
  smb_v1_enabled: "Server Message Block version 1 (SMBv1) is an outdated, highly vulnerable network file sharing protocol. It lacks encryption and is susceptible to remote code execution (RCE) attacks. The infamous WannaCry and NotPetya ransomware strains used the EternalBlue exploit against SMBv1 to propagate automatically across corporate networks. Disabling SMBv1 is a critical first step in ransomware defense, as modern environments should strictly rely on SMBv2 or SMBv3 for secure file sharing.",
  lsass_protection_off: "The Local Security Authority Subsystem Service (LSASS) is responsible for enforcing security policy on Windows systems and handling user logins. When unprotected, attackers can use tools like Mimikatz to dump plaintext passwords, Kerberos tickets, and NTLM hashes directly from memory. Enabling Protected Process Light (PPL) for LSASS ensures that only digitally signed processes can interact with it, effectively neutralizing memory credential dumping techniques used for lateral movement.",
  vss_deleted: "Volume Shadow Copy Service (VSS) provides point-in-time snapshots of data on a volume. Ransomware operators almost universally attempt to delete or disable these shadow copies using commands like 'vssadmin.exe Delete Shadows /All /Quiet' before encrypting the live files. If VSS is disabled or deleted, the organization loses the ability to perform a quick local rollback, forcing them to rely entirely on off-site backups or pay the ransom.",
  backup_absent: "A robust backup strategy is the ultimate fail-safe against ransomware. Without a configured backup system, organizations have zero resilience if encryption occurs. Attackers specifically target active backup agents to halt them. Ensuring backups are configured, isolated, and immutable is essential so that even if the primary data and shadow copies are wiped, operations can be restored without submitting to extortion.",
  bitlocker_off: "BitLocker provides full disk encryption, ensuring that data at rest cannot be accessed if a physical drive is stolen or the machine is booted from an alternate OS. While ransomware encrypts files while the system is running, lacking BitLocker exposes the endpoint to offline data extraction. Double-extortion ransomware gangs frequently steal sensitive data before encrypting it; full disk encryption adds a critical layer of defense against physical data theft.",
  rdp_enabled: "Remote Desktop Protocol (RDP) on Port 3389 is the single most common entry vector for ransomware operators. Attackers constantly scan the internet for exposed RDP ports to perform brute-force or credential-stuffing attacks. Once inside, they have direct GUI access to the environment. RDP should never be exposed directly to the internet; it must be secured behind a VPN, Remote Desktop Gateway, and require Multi-Factor Authentication (MFA).",
  macro_execution_enabled: "Microsoft Office Macros (VBA) are frequently abused as initial access payloads via phishing emails. When a user opens a malicious document, the macro silently executes and downloads secondary malware payloads like Emotet or Cobalt Strike, which eventually lead to ransomware deployment. Disabling macro execution, or restricting it only to digitally signed macros from trusted locations, drastically reduces the success rate of email-borne malware.",
  powershell_unrestricted: "PowerShell is a powerful administrative framework that is deeply integrated into Windows. Attackers use it for 'living off the land' (LotL) techniques to execute fileless malware, download payloads, and manipulate system configurations without dropping executables that AV might catch. Leaving the execution policy unrestricted allows any script to run. It must be locked down, and PowerShell logging should be enabled to track malicious script execution.",
  defender_disabled: "Windows Defender (or equivalent EDR/AV) provides real-time heuristic and signature-based scanning to detect malware execution. Ransomware affiliates often attempt to disable Defender via registry tweaks or Group Policy before dropping their final payload. If this real-time protection is disabled, the endpoint is completely blind and defenseless against even trivial, known malware strains.",
  firewall_disabled: "The Windows Defender Firewall restricts incoming and outgoing network traffic based on predefined rules. Disabling the firewall exposes all listening ports on the endpoint to the local network, drastically accelerating an attacker's ability to move laterally, enumerate services, and exploit vulnerabilities (like SMB or RDP). The firewall must remain active on all profiles (Domain, Private, Public) to enforce network segmentation.",
  uac_disabled: "User Account Control (UAC) is a security feature that prevents unauthorized changes to the operating system by prompting the user for approval when administrative privileges are required. If UAC is disabled, any malware running under a user's context can silently elevate to SYSTEM privileges without user interaction. This allows ransomware to easily install persistence mechanisms, disable security software, and encrypt system-level files.",
  tamper_protection_off: "Tamper Protection prevents malicious applications from modifying essential Microsoft Defender Antivirus settings, such as disabling real-time protection or cloud-delivered protection. Before deploying ransomware, attackers often try to neutralize the EDR by modifying its registry keys. Without Tamper Protection, these attempts will succeed, leaving the system completely vulnerable to the subsequent encryption payload.",
  event_logging_disabled: "Windows Event Logs are the primary source of truth for detecting anomalous behavior, threat hunting, and post-incident forensics. Attackers frequently attempt to clear or disable the Security, System, and Application logs to cover their tracks and blind the Security Operations Center (SOC). If logging is disabled, incident response becomes nearly impossible, as there is no historical record of the attacker's actions.",
  admin_shares_enabled: "Administrative shares (C$, ADMIN$) are hidden network shares created by Windows for remote administration. Ransomware strains like PsExec or WMI use these shares to rapidly distribute malware payloads across the entire domain. While useful for IT, they provide a frictionless highway for lateral movement. They should be disabled or strictly firewalled to prevent automated network-wide ransomware propagation.",
  open_network_shares: "Network shares configured with overly permissive access rights (e.g., 'Everyone' has Full Control) allow ransomware executed on one machine to reach across the network and encrypt files on centralized file servers. Ransomware actively scans the network for open SMB shares and maps them. Implementing the Principle of Least Privilege and restricting share permissions is critical to contain the blast radius of an infection.",
  guest_account_active: "The built-in Windows Guest account is a historical legacy feature that provides unauthenticated access to the local machine. While disabled by default in modern Windows versions, if it is enabled, it offers a foothold for attackers to enumerate the system and potentially execute privilege escalation exploits without needing valid credentials. It should always remain disabled.",
  autorun_enabled: "AutoRun (and AutoPlay) automatically executes code from removable media (like USB drives) as soon as they are connected to the system. This was historically abused by worms like Conficker and remains a viable physical access vector for malware delivery (e.g., via malicious dropped USBs in a parking lot). Disabling AutoRun ensures that users must manually inspect and launch files from external drives.",
  applocker_absent: "AppLocker (or Windows Defender Application Control) provides application whitelisting, ensuring that only IT-approved executables, scripts, and installers can run. Without application whitelisting, the endpoint operates on a default-allow model, meaning any downloaded ransomware executable can run freely. Implementing a strict AppLocker policy is one of the most effective ways to stop unauthorized payloads from executing.",
  wdigest_enabled: "WDigest is a legacy authentication protocol that stores user credentials in clear text in the LSASS memory space. Attackers using memory dumping tools actively look for WDigest artifacts to steal passwords. It has been superseded by more secure protocols and should be strictly disabled via the registry (UseLogonCredential=0) to prevent trivial credential theft during the lateral movement phase.",
  laps_absent: "The Local Administrator Password Solution (LAPS) automatically randomizes and securely stores the local administrator password for every machine in Active Directory. Without LAPS, organizations often use the same local admin password across all endpoints. If an attacker dumps this shared password from one machine, they immediately gain administrative access to the entire fleet via Pass-the-Hash, enabling rapid ransomware deployment.",
  nla_disabled: "Network Level Authentication (NLA) requires the connecting user to authenticate themselves before establishing an RDP session with the server. If NLA is disabled, the server consumes resources allocating a session before authentication occurs, making it vulnerable to Denial of Service (DoS) attacks and pre-authentication remote code execution exploits (like BlueKeep). NLA is a critical mitigation for RDP exposure.",
  always_install_elevated: "AlwaysInstallElevated is a Windows Installer policy that allows standard users to install MSI packages with SYSTEM privileges. Attackers can abuse this policy by packaging their ransomware or reverse shells inside an MSI file. When executed, the payload runs with the highest privileges available, completely bypassing standard user restrictions and UAC. This policy should always be disabled.",
  vulnerable_driver_blocklist_enabled: "Bring Your Own Vulnerable Driver (BYOVD) is a sophisticated technique where attackers load a legitimate, digitally signed hardware driver that contains a known exploit. They then use this driver to execute code in kernel mode (Ring 0) to terminate EDR processes and bypass security controls. Disabling the vulnerable driver blocklist leaves the system defenseless against these kernel-level attacks.",
  hvci_enabled: "Hypervisor-Protected Code Integrity (HVCI), or Memory Integrity, uses hardware virtualization to isolate the Code Integrity decision-making function from the rest of Windows. This prevents malicious code from running in the kernel. If disabled, attackers can exploit kernel vulnerabilities to execute unsigned code, bypass EDR hooks, and deploy rootkits that hide the ransomware's activities from security software.",
  asr_rules_configured: "Attack Surface Reduction (ASR) rules are a set of controls in Microsoft Defender that prevent software behaviors commonly abused by malware, such as blocking Office apps from creating child processes or blocking executable content from email clients. Without these rules, common attack vectors remain open, allowing phishing payloads to easily download and execute secondary ransomware stages.",
  mock_attack_vss_enum_succeeded: "Ransomware groups heavily rely on deleting Volume Shadow Copies to prevent victims from recovering files without paying the ransom. This Mock Attack actively simulates this reconnaissance behavior by issuing WMI queries to enumerate shadow copies. If the EDR/AV fails to detect and block this highly suspicious activity, it proves the system's behavioral defenses are inadequate against real ransomware.",
  mock_attack_mass_rename_succeeded: "The defining characteristic of a ransomware attack is the rapid encryption and renaming of thousands of files in a short time window. This Mock Attack safely simulates this by generating temporary files and rapidly renaming them to a '.locked' extension. A failure to block this simulation indicates that the endpoint's heuristic defenses cannot recognize or halt a live mass-encryption event."
}

export const MANUAL_FIX_GUIDES = {
  "smb_v1_enabled": {
    summary: "Disable SMBv1 network file sharing protocol to block remote code execution vulnerabilities like EternalBlue/WannaCry.",
    steps: ["Open Settings (Win + I) and navigate to Apps > Optional features.", "Scroll to the bottom and click 'More Windows features'.", "In the Windows Features dialog, locate 'SMB 1.0/CIFS File Sharing Support' and uncheck the entire box.", "Click OK, wait for Windows to remove the feature files, and click 'Restart now' when prompted."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Open Settings (Win + I) and navigate to Apps > Optional features.", "Scroll to the bottom and click 'More Windows features'.", "In the Windows Features dialog, locate 'SMB 1.0/CIFS File Sharing Support' and uncheck the entire box.", "Click OK, wait for Windows to remove the feature files, and click 'Restart now' when prompted."],
        cli: "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"
      },
      win10: {
        label: "Windows 10",
        gui: ["Press Win + R, type 'optionalfeatures.exe' and press Enter.", "Scroll down to locate 'SMB 1.0/CIFS File Sharing Support'.", "Uncheck 'SMB 1.0/CIFS File Sharing Support' (including client and server sub-items).", "Click OK and restart the computer when prompted."],
        cli: "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"
      },
      server: {
        label: "Windows Server",
        gui: ["Open Server Manager > Manage > Remove Roles and Features.", "Click Next until reaching the 'Features' screen.", "Expand 'SMB 1.0/CIFS File Sharing Support' and uncheck it.", "Click Next and then Remove. Restart the server during an approved maintenance window."],
        cli: "Remove-WindowsFeature FS-SMB1; Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"
      },
    },
    verify: "Run '(Get-SmbServerConfiguration).EnableSMB1Protocol' in elevated PowerShell. It must return 'False'.",
    caution: "Legacy network copiers or ancient NAS devices from before 2010 may require firmware upgrades to support modern SMBv2 or SMBv3."
  },
  "rdp_enabled": {
    summary: "Close or restrict exposed Remote Desktop Protocol (port 3389) to prevent automated brute-force and credential stuffing attacks.",
    steps: ["Open Settings (Win + I) and select System > Remote Desktop.", "Toggle the 'Remote Desktop' switch to OFF.", "Click Confirm when asked to disable Remote Desktop."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Open Settings (Win + I) and select System > Remote Desktop.", "Toggle the 'Remote Desktop' switch to OFF.", "Click Confirm when asked to disable Remote Desktop."],
        cli: "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 1; Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue"
      },
      win10: {
        label: "Windows 10",
        gui: ["Open Settings (Win + I) and select System > Remote Desktop.", "Toggle 'Enable Remote Desktop' to OFF.", "Click Confirm in the confirmation dialog."],
        cli: "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 1; Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue"
      },
      server: {
        label: "Windows Server",
        gui: ["Open Server Manager > Local Server.", "Click 'Enabled' next to Remote Desktop to open System Properties.", "Select 'Don't allow remote connections to this computer' and click OK (or run 'sconfig' and choose Option 7 > D)."],
        cli: "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 1; Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue"
      },
    },
    verify: "Run 'Test-NetConnection -ComputerName 127.0.0.1 -Port 3389' in PowerShell. 'TcpTestSucceeded' must be False.",
    caution: "Disabling RDP immediately drops active remote sessions. Only execute if you have physical or out-of-band console access. If RDP is needed, place it behind a VPN and require NLA."
  },
  "autorun_enabled": {
    summary: "Disable USB AutoRun and AutoPlay so connected removable drives cannot automatically execute rogue binaries.",
    steps: ["Open Settings (Win + I) and navigate to Bluetooth & devices > AutoPlay.", "Toggle 'Use AutoPlay for all media and devices' to OFF.", "Set Removable drive and Memory card default actions to 'Take no action'."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Open Settings (Win + I) and navigate to Bluetooth & devices > AutoPlay.", "Toggle 'Use AutoPlay for all media and devices' to OFF.", "Set Removable drive and Memory card default actions to 'Take no action'."],
        cli: "$path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer'; if (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord"
      },
      win10: {
        label: "Windows 10",
        gui: ["Open Settings (Win + I) and navigate to Devices > AutoPlay.", "Toggle 'Use AutoPlay for all media and devices' to OFF.", "Set dropdowns for removable drives to 'Take no action'."],
        cli: "$path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer'; if (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord"
      },
      server: {
        label: "Windows Server",
        gui: ["Press Win + R, type 'gpedit.msc' and press Enter.", "Navigate to Computer Configuration > Administrative Templates > Windows Components > AutoPlay Policies.", "Double-click 'Turn off AutoPlay', select 'Enabled', choose 'All drives', and click OK."],
        cli: "$path = 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer'; if (!(Test-Path $path)) { New-Item -Path $path -Force }; Set-ItemProperty -Path $path -Name 'NoDriveTypeAutoRun' -Value 255 -Type DWord"
      },
    },
    verify: "Run 'Get-ItemPropertyValue -Path HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer -Name NoDriveTypeAutoRun'. It should return '255'.",
    caution: "This disables automatic launching; users can still manually open files in File Explorer."
  },
  "open_network_shares": {
    summary: "Restrict network shares granting access to 'Everyone' to prevent ransomware from encrypting departmental shared folders.",
    steps: ["Press Win + R, type 'compmgmt.msc' and press Enter.", "Navigate to System Tools > Shared Folders > Shares.", "Right-click the exposed share > Properties > Share Permissions tab.", "Select 'Everyone' and click Remove. Click Add to specify only authorized users or domain security groups with Least Privilege."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Press Win + R, type 'compmgmt.msc' and press Enter.", "Navigate to System Tools > Shared Folders > Shares.", "Right-click the exposed share > Properties > Share Permissions tab.", "Select 'Everyone' and click Remove. Click Add to specify only authorized users or domain security groups with Least Privilege."],
        cli: "Revoke-SmbShareAccess -Name '<ShareName>' -AccountName 'Everyone' -Force"
      },
      win10: {
        label: "Windows 10",
        gui: ["Press Win + R, type 'fsmgmt.msc' or 'compmgmt.msc' and press Enter.", "Select Shares, right-click the open share, and choose Properties.", "Under the Share Permissions tab, remove 'Everyone' and grant permissions only to authorized user accounts.", "Check the Security (NTFS) tab to ensure underlying folder permissions match."],
        cli: "Revoke-SmbShareAccess -Name '<ShareName>' -AccountName 'Everyone' -Force"
      },
      server: {
        label: "Windows Server",
        gui: ["Open Server Manager > File and Storage Services > Shares.", "Right-click the share > Properties > Permissions tab.", "Click Customize permissions, select 'Everyone', and click Remove. Add authorized Active Directory security groups."],
        cli: "Revoke-SmbShareAccess -Name '<ShareName>' -AccountName 'Everyone' -Force"
      },
    },
    verify: "Run 'Get-SmbShareAccess -Name <ShareName>' in PowerShell. Confirm 'Everyone' is absent from the access control list.",
    caution: "Review NTFS security permissions alongside share permissions. Ensure legitimate applications and employees retain necessary access."
  },
  "macro_execution_enabled": {
    summary: "Block unprompted execution of Microsoft Office VBA macros to eliminate a primary malware and ransomware downloader vector.",
    steps: ["Open Microsoft Word or Excel, then click File > Options.", "Click Trust Center > Trust Center Settings > Macro Settings.", "Select 'Disable VBA macros with notification' (or 'Disable all macros without notification').", "Check 'Enable macros in digitally signed documents' if your organization signs internal scripts, then click OK."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Open Microsoft Word or Excel, then click File > Options.", "Click Trust Center > Trust Center Settings > Macro Settings.", "Select 'Disable VBA macros with notification' (or 'Disable all macros without notification').", "Check 'Enable macros in digitally signed documents' if your organization signs internal scripts, then click OK."],
        cli: "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Office\\16.0\\Word\\Security' -Name 'VBAWarnings' -Value 4 -Type DWord; Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Office\\16.0\\Excel\\Security' -Name 'VBAWarnings' -Value 4 -Type DWord"
      },
      win10: {
        label: "Windows 10",
        gui: ["Open Word or Excel > File > Options.", "Navigate to Trust Center > Trust Center Settings > Macro Settings.", "Select 'Disable VBA macros with notification'.", "Click OK to save changes."],
        cli: "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Office\\16.0\\Word\\Security' -Name 'VBAWarnings' -Value 4 -Type DWord; Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Office\\16.0\\Excel\\Security' -Name 'VBAWarnings' -Value 4 -Type DWord"
      },
      server: {
        label: "Windows Server",
        gui: ["For RDS/Terminal servers, open 'gpedit.msc' or Domain Group Policy.", "Navigate to User Configuration > Administrative Templates > Microsoft Office > Security Settings.", "Set 'VBA Macro Notification Settings' to Enabled and choose 'Disable all with notification'."],
        cli: "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Office\\16.0\\Word\\Security' -Name 'VBAWarnings' -Value 4 -Type DWord; Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Office\\16.0\\Excel\\Security' -Name 'VBAWarnings' -Value 4 -Type DWord"
      },
    },
    verify: "Open Word/Excel > File > Options > Trust Center > Macro Settings. Verify 'Disable VBA macros with notification' is selected.",
    caution: "If accounting or reporting processes use internal macros, sign them with an internal code-signing certificate rather than allowing unsigned macros."
  },
  "powershell_unrestricted": {
    summary: "Enforce RemoteSigned execution policy to prevent unapproved external PowerShell scripts from running automatically.",
    steps: ["Right-click the Start button and choose 'Terminal (Admin)' or 'PowerShell (Admin)'.", "Execute: Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force", "Type 'Y' if prompted for confirmation."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Right-click the Start button and choose 'Terminal (Admin)' or 'PowerShell (Admin)'.", "Execute: Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force", "Type 'Y' if prompted for confirmation."],
        cli: "Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force"
      },
      win10: {
        label: "Windows 10",
        gui: ["Click Start, type 'PowerShell', right-click 'Windows PowerShell' and select 'Run as Administrator'.", "Execute: Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force", "Confirm the prompt."],
        cli: "Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force"
      },
      server: {
        label: "Windows Server",
        gui: ["Open 'gpedit.msc' > Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell.", "Double-click 'Turn on Script Execution', set to Enabled, and choose 'Allow only signed scripts' or 'Allow local scripts and remote signed scripts'.", "Click OK and run 'gpupdate /force'."],
        cli: "Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force"
      },
    },
    verify: "Run 'Get-ExecutionPolicy -List' in PowerShell. Confirm 'LocalMachine' is set to 'RemoteSigned' or 'Restricted'.",
    caution: "Execution policy is a safety guardrail, not an impenetrable security barrier. For comprehensive application control, deploy AppLocker or WDAC."
  },
  "uac_disabled": {
    summary: "Enable User Account Control (UAC) to stop malicious processes from silently escalating to SYSTEM privileges without administrator consent.",
    steps: ["Press Win + R, type 'UserAccountControlSettings.exe' and press Enter.", "Move the slider to the default position ('Notify me only when apps try to make changes') or to the top ('Always notify').", "Click OK, confirm the UAC prompt, and restart the computer."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Press Win + R, type 'UserAccountControlSettings.exe' and press Enter.", "Move the slider to the default position ('Notify me only when apps try to make changes') or to the top ('Always notify').", "Click OK, confirm the UAC prompt, and restart the computer."],
        cli: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -Value 1 -Type DWord"
      },
      win10: {
        label: "Windows 10",
        gui: ["Press Win + R, type 'UserAccountControlSettings.exe' and press Enter.", "Move the slider up to the recommended level (second from top) or top level.", "Click OK and restart the system when prompted."],
        cli: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -Value 1 -Type DWord"
      },
      server: {
        label: "Windows Server",
        gui: ["Open 'secpol.msc' > Local Policies > Security Options.", "Locate 'User Account Control: Run all administrators in Admin Approval Mode'.", "Set it to Enabled, click OK, and schedule a system reboot."],
        cli: "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -Value 1 -Type DWord"
      },
    },
    verify: "Run 'Get-ItemPropertyValue -Path HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System -Name EnableLUA'. It must return '1'.",
    caution: "A system restart is required for User Account Control to take full effect across all processes."
  },
  "applocker_absent": {
    summary: "Configure AppLocker application control policies to ensure only verified, authorized executables can launch on the endpoint.",
    steps: ["Press Win + R, type 'secpol.msc' and press Enter.", "Navigate to Application Control Policies > AppLocker.", "Click 'Configure rule enforcement' and check 'Configured' under Executable rules (start with 'Audit only').", "Right-click Executable Rules > 'Create Default Rules' to ensure Windows and Program Files remain accessible.", "Start the Application Identity service: Win + R > services.msc > Application Identity > Set to Automatic and Start."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Press Win + R, type 'secpol.msc' and press Enter.", "Navigate to Application Control Policies > AppLocker.", "Click 'Configure rule enforcement' and check 'Configured' under Executable rules (start with 'Audit only').", "Right-click Executable Rules > 'Create Default Rules' to ensure Windows and Program Files remain accessible.", "Start the Application Identity service: Win + R > services.msc > Application Identity > Set to Automatic and Start."],
        cli: "Set-Service -Name AppIDSvc -StartupType Automatic; Start-Service AppIDSvc"
      },
      win10: {
        label: "Windows 10",
        gui: ["Press Win + R, type 'secpol.msc' and navigate to Application Control Policies > AppLocker.", "Right-click Executable Rules > Create Default Rules.", "Enable rule enforcement in Audit mode first.", "Ensure the Application Identity service is started and set to Automatic."],
        cli: "Set-Service -Name AppIDSvc -StartupType Automatic; Start-Service AppIDSvc"
      },
      server: {
        label: "Windows Server",
        gui: ["Server Manager > Tools > Local Security Policy (or Group Policy Management for fleet).", "Navigate to Application Control Policies > AppLocker.", "Create Default Rules under Executable Rules and Packaged App Rules.", "Set Application Identity service to Automatic and start it."],
        cli: "Set-Service -Name AppIDSvc -StartupType Automatic; Start-Service AppIDSvc"
      },
    },
    verify: "Run 'Get-Service AppIDSvc' in elevated PowerShell. Confirm Status is 'Running'. Check Event Viewer > Applications and Services Logs > Microsoft > Windows > AppLocker.",
    caution: "CRITICAL: Always generate Default Rules (allowing %WINDIR% and %PROGRAMFILES%) before switching from Audit to Enforce mode to avoid blocking essential system binaries."
  },
  "defender_disabled": {
    summary: "Enable Windows Defender real-time antivirus protection to detect and quarantine malware signatures and heuristic threats.",
    steps: ["Open Settings (Win + I) > Privacy & security > Windows Security.", "Click 'Virus & threat protection', then click 'Manage settings' under Virus & threat protection settings.", "Toggle 'Real-time protection' to ON.", "Also toggle 'Cloud-delivered protection' and 'Automatic sample submission' to ON."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Open Settings (Win + I) > Privacy & security > Windows Security.", "Click 'Virus & threat protection', then click 'Manage settings' under Virus & threat protection settings.", "Toggle 'Real-time protection' to ON.", "Also toggle 'Cloud-delivered protection' and 'Automatic sample submission' to ON."],
        cli: "Set-MpPreference -DisableRealtimeMonitoring $false; Start-Service WinDefend -ErrorAction SilentlyContinue"
      },
      win10: {
        label: "Windows 10",
        gui: ["Open Settings (Win + I) > Update & Security > Windows Security.", "Click 'Virus & threat protection' > 'Manage settings'.", "Toggle 'Real-time protection' to ON."],
        cli: "Set-MpPreference -DisableRealtimeMonitoring $false; Start-Service WinDefend -ErrorAction SilentlyContinue"
      },
      server: {
        label: "Windows Server",
        gui: ["Open Server Manager > Local Server.", "Verify Windows Defender is installed (if not, add feature via Add Roles and Features > Windows Defender Antivirus).", "Open Windows Security from Start menu > Virus & threat protection > Turn ON Real-time protection."],
        cli: "Set-MpPreference -DisableRealtimeMonitoring $false; Start-Service WinDefend -ErrorAction SilentlyContinue"
      },
    },
    verify: "Run '(Get-MpComputerStatus).RealTimeProtectionEnabled' in PowerShell. It must return 'True'.",
    caution: "If an authorized third-party enterprise EDR (e.g. CrowdStrike, SentinelOne) is deployed, Defender may operate in passive mode. Coordinate with your IT security team."
  },
  "firewall_disabled": {
    summary: "Enable Windows Defender Firewall across Domain, Private, and Public profiles to block unauthorized inbound connections and scanning.",
    steps: ["Open Settings (Win + I) > Privacy & security > Windows Security > Firewall & network protection.", "Click on Domain network, Private network, and Public network.", "Toggle 'Microsoft Defender Firewall' to ON for all three profiles."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Open Settings (Win + I) > Privacy & security > Windows Security > Firewall & network protection.", "Click on Domain network, Private network, and Public network.", "Toggle 'Microsoft Defender Firewall' to ON for all three profiles."],
        cli: "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"
      },
      win10: {
        label: "Windows 10",
        gui: ["Open Settings (Win + I) > Update & Security > Windows Security > Firewall & network protection.", "Click each profile (Domain, Private, Public) and toggle the firewall to ON."],
        cli: "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"
      },
      server: {
        label: "Windows Server",
        gui: ["Server Manager > Local Server > Click 'Windows Defender Firewall'.", "Click 'Turn Windows Defender Firewall on or off' in the left pane.", "Select 'Turn on Windows Defender Firewall' for all network locations and click OK."],
        cli: "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"
      },
    },
    verify: "Run 'Get-NetFirewallProfile | Select-Object Name, Enabled' in PowerShell. All three profiles must report Enabled: True.",
    caution: "Ensure required line-of-business services have specific inbound port allow rules before turning on the firewall to prevent connection drops."
  },
  "tamper_protection_off": {
    summary: "Turn on Defender Tamper Protection to prevent ransomware and malware from manipulating registry keys or stopping antivirus services.",
    steps: ["Open Settings (Win + I) > Privacy & security > Windows Security > Virus & threat protection.", "Under 'Virus & threat protection settings', click 'Manage settings'.", "Scroll down to 'Tamper Protection' and toggle it to ON."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Open Settings (Win + I) > Privacy & security > Windows Security > Virus & threat protection.", "Under 'Virus & threat protection settings', click 'Manage settings'.", "Scroll down to 'Tamper Protection' and toggle it to ON."],
        cli: "Set-MpPreference -DisableTamperProtection $false -ErrorAction SilentlyContinue"
      },
      win10: {
        label: "Windows 10",
        gui: ["Open Settings (Win + I) > Update & Security > Windows Security > Virus & threat protection.", "Click 'Manage settings' under Virus & threat protection settings.", "Toggle 'Tamper Protection' to ON."],
        cli: "Set-MpPreference -DisableTamperProtection $false -ErrorAction SilentlyContinue"
      },
      server: {
        label: "Windows Server",
        gui: ["On Windows Server 2019/2022/2025, Tamper Protection is managed centrally through Microsoft Defender for Endpoint / Intune Security Center.", "On standalone servers, enable it via elevated PowerShell using the command below."],
        cli: "Set-MpPreference -DisableTamperProtection $false -ErrorAction SilentlyContinue"
      },
    },
    verify: "Run '(Get-MpComputerStatus).IsTamperProtected' in PowerShell. It should return 'True'.",
    caution: "On managed domain or Entra-joined machines, local UI changes may be overridden by central Group Policy or Intune profiles."
  },
  "event_logging_disabled": {
    summary: "Start and configure the Windows Event Log service so all logon, process execution, and security events are recorded for forensics.",
    steps: ["Press Win + R, type 'services.msc' and press Enter.", "Scroll down to 'Windows Event Log'.", "Right-click > Properties > Set Startup type to 'Automatic'.", "Click 'Start' if the service is stopped, then click OK."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Press Win + R, type 'services.msc' and press Enter.", "Scroll down to 'Windows Event Log'.", "Right-click > Properties > Set Startup type to 'Automatic'.", "Click 'Start' if the service is stopped, then click OK."],
        cli: "Set-Service -Name 'eventlog' -StartupType Automatic; Start-Service -Name 'eventlog'"
      },
      win10: {
        label: "Windows 10",
        gui: ["Press Win + R, type 'services.msc' and press Enter.", "Double-click 'Windows Event Log' in the list.", "Set Startup type to 'Automatic', click 'Start', and click OK."],
        cli: "Set-Service -Name 'eventlog' -StartupType Automatic; Start-Service -Name 'eventlog'"
      },
      server: {
        label: "Windows Server",
        gui: ["Server Manager > Tools > Services.", "Locate 'Windows Event Log', open Properties.", "Set Startup type to 'Automatic' and click 'Start'."],
        cli: "Set-Service -Name 'eventlog' -StartupType Automatic; Start-Service -Name 'eventlog'"
      },
    },
    verify: "Run 'Get-Service eventlog' in PowerShell. Status must be 'Running' and StartType must be 'Automatic'.",
    caution: "Never clear event logs as a diagnostic step, as doing so destroys critical forensic traces during an ongoing security incident."
  },
  "admin_shares_enabled": {
    summary: "Restrict or disable default administrative hidden shares (C$, ADMIN$) to prevent attackers from executing remote tools like PsExec across the subnet.",
    steps: ["Press Win + R, type 'wf.msc' (Windows Firewall with Advanced Security) and press Enter.", "Click Inbound Rules, locate 'File and Printer Sharing (SMB-In)', and restrict the Remote IP Address scope to approved admin workstations only.", "Alternatively, disable client auto-shares via the registry command below."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Press Win + R, type 'wf.msc' (Windows Firewall with Advanced Security) and press Enter.", "Click Inbound Rules, locate 'File and Printer Sharing (SMB-In)', and restrict the Remote IP Address scope to approved admin workstations only.", "Alternatively, disable client auto-shares via the registry command below."],
        cli: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name 'AutoShareWks' -Value 0 -Type DWord; Restart-Service LanmanServer -Force"
      },
      win10: {
        label: "Windows 10",
        gui: ["Open Windows Defender Firewall with Advanced Security ('wf.msc').", "Scope Inbound SMB (TCP port 445) rules to management IP subnets only.", "To disable auto-shares completely on workstations, run the PowerShell command below."],
        cli: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name 'AutoShareWks' -Value 0 -Type DWord; Restart-Service LanmanServer -Force"
      },
      server: {
        label: "Windows Server",
        gui: ["On servers, administrative shares are commonly used by backup and deployment agents.", "Best practice is to restrict inbound SMB (Port 445) to dedicated management IPs in Windows Firewall.", "If policy requires disabling server auto-shares completely, apply the AutoShareServer registry key."],
        cli: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' -Name 'AutoShareServer' -Value 0 -Type DWord; Restart-Service LanmanServer -Force"
      },
    },
    verify: "Run 'Get-SmbShare' in PowerShell. Administrative shares C$ and ADMIN$ should be removed or inaccessible from unapproved hosts.",
    caution: "Disabling admin shares may disrupt remote management software (SCCM, PDQ) or agentless backup tools. Coordinate with system administrators."
  },
  "lsass_protection_off": {
    summary: "Enable LSASS Protected Process Light (RunAsPPL) to prevent memory-dumping tools like Mimikatz from stealing credentials and Kerberos tickets.",
    steps: ["Open Settings (Win + I) > Privacy & security > Windows Security > Device security.", "Click 'Core isolation details'.", "Locate 'Local Security Authority protection' and toggle it to ON.", "Restart the computer when prompted."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Open Settings (Win + I) > Privacy & security > Windows Security > Device security.", "Click 'Core isolation details'.", "Locate 'Local Security Authority protection' and toggle it to ON.", "Restart the computer when prompted."],
        cli: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL' -Value 1 -Type DWord"
      },
      win10: {
        label: "Windows 10",
        gui: ["Press Win + R, type 'regedit' and press Enter.", "Navigate to 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa'.", "Right-click Lsa > New > DWORD (32-bit) Value, name it 'RunAsPPL' and set value to '1'.", "Restart the computer."],
        cli: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL' -Value 1 -Type DWord"
      },
      server: {
        label: "Windows Server",
        gui: ["Open 'gpedit.msc' (or Group Policy Management Console).", "Navigate to Computer Configuration > Administrative Templates > System > Local Security Authority.", "Open 'Configures LSASS to run as a protected process', set to Enabled, and choose 'Enabled without UEFI lock' or 'Enabled with UEFI lock'.", "Restart the server during a scheduled maintenance window."],
        cli: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL' -Value 1 -Type DWord"
      },
    },
    verify: "Run 'Get-ItemPropertyValue -Path HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa -Name RunAsPPL' in PowerShell. It should return '1' or '2'. Check Event ID 3065 in Microsoft-Windows-CodeIntegrity/Operational.",
    caution: "Requires a system reboot. Verify that custom third-party smart card or biometric credential providers are digitally signed and compatible."
  },
  "guest_account_active": {
    summary: "Disable the built-in Guest account to eliminate unauthenticated local and network logon opportunities for intruders.",
    steps: ["Press Win + R, type 'lusrmgr.msc' and press Enter.", "Click 'Users' in the left pane.", "Right-click 'Guest' and select Properties.", "Check the box 'Account is disabled', then click OK."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Press Win + R, type 'lusrmgr.msc' and press Enter.", "Click 'Users' in the left pane.", "Right-click 'Guest' and select Properties.", "Check the box 'Account is disabled', then click OK."],
        cli: "Disable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue"
      },
      win10: {
        label: "Windows 10",
        gui: ["Press Win + R, type 'lusrmgr.msc' and press Enter.", "Open Users, right-click Guest > Properties.", "Check 'Account is disabled' and click Apply > OK."],
        cli: "Disable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue"
      },
      server: {
        label: "Windows Server",
        gui: ["Server Manager > Tools > Computer Management > Local Users and Groups > Users.", "Right-click Guest > Properties.", "Ensure 'Account is disabled' is checked and click OK."],
        cli: "Disable-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue"
      },
    },
    verify: "Run '(Get-LocalUser -Name Guest).Enabled' in PowerShell. It must return 'False'.",
    caution: "Never delete the Guest account (it is a built-in operating system security principal); keep it disabled."
  },
  "vss_deleted": {
    summary: "Enable System Protection and Volume Shadow Copies to guarantee rapid local snapshot rollbacks after ransomware attacks.",
    steps: ["Press Win + R, type 'sysdm.cpl' and press Enter.", "Select the 'System Protection' tab, select your system drive (C:), and click 'Configure'.", "Choose 'Turn on system protection', adjust Max Usage to 5-10% of disk space, and click OK.", "Click 'Create...' and name the new restore point (e.g. 'R3P_Secure_Baseline')."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Press Win + R, type 'sysdm.cpl' and press Enter.", "Select the 'System Protection' tab, select your system drive (C:), and click 'Configure'.", "Choose 'Turn on system protection', adjust Max Usage to 5-10% of disk space, and click OK.", "Click 'Create...' and name the new restore point (e.g. 'R3P_Secure_Baseline')."],
        cli: "Enable-ComputerRestore -Drive 'C:\'; Checkpoint-Computer -Description 'R3P_Baseline_RestorePoint' -RestorePointType 'MODIFY_SETTINGS'"
      },
      win10: {
        label: "Windows 10",
        gui: ["Press Win + R, type 'systempropertiesprotection.exe' and press Enter.", "Select drive C: > Configure > Select 'Turn on system protection' > Allocate 5-10% disk space > OK.", "Click 'Create' to generate an immediate initial restore point."],
        cli: "Enable-ComputerRestore -Drive 'C:\'; Checkpoint-Computer -Description 'R3P_Baseline_RestorePoint' -RestorePointType 'MODIFY_SETTINGS'"
      },
      server: {
        label: "Windows Server",
        gui: ["Open File Explorer, right-click the volume (C:) and choose 'Configure Shadow Copies...'.", "Select the volume, click 'Settings' to allocate storage, then click 'Enable'.", "Click 'Create Now' to establish an immediate point-in-time snapshot."],
        cli: "vssadmin create shadow /for=C:"
      },
    },
    verify: "Run 'vssadmin list shadows' in elevated CMD/PowerShell. Confirm active shadow copies are listed for volume C:.",
    caution: "Previously deleted shadow copies cannot be restored by turning the service back on; this creates new recovery points going forward. Pair with offline backups."
  },
  "backup_absent": {
    summary: "Configure scheduled, resilient backups to provide a dependable fail-safe against total data loss during encryption events.",
    steps: ["Open Settings (Win + I) > System > Storage > Advanced storage settings > Backup options.", "Configure File History with an external hard drive or setup automatic OneDrive / enterprise cloud sync.", "Alternatively, deploy and schedule an approved enterprise backup agent (e.g. Veeam, Acronis)."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Open Settings (Win + I) > System > Storage > Advanced storage settings > Backup options.", "Configure File History with an external hard drive or setup automatic OneDrive / enterprise cloud sync.", "Alternatively, deploy and schedule an approved enterprise backup agent (e.g. Veeam, Acronis)."],
        cli: "Set-Service -Name 'fhsvc' -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service 'fhsvc' -ErrorAction SilentlyContinue"
      },
      win10: {
        label: "Windows 10",
        gui: ["Open Settings (Win + I) > Update & Security > Backup.", "Click 'Add a drive' under 'Back up using File History' and select a dedicated backup drive.", "Click 'More options' and verify backup frequency (e.g. Every hour or daily)."],
        cli: "Set-Service -Name 'fhsvc' -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service 'fhsvc' -ErrorAction SilentlyContinue"
      },
      server: {
        label: "Windows Server",
        gui: ["Open Server Manager > Manage > Add Roles and Features > Features > Check 'Windows Server Backup' > Install.", "Open Tools > Windows Server Backup ('wbadmin.msc').", "Click 'Backup Schedule Wizard' in the Actions pane and configure a daily automated backup to dedicated storage."],
        cli: "Install-WindowsFeature Windows-Server-Backup; Start-Service -Name 'wbengine' -ErrorAction SilentlyContinue"
      },
    },
    verify: "Run 'wbadmin get status' or inspect your backup software console to confirm recent successful backup jobs.",
    caution: "Ensure at least one backup tier is air-gapped, immutable, or stored offsite so attackers cannot delete backups prior to triggering ransomware."
  },
  "bitlocker_off": {
    summary: "Enable BitLocker full-disk encryption to prevent offline data theft, physical drive extraction, and extortion.",
    steps: ["Open Settings (Win + I) > Privacy & security > Device encryption (or Control Panel > BitLocker Drive Encryption).", "Click 'Turn on BitLocker' for Drive C:.", "Choose how to back up your recovery key (Microsoft Account, Entra ID, or Print/Save file).", "Choose 'Encrypt used disk space only' and 'New encryption mode', then start encryption."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Open Settings (Win + I) > Privacy & security > Device encryption (or Control Panel > BitLocker Drive Encryption).", "Click 'Turn on BitLocker' for Drive C:.", "Choose how to back up your recovery key (Microsoft Account, Entra ID, or Print/Save file).", "Choose 'Encrypt used disk space only' and 'New encryption mode', then start encryption."],
        cli: "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector"
      },
      win10: {
        label: "Windows 10",
        gui: ["Open Control Panel > System and Security > BitLocker Drive Encryption.", "Click 'Turn on BitLocker' next to the operating system drive.", "Save the 48-digit recovery key in a secure location.", "Follow the setup wizard to complete drive encryption."],
        cli: "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector"
      },
      server: {
        label: "Windows Server",
        gui: ["Server Manager > Add Roles and Features > Features > Check 'BitLocker Drive Encryption' > Install (reboot required).", "After reboot, open File Explorer, right-click Drive C: > 'Turn on BitLocker'.", "Escrow the recovery key into Active Directory Domain Services."],
        cli: "Install-WindowsFeature BitLocker -IncludeManagementTools; Enable-BitLocker -MountPoint 'C:' -TpmProtector"
      },
    },
    verify: "Run 'manage-bde -status C:' in elevated command prompt. 'Protection Status' must show 'Protection On'.",
    caution: "MANDATORY: Always backup and confirm retrieval of the 48-digit BitLocker recovery key to Active Directory or a secure vault before initiating encryption."
  },
  "wdigest_enabled": {
    summary: "Disable WDigest cleartext credential caching to prevent attackers from reading plaintext passwords out of memory.",
    steps: ["Press Win + R, type 'regedit' and press Enter.", "Navigate to: HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest.", "Double-click 'UseLogonCredential' and set its value to '0' (or delete the DWORD).", "Click OK."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Press Win + R, type 'regedit' and press Enter.", "Navigate to: HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest.", "Double-click 'UseLogonCredential' and set its value to '0' (or delete the DWORD).", "Click OK."],
        cli: "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name 'UseLogonCredential' -Value 0 -Type DWord"
      },
      win10: {
        label: "Windows 10",
        gui: ["Press Win + R, type 'regedit' and press Enter.", "Navigate to: HKLM\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest.", "Set DWORD 'UseLogonCredential' to 0.", "Click OK."],
        cli: "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name 'UseLogonCredential' -Value 0 -Type DWord"
      },
      server: {
        label: "Windows Server",
        gui: ["Open 'gpedit.msc' or Domain Group Policy.", "Navigate to Computer Configuration > Administrative Templates > System > Credentials Delegation.", "Or apply the registry setting directly using the CLI command below."],
        cli: "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name 'UseLogonCredential' -Value 0 -Type DWord"
      },
    },
    verify: "Run 'Get-ItemPropertyValue -Path HKLM:\\System\\CurrentControlSet\\Control\\SecurityProviders\\WDigest -Name UseLogonCredential'. It must return '0'.",
    caution: "Currently logged-in users must sign out and sign back in to purge existing plaintext credentials from LSASS memory."
  },
  "laps_absent": {
    summary: "Deploy Windows LAPS to randomize and manage local administrator passwords, blocking pass-the-hash lateral traversal.",
    steps: ["Windows 11 (22H2+) includes native Windows LAPS built into the OS!", "Press Win + R, type 'gpedit.msc' > Computer Configuration > Administrative Templates > System > LAPS.", "Enable 'Configure password backup directory' and select 'Microsoft Entra ID' or 'Active Directory'.", "Configure password complexity and age requirements."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Windows 11 (22H2+) includes native Windows LAPS built into the OS!", "Press Win + R, type 'gpedit.msc' > Computer Configuration > Administrative Templates > System > LAPS.", "Enable 'Configure password backup directory' and select 'Microsoft Entra ID' or 'Active Directory'.", "Configure password complexity and age requirements."],
        cli: "Get-Item C:\\Windows\\System32\\Laps.dll -ErrorAction SilentlyContinue"
      },
      win10: {
        label: "Windows 10",
        gui: ["On updated Windows 10 (April 2023 update or later), native Windows LAPS is installed.", "For older builds, download and install the Microsoft LAPS MSI package from Microsoft Download Center.", "Configure policy via 'gpedit.msc' under System > LAPS."],
        cli: "Get-Item C:\\Windows\\System32\\Laps.dll -ErrorAction SilentlyContinue"
      },
      server: {
        label: "Windows Server",
        gui: ["Windows Server 2019/2022 includes native Windows LAPS with current cumulative updates.", "Open Domain Group Policy Management, configure LAPS under Computer Configuration > Policies > Admin Templates > System > LAPS.", "Set the backup directory to Active Directory and assign delegated read rights to IT administrators."],
        cli: "Get-Command *Laps* -ErrorAction SilentlyContinue"
      },
    },
    verify: "Inspect 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\LAPS\\Config' or check Active Directory computer object for the msLAPS-Password attribute.",
    caution: "Requires directory permissions and schema support so workstations can securely escrow random passwords into Active Directory or Entra ID."
  },
  "nla_disabled": {
    summary: "Enforce Network Level Authentication (NLA) for Remote Desktop to mitigate pre-authentication vulnerabilities and denial-of-service risks.",
    steps: ["Press Win + R, type 'sysdm.cpl' and press Enter.", "Select the 'Remote' tab.", "Under Remote Desktop, check the box: 'Allow remote connections only with Network Level Authentication (recommended)'.", "Click Apply > OK."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Press Win + R, type 'sysdm.cpl' and press Enter.", "Select the 'Remote' tab.", "Under Remote Desktop, check the box: 'Allow remote connections only with Network Level Authentication (recommended)'.", "Click Apply > OK."],
        cli: "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 1 -Type DWord"
      },
      win10: {
        label: "Windows 10",
        gui: ["Open Settings (Win + I) > System > Remote Desktop > Click 'Advanced settings'.", "Check the box: 'Require computers to use Network Level Authentication to connect'.", "Return to Settings."],
        cli: "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 1 -Type DWord"
      },
      server: {
        label: "Windows Server",
        gui: ["Server Manager > Local Server > Click on Remote Desktop setting.", "In System Properties, ensure 'Allow connections only from computers running Remote Desktop with Network Level Authentication' is checked.", "Click OK."],
        cli: "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -Value 1 -Type DWord"
      },
    },
    verify: "Run 'Get-ItemPropertyValue -Path \"HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" -Name UserAuthentication'. It must return '1'.",
    caution: "Pre-NLA legacy remote desktop clients will no longer be able to establish connections."
  },
  "always_install_elevated": {
    summary: "Disable AlwaysInstallElevated to stop standard unprivileged users from installing malicious MSI packages with SYSTEM rights.",
    steps: ["Press Win + R, type 'gpedit.msc' and press Enter.", "Navigate to: Computer Configuration > Administrative Templates > Windows Components > Windows Installer.", "Double-click 'Always install with elevated privileges' and set it to 'Disabled'.", "Repeat the step under User Configuration > Administrative Templates > Windows Components > Windows Installer."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Press Win + R, type 'gpedit.msc' and press Enter.", "Navigate to: Computer Configuration > Administrative Templates > Windows Components > Windows Installer.", "Double-click 'Always install with elevated privileges' and set it to 'Disabled'.", "Repeat the step under User Configuration > Administrative Templates > Windows Components > Windows Installer."],
        cli: "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue; Remove-ItemProperty -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue"
      },
      win10: {
        label: "Windows 10",
        gui: ["Open 'gpedit.msc'.", "Go to Computer Configuration & User Configuration > Admin Templates > Windows Components > Windows Installer.", "Set 'Always install with elevated privileges' to Disabled in both locations.", "Run 'gpupdate /force'."],
        cli: "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue; Remove-ItemProperty -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue"
      },
      server: {
        label: "Windows Server",
        gui: ["Open Group Policy Management Console or 'gpedit.msc'.", "Set 'Always install with elevated privileges' to Disabled under both Computer Configuration and User Configuration.", "Run the CLI cleanup command to purge registry values."],
        cli: "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue; Remove-ItemProperty -Path 'HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer' -Name 'AlwaysInstallElevated' -ErrorAction SilentlyContinue"
      },
    },
    verify: "Run 'Get-ItemProperty -Path HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer -Name AlwaysInstallElevated -ErrorAction SilentlyContinue'. It must return null or 0.",
    caution: "Standard users will require administrator elevation or an automated software distribution tool to install system software."
  },
  "vulnerable_driver_blocklist_enabled": {
    summary: "Enable Microsoft Vulnerable Driver Blocklist to neutralize BYOVD (Bring Your Own Vulnerable Driver) attacks that terminate EDR defenses.",
    steps: ["Open Settings (Win + I) > Privacy & security > Windows Security > Device security.", "Click 'Core isolation details'.", "Locate 'Microsoft Vulnerable Driver Blocklist' and toggle it to ON.", "Restart the computer when prompted."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Open Settings (Win + I) > Privacy & security > Windows Security > Device security.", "Click 'Core isolation details'.", "Locate 'Microsoft Vulnerable Driver Blocklist' and toggle it to ON.", "Restart the computer when prompted."],
        cli: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config' -Name 'VulnerableDriverBlocklistEnable' -Value 1 -Type DWord"
      },
      win10: {
        label: "Windows 10",
        gui: ["Ensure Windows 10 is updated with KB5018410 or newer.", "Open elevated PowerShell and run the CLI fix command below to enable blocklist enforcement.", "Restart the computer."],
        cli: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config' -Name 'VulnerableDriverBlocklistEnable' -Value 1 -Type DWord"
      },
      server: {
        label: "Windows Server",
        gui: ["On Windows Server 2022/2025, enable via elevated PowerShell command below.", "Alternatively, deploy a custom Windows Defender Application Control (WDAC) policy containing Microsoft's driver blocklist.", "Restart the server."],
        cli: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config' -Name 'VulnerableDriverBlocklistEnable' -Value 1 -Type DWord"
      },
    },
    verify: "Run 'Get-ItemPropertyValue -Path HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config -Name VulnerableDriverBlocklistEnable'. It must return '1'.",
    caution: "Requires a system reboot. Blocks known vulnerable third-party hardware drivers that have been weaponized by ransomware syndicates."
  },
  "hvci_enabled": {
    summary: "Enable HVCI (Hypervisor-Protected Code Integrity / Memory Integrity) to prevent unsigned kernel-mode rootkits and driver exploits.",
    steps: ["Open Settings (Win + I) > Privacy & security > Windows Security > Device security.", "Click 'Core isolation details'.", "Toggle 'Memory integrity' to ON.", "Restart your PC."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Open Settings (Win + I) > Privacy & security > Windows Security > Device security.", "Click 'Core isolation details'.", "Toggle 'Memory integrity' to ON.", "Restart your PC."],
        cli: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity' -Name 'Enabled' -Value 1 -Type DWord"
      },
      win10: {
        label: "Windows 10",
        gui: ["Open Settings (Win + I) > Update & Security > Windows Security > Device security.", "Click 'Core isolation details'.", "Toggle 'Memory integrity' to ON.", "Restart your PC."],
        cli: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity' -Name 'Enabled' -Value 1 -Type DWord"
      },
      server: {
        label: "Windows Server",
        gui: ["Open 'gpedit.msc' > Computer Configuration > Administrative Templates > System > Device Guard.", "Double-click 'Turn On Virtualization Based Security', select Enabled.", "Under 'Virtualization Based Protection of Code Integrity', select 'Enabled with UEFI lock'.", "Click OK and schedule a reboot."],
        cli: "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity' -Name 'Enabled' -Value 1 -Type DWord"
      },
    },
    verify: "Run 'Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard | Select-Object SecurityServicesRunning'. It should include '2' (HVCI).",
    caution: "Requires CPU virtualization (Intel VT-x / AMD-V) enabled in BIOS/UEFI. Incompatible legacy hardware drivers must be updated before Memory Integrity will turn on."
  },
  "asr_rules_configured": {
    summary: "Configure Microsoft Defender Attack Surface Reduction (ASR) rules to block common malware exploitation pathways.",
    steps: ["Open Terminal (PowerShell Admin).", "Run the CLI command below to enable core ASR rules protecting against ransomware (blocking child processes from Office apps and blocking credential stealing)."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Open Terminal (PowerShell Admin).", "Run the CLI command below to enable core ASR rules protecting against ransomware (blocking child processes from Office apps and blocking credential stealing)."],
        cli: "Add-MpPreference -AttackSurfaceReductionRules_Ids 'd4f940ab-401b-4efc-aadc-ad5f3c50688a','be9ba2d9-53ea-44a7-9161-ab422405a9c6','92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' -AttackSurfaceReductionRules_Actions Enabled"
      },
      win10: {
        label: "Windows 10",
        gui: ["Open 'gpedit.msc' > Computer Configuration > Admin Templates > Windows Components > Microsoft Defender Antivirus > Attack Surface Reduction.", "Open 'Configure Attack Surface Reduction rules', set to Enabled, and add the rule GUIDs.", "Or run the PowerShell command directly as Administrator."],
        cli: "Add-MpPreference -AttackSurfaceReductionRules_Ids 'd4f940ab-401b-4efc-aadc-ad5f3c50688a','be9ba2d9-53ea-44a7-9161-ab422405a9c6','92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b' -AttackSurfaceReductionRules_Actions Enabled"
      },
      server: {
        label: "Windows Server",
        gui: ["Configure through Microsoft Intune / Defender for Endpoint security portal for fleet deployment.", "On standalone servers with Defender, run the PowerShell command below."],
        cli: "Add-MpPreference -AttackSurfaceReductionRules_Ids 'd4f940ab-401b-4efc-aadc-ad5f3c50688a','be9ba2d9-53ea-44a7-9161-ab422405a9c6' -AttackSurfaceReductionRules_Actions Enabled"
      },
    },
    verify: "Run 'Get-MpPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids' in PowerShell. Rule GUIDs must be listed.",
    caution: "In organizations with specialized Office macro add-ins, test ASR rules in Audit mode first to verify compatibility before enforcing."
  },
  "mock_attack_vss_enum_succeeded": {
    summary: "Active Validation Finding: The host permitted a WMI enumeration query against Volume Shadow Copies without behavioral alert or blocking.",
    steps: ["Open Windows Security > Virus & threat protection > Manage settings.", "Ensure 'Cloud-delivered protection' and 'Automatic sample submission' are active.", "Enable Defender behavioral monitoring and WMI event persistence blocking via the PowerShell CLI below."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Open Windows Security > Virus & threat protection > Manage settings.", "Ensure 'Cloud-delivered protection' and 'Automatic sample submission' are active.", "Enable Defender behavioral monitoring and WMI event persistence blocking via the PowerShell CLI below."],
        cli: "Set-MpPreference -DisableBehaviorMonitoring $false; Add-MpPreference -AttackSurfaceReductionRules_Ids 'e6db77e5-3df2-4cf1-b95a-63e5dd9f9353' -AttackSurfaceReductionRules_Actions Enabled"
      },
      win10: {
        label: "Windows 10",
        gui: ["Open Settings > Update & Security > Windows Security > Virus & threat protection > Manage settings.", "Verify Real-time protection is ON.", "Execute the PowerShell command below to ensure behavior monitoring is active."],
        cli: "Set-MpPreference -DisableBehaviorMonitoring $false; Add-MpPreference -AttackSurfaceReductionRules_Ids 'e6db77e5-3df2-4cf1-b95a-63e5dd9f9353' -AttackSurfaceReductionRules_Actions Enabled"
      },
      server: {
        label: "Windows Server",
        gui: ["In Microsoft Defender for Endpoint / third-party EDR, create an alert rule for suspicious discovery queries targeting Win32_ShadowCopy.", "Ensure behavioral monitoring is enabled on the server."],
        cli: "Set-MpPreference -DisableBehaviorMonitoring $false"
      },
    },
    verify: "Run '(Get-MpPreference).DisableBehaviorMonitoring' in PowerShell. It must return 'False'. Perform a rescan in R3P Agent.",
    caution: "The R3P check is a safe, read-only simulation. Do not disable WMI or Shadow Copy service to suppress this finding."
  },
  "mock_attack_mass_rename_succeeded": {
    summary: "Active Validation Finding: The host permitted rapid file renaming and extension modification in a short interval (the hallmark of live ransomware encryption).",
    steps: ["Open Settings (Win + I) > Privacy & security > Windows Security > Virus & threat protection.", "Scroll down to 'Ransomware protection' and click 'Manage ransomware protection'.", "Toggle 'Controlled folder access' to ON to block unauthorized applications from mass-altering files."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Open Settings (Win + I) > Privacy & security > Windows Security > Virus & threat protection.", "Scroll down to 'Ransomware protection' and click 'Manage ransomware protection'.", "Toggle 'Controlled folder access' to ON to block unauthorized applications from mass-altering files."],
        cli: "Set-MpPreference -EnableControlledFolderAccess Enabled"
      },
      win10: {
        label: "Windows 10",
        gui: ["Open Settings (Win + I) > Update & Security > Windows Security > Virus & threat protection.", "Click 'Manage ransomware protection'.", "Toggle 'Controlled folder access' to ON."],
        cli: "Set-MpPreference -EnableControlledFolderAccess Enabled"
      },
      server: {
        label: "Windows Server",
        gui: ["On Windows Server with Defender, enable Controlled folder access via PowerShell or deploy anti-ransomware heuristic policies through your central EDR console."],
        cli: "Set-MpPreference -EnableControlledFolderAccess Enabled"
      },
    },
    verify: "Run '(Get-MpPreference).EnableControlledFolderAccess' in PowerShell. It should return '1' (Enabled). Perform a rescan in R3P Agent.",
    caution: "Controlled folder access guards Documents, Pictures, and Desktop folders. Legitimate custom apps writing to these folders can be added via 'Add-MpPreference -ControlledFolderAccessAllowedApplications'."
  },
  "rdp_open": {
    summary: "Close or restrict exposed Remote Desktop Protocol (port 3389) to prevent automated brute-force and credential stuffing attacks.",
    steps: ["Open Settings (Win + I) and select System > Remote Desktop.", "Toggle the 'Remote Desktop' switch to OFF.", "Click Confirm when asked to disable Remote Desktop."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Open Settings (Win + I) and select System > Remote Desktop.", "Toggle the 'Remote Desktop' switch to OFF.", "Click Confirm when asked to disable Remote Desktop."],
        cli: "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 1; Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue"
      },
      win10: {
        label: "Windows 10",
        gui: ["Open Settings (Win + I) and select System > Remote Desktop.", "Toggle 'Enable Remote Desktop' to OFF.", "Click Confirm in the confirmation dialog."],
        cli: "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 1; Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue"
      },
      server: {
        label: "Windows Server",
        gui: ["Open Server Manager > Local Server.", "Click 'Enabled' next to Remote Desktop to open System Properties.", "Select 'Don't allow remote connections to this computer' and click OK (or run 'sconfig' and choose Option 7 > D)."],
        cli: "Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 1; Disable-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue"
      },
    },
    verify: "Run 'Test-NetConnection -ComputerName 127.0.0.1 -Port 3389' in PowerShell. 'TcpTestSucceeded' must be False.",
    caution: "Disabling RDP immediately drops active remote sessions. Only execute if you have physical or out-of-band console access. If RDP is needed, place it behind a VPN and require NLA."
  },
  "backup_configured": {
    summary: "Configure scheduled, resilient backups to provide a dependable fail-safe against total data loss during encryption events.",
    steps: ["Open Settings (Win + I) > System > Storage > Advanced storage settings > Backup options.", "Configure File History with an external hard drive or setup automatic OneDrive / enterprise cloud sync.", "Alternatively, deploy and schedule an approved enterprise backup agent (e.g. Veeam, Acronis)."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Open Settings (Win + I) > System > Storage > Advanced storage settings > Backup options.", "Configure File History with an external hard drive or setup automatic OneDrive / enterprise cloud sync.", "Alternatively, deploy and schedule an approved enterprise backup agent (e.g. Veeam, Acronis)."],
        cli: "Set-Service -Name 'fhsvc' -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service 'fhsvc' -ErrorAction SilentlyContinue"
      },
      win10: {
        label: "Windows 10",
        gui: ["Open Settings (Win + I) > Update & Security > Backup.", "Click 'Add a drive' under 'Back up using File History' and select a dedicated backup drive.", "Click 'More options' and verify backup frequency (e.g. Every hour or daily)."],
        cli: "Set-Service -Name 'fhsvc' -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service 'fhsvc' -ErrorAction SilentlyContinue"
      },
      server: {
        label: "Windows Server",
        gui: ["Open Server Manager > Manage > Add Roles and Features > Features > Check 'Windows Server Backup' > Install.", "Open Tools > Windows Server Backup ('wbadmin.msc').", "Click 'Backup Schedule Wizard' in the Actions pane and configure a daily automated backup to dedicated storage."],
        cli: "Install-WindowsFeature Windows-Server-Backup; Start-Service -Name 'wbengine' -ErrorAction SilentlyContinue"
      },
    },
    verify: "Run 'wbadmin get status' or inspect your backup software console to confirm recent successful backup jobs.",
    caution: "Ensure at least one backup tier is air-gapped, immutable, or stored offsite so attackers cannot delete backups prior to triggering ransomware."
  },
  "firewall_on": {
    summary: "Enable Windows Defender Firewall across Domain, Private, and Public profiles to block unauthorized inbound connections and scanning.",
    steps: ["Open Settings (Win + I) > Privacy & security > Windows Security > Firewall & network protection.", "Click on Domain network, Private network, and Public network.", "Toggle 'Microsoft Defender Firewall' to ON for all three profiles."],
    tabs: {
      win11: {
        label: "Windows 11",
        gui: ["Open Settings (Win + I) > Privacy & security > Windows Security > Firewall & network protection.", "Click on Domain network, Private network, and Public network.", "Toggle 'Microsoft Defender Firewall' to ON for all three profiles."],
        cli: "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"
      },
      win10: {
        label: "Windows 10",
        gui: ["Open Settings (Win + I) > Update & Security > Windows Security > Firewall & network protection.", "Click each profile (Domain, Private, Public) and toggle the firewall to ON."],
        cli: "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"
      },
      server: {
        label: "Windows Server",
        gui: ["Server Manager > Local Server > Click 'Windows Defender Firewall'.", "Click 'Turn Windows Defender Firewall on or off' in the left pane.", "Select 'Turn on Windows Defender Firewall' for all network locations and click OK."],
        cli: "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"
      },
    },
    verify: "Run 'Get-NetFirewallProfile | Select-Object Name, Enabled' in PowerShell. All three profiles must report Enabled: True.",
    caution: "Ensure required line-of-business services have specific inbound port allow rules before turning on the firewall to prevent connection drops."
  },
}

// ── MITRE ATT&CK Mapping ─────────────────────────────────────────────────────
export const MITRE_MAPPING = {
  smb_v1_enabled: { id: 'T1210', name: 'Exploitation of Remote Services', tactic: 'Initial Access' },
  rdp_enabled: { id: 'T1021.001', name: 'Remote Desktop Protocol', tactic: 'Lateral Movement' },
  autorun_enabled: { id: 'T1091', name: 'Replication via Removable Media', tactic: 'Initial Access' },
  open_network_shares: { id: 'T1021.002', name: 'SMB/Windows Admin Shares', tactic: 'Lateral Movement' },
  macro_execution_enabled: { id: 'T1204.002', name: 'Malicious File', tactic: 'Execution' },
  powershell_unrestricted: { id: 'T1059.001', name: 'PowerShell', tactic: 'Execution' },
  uac_disabled: { id: 'T1548.002', name: 'Bypass UAC', tactic: 'Privilege Escalation' },
  applocker_absent: { id: 'T1204', name: 'User Execution', tactic: 'Execution' },
  defender_disabled: { id: 'T1562.001', name: 'Disable or Modify Tools', tactic: 'Defense Evasion' },
  firewall_disabled: { id: 'T1562.004', name: 'Disable System Firewall', tactic: 'Defense Evasion' },
  tamper_protection_off: { id: 'T1562.001', name: 'Disable or Modify Tools', tactic: 'Defense Evasion' },
  event_logging_disabled: { id: 'T1562.002', name: 'Disable Event Logging', tactic: 'Defense Evasion' },
  admin_shares_enabled: { id: 'T1021.002', name: 'SMB/Windows Admin Shares', tactic: 'Lateral Movement' },
  lsass_protection_off: { id: 'T1003.001', name: 'LSASS Memory', tactic: 'Credential Access' },
  guest_account_active: { id: 'T1078.001', name: 'Default Accounts', tactic: 'Persistence' },
  vss_deleted: { id: 'T1490', name: 'Inhibit System Recovery', tactic: 'Impact' },
  backup_absent: { id: 'T1490', name: 'Inhibit System Recovery', tactic: 'Impact' },
  bitlocker_off: { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact' },
  always_install_elevated: { id: 'T1548.002', name: 'Bypass User Account Control', tactic: 'Privilege Escalation' },
  wdigest_enabled: { id: 'T1003.001', name: 'LSASS Memory', tactic: 'Credential Access' },
  laps_absent: { id: 'T1562', name: 'Impair Defenses', tactic: 'Defense Evasion' },
  nla_disabled: { id: 'T1021.001', name: 'Remote Desktop Protocol', tactic: 'Lateral Movement' },
  vulnerable_driver_blocklist_enabled: { id: 'T1068', name: 'Exploitation for Privilege Escalation', tactic: 'Privilege Escalation' },
  hvci_enabled: { id: 'T1562.001', name: 'Disable or Modify Tools', tactic: 'Defense Evasion' },
  asr_rules_configured: { id: 'T1562.001', name: 'Disable or Modify Tools', tactic: 'Defense Evasion' },
  mock_attack_vss_enum_succeeded: { id: 'T1490', name: 'Inhibit System Recovery (Mock)', tactic: 'Impact' },
  mock_attack_mass_rename_succeeded: { id: 'T1486', name: 'Data Encrypted for Impact (Mock)', tactic: 'Impact' },
}
