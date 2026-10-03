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
  rdp_enabled: {
    steps: ['If Remote Desktop is required, do not disable it outright. Require Network Level Authentication, enforce MFA through an approved gateway, and restrict inbound access to a VPN or trusted management network.', 'If RDP is not required, coordinate an approved maintenance window and confirm you have another way to administer the device before disabling Remote Desktop in Settings → System → Remote Desktop or through managed Group Policy.', 'Review Windows Defender Firewall Remote Desktop rules and allow access only from approved management networks.'],
    verify: 'From an approved management host, confirm the intended RDP access works—or, if disabled, confirm port 3389 is no longer reachable and an alternate management path remains available.'
  },
  tamper_protection_off: {
    steps: ['On an unmanaged endpoint, open Windows Security → Virus & threat protection → Manage settings and turn on Tamper Protection.', 'For managed devices, configure Tamper Protection through Microsoft Defender for Endpoint or the organization’s Intune security policy. Centrally managed settings may override local changes.', 'Check that Defender real-time protection and other required protections are also enabled; Tamper Protection alone does not replace them.'],
    verify: 'Check Windows Security or the Defender management console after policy sync and confirm Tamper Protection is On. Run a new R3P scan.'
  },
  open_network_shares: {
    steps: ['On the endpoint, open Computer Management → System Tools → Shared Folders → Shares.', 'For each business-required share, open Properties → Share Permissions and remove Everyone or broad groups; grant only the users/groups that need access. Check the Security tab too, because both share and NTFS permissions apply.', 'If a share is not needed, stop sharing it from the Shares view. Do not remove administrative shares without checking remote-management dependencies.'],
    verify: 'From an elevated PowerShell prompt, review shares with Get-SmbShare and access with Get-SmbShareAccess -Name <ShareName>. Confirm only approved identities have access.'
  },
  macro_execution_enabled: {
    steps: ['In Microsoft 365 Apps, open File → Options → Trust Center → Trust Center Settings → Macro Settings.', 'Choose Disable VBA macros with notification, or the stricter setting required by your organization. Prefer centrally managed Office policy for fleet-wide enforcement.', 'If signed macros are required, publish an approved signing certificate and allow only trusted, signed macros; avoid broadly trusted folders.'],
    verify: 'Open the Trust Center Macro Settings page and confirm the enforced setting. If managed by policy, check the effective Office policy with your administrator.'
  },
  applocker_absent: {
    steps: ['On a supported Windows edition, open secpol.msc → Application Control Policies → AppLocker.', 'Create the default rules for Executable Rules first so Windows system files and administrators remain usable. Add publisher/path rules for required applications.', 'Set the rule collections to Audit only, review the AppLocker event log for blocked-use candidates, then change to Enforce rules after validating business applications. Deploy via Group Policy for managed fleets.'],
    verify: 'Review Applications and Services Logs → Microsoft → Windows → AppLocker and confirm the relevant rule collections are enforced. Test a known approved and unapproved application.'
  },
  admin_shares_enabled: {
    steps: ['First confirm that management, backup, and deployment tools do not depend on C$, ADMIN$, or other administrative shares.', 'Prefer restricting inbound SMB (TCP 445) to approved management hosts using Windows Defender Firewall or network controls.', 'If the organization explicitly requires disabling automatic administrative shares, deploy the appropriate AutoShareWks (client) or AutoShareServer (server) DWORD value under HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters, set to 0, through managed policy, then restart the Server service or reboot in a maintenance window.'],
    verify: 'Run Get-SmbShare and confirm the intended shares are absent or access is restricted. Verify approved remote administration and backup still work.'
  },
  vss_deleted: {
    steps: ['Open System Protection (run systempropertiesprotection.exe), select the system volume, choose Configure, and enable protection.', 'Set an appropriate maximum disk usage and create a restore point. For servers, configure an organization-approved backup/snapshot plan as well.', 'Previously deleted shadow copies cannot be recovered by re-enabling the service; establish new restore points and verify independent backups.'],
    verify: 'Run vssadmin list shadows and confirm current snapshots exist. Perform a controlled restore test according to your recovery procedure.'
  },
  backup_absent: {
    steps: ['Choose the organization-approved backup product or Windows Server Backup for supported server workloads.', 'Configure scheduled backups for required data and system state. Keep at least one copy isolated or immutable and restrict deletion rights from endpoint administrator accounts.', 'Document retention, encryption, and recovery ownership; do not count a configured job as protection until it has completed successfully.'],
    verify: 'Check the backup console for recent successful jobs, then perform a test restore to a safe location and record the result.'
  },
  bitlocker_off: {
    steps: ['Before enabling encryption, confirm the device supports BitLocker and ensure its recovery key will be escrowed to Microsoft Entra ID, Active Directory, or your approved key-management system.', 'For a managed device, deploy BitLocker settings using Intune or Group Policy, including the recovery-key backup requirement and approved encryption method.', 'On an individual device, use Control Panel → System and Security → BitLocker Drive Encryption → Turn on BitLocker, then follow the organization’s key-protection policy. Do not start encryption until recovery-key escrow is confirmed.'],
    verify: 'Run manage-bde -status C: and confirm Protection Status is Protection On. Confirm the recovery key is retrievable from the approved directory.'
  },
  laps_absent: {
    steps: ['Select Windows LAPS and the appropriate storage target: Microsoft Entra ID or Active Directory Domain Services.', 'Deploy the required Windows updates/schema preparation, grant the managed devices permission to update their LAPS passwords, and configure policy for password length, age, and backup directory.', 'Enable Windows LAPS through Intune or Group Policy, then rotate local administrator passwords. Remove shared/static local admin passwords from operational use.'],
    verify: 'Confirm LAPS policy is applied and a recent password backup timestamp appears in the selected directory. Test authorized retrieval using delegated access.'
  },
  mock_attack_vss_enum_succeeded: {
    steps: ['Review endpoint protection alerts and policy for the simulated Volume Shadow Copy enumeration behavior.', 'Configure the organization’s EDR/AV behavior protection to detect or block suspicious shadow-copy discovery and ransomware preparation, following the vendor’s guidance.', 'Rerun the authorized R3P validation scan after policy propagation; do not attempt to remediate by disabling legitimate backup or recovery services.'],
    verify: 'The next R3P validation should report the simulation as blocked. Review the EDR event to confirm the expected control produced the block.'
  },
  mock_attack_mass_rename_succeeded: {
    steps: ['Review endpoint protection alerts and policy for rapid file modification or mass-rename behavior.', 'Configure EDR/AV ransomware behavior protection and controlled-folder protections for the directories that need protection, using the vendor’s recommended policy.', 'Rerun the authorized R3P validation after policy propagation and confirm the simulation is contained without disrupting approved applications.'],
    verify: 'The next R3P validation should report the simulation as blocked. Confirm the EDR event identifies the expected ransomware behavior control.'
  }
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
