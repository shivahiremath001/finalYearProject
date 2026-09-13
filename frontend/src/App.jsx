import { useState, useEffect, useRef, useCallback } from 'react'
import { 
  Shield, ShieldAlert, TriangleAlert, Info, ShieldCheck, Monitor, Clock, Settings, 
  CheckCircle2, XCircle, TrendingUp, TrendingDown, Minus, Circle, User, Zap, X, 
  Sun, Moon, Crosshair, AlertTriangle, HardDrive, Activity, Map, FileKey, LogOut
} from 'lucide-react'
import './App.css'

// Import New Views
import PoliciesView from './views/PoliciesView'
import RemediationView from './views/RemediationView'
import AnalyticsView from './views/AnalyticsView'
import NetworkMapView from './views/NetworkMapView'
import AboutView from './views/AboutView'

// ── API config ────────────────────────────────────────────────────────────────
export const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

// Add ngrok bypass header for all fetch requests (no-op when not using ngrok)
const FETCH_HEADERS = { 'ngrok-skip-browser-warning': 'true' }

const SEVERITY_COLOR = {
  CRITICAL: 'sev-critical',
  HIGH: 'sev-high',
  MEDIUM: 'sev-medium',
  LOW: 'sev-low',
}
const RISK_CLASS_COLOR = {
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
const PARAM_SEVERITY = {
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

function apiFetch(path, options = {}, token = null) {
  const headers = { 'Content-Type': 'application/json', ...FETCH_HEADERS, ...(options.headers || {}) }
  if (token) headers['Authorization'] = `Bearer ${token}`
  return fetch(`${API_BASE}${path}`, { ...options, headers })
}

function timeSince(isoStr) {
  if (!isoStr) return '—'
  const diff = (Date.now() - new Date(isoStr).getTime()) / 1000
  if (diff < 60) return `${Math.floor(diff)}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  return `${Math.floor(diff / 3600)}h ago`
}
function isStale(isoStr, s = 150) {
  if (!isoStr) return true
  return (Date.now() - new Date(isoStr).getTime()) / 1000 > s
}

// ── Toast Notification System ─────────────────────────────────────────────────
function ToastContainer({ toasts, onDismiss }) {
  return (
    <div className="toast-container">
      {toasts.map(t => (
        <div key={t.id} className={`toast toast-${t.type}`} onClick={() => onDismiss(t.id)}>
          <span className="toast-icon">{t.type === 'anomaly' ? <TriangleAlert size={24} /> : t.type === 'success' ? <CheckCircle2 size={24} /> : <Info size={24} />}</span>
          <div className="toast-body">
            <span className="toast-title">{t.title}</span>
            <span className="toast-msg">{t.message}</span>
          </div>
          <span className="toast-close" onClick={(e) => { e.stopPropagation(); onDismiss(t.id) }}>✕</span>
        </div>
      ))}
    </div>
  )
}

// ── Score Gauge ───────────────────────────────────────────────────────────────
function ScoreGauge({ score, riskClass }) {
  const r = 56, sw = 10, norm = r - sw/2, circ = 2 * Math.PI * norm
  const pct  = Math.min(100, Math.max(0, score)) / 100
  const dash  = pct * circ * 0.75
  const cmap  = { CRITICAL:'#ff453a','HIGH RISK':'#ff9f0a','LOW RISK':'#ffd60a', SAFE:'#30d158' }
  const col   = cmap[riskClass] || '#0a84ff'
  const cx    = r + sw/2, cy = r + sw/2

  return (
    <div className="gauge-wrap">
      <svg width={cx*2} height={cy*2} viewBox={`0 0 ${cx*2} ${cy*2}`}>
        <circle cx={cx} cy={cy} r={norm} fill="none" stroke="#3f3f46" strokeWidth={sw}
          strokeDasharray={`${circ*0.75} ${circ}`} strokeLinecap="round"
          transform={`rotate(135,${cx},${cy})`} />
        <circle cx={cx} cy={cy} r={norm} fill="none" stroke={col} strokeWidth={sw}
          strokeDasharray={`${dash} ${circ}`} strokeLinecap="round"
          style={{transition:'stroke-dasharray 0.8s ease', filter: `drop-shadow(0 0 8px ${col}66)`}}
          transform={`rotate(135,${cx},${cy})`} />
      </svg>
      <div className="gauge-center">
        <span className="gauge-score">{score}</span>
        <span className="gauge-label">/100</span>
      </div>
    </div>
  )
}

// ── Risk Timeline Chart (Canvas-based) ────────────────────────────────────────
function RiskTimeline({ scoreHistory, theme }) {
  const canvasRef = useRef(null)

  useEffect(() => {
    if (!scoreHistory || scoreHistory.length < 2) return
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    const dpr = window.devicePixelRatio || 1
    const w = canvas.clientWidth
    const h = canvas.clientHeight
    canvas.width = w * dpr
    canvas.height = h * dpr
    ctx.scale(dpr, dpr)

    const pad = { top: 20, right: 16, bottom: 30, left: 40 }
    const cw = w - pad.left - pad.right
    const ch = h - pad.top - pad.bottom
    const n = scoreHistory.length

    // Get computed theme colors for Canvas
    const style = getComputedStyle(document.documentElement)
    const gridColor = style.getPropertyValue('--border2').trim() || '#3f3f46'
    const textColor = style.getPropertyValue('--subtle').trim() || '#a1a1aa'

    // Clear
    ctx.clearRect(0, 0, w, h)

    // Grid lines (Subtle tactical map grid)
    ctx.strokeStyle = gridColor
    ctx.lineWidth = 1
    for (let i = 0; i <= 4; i++) {
      const y = pad.top + (ch / 4) * i
      ctx.beginPath()
      ctx.moveTo(pad.left, y)
      ctx.lineTo(w - pad.right, y)
      ctx.stroke()
      // Labels
      ctx.fillStyle = textColor
      ctx.font = '10px -apple-system, BlinkMacSystemFont, monospace'
      ctx.textAlign = 'right'
      ctx.fillText((100 - i * 25).toString(), pad.left - 8, y + 3)
    }

    // Data points
    const points = scoreHistory.map((s, i) => ({
      x: pad.left + (cw / (n - 1)) * i,
      y: pad.top + ch * (1 - s.score / 100),
      score: s.score,
      isAnomaly: s.is_anomaly,
      riskClass: s.risk_class,
    }))

    // Gradient fill under line (Tech Cyan)
    const gradient = ctx.createLinearGradient(0, pad.top, 0, pad.top + ch)
    gradient.addColorStop(0, 'rgba(0, 229, 255, 0.2)')
    gradient.addColorStop(1, 'rgba(0, 229, 255, 0.0)')
    ctx.beginPath()
    ctx.moveTo(points[0].x, pad.top + ch)
    points.forEach(p => ctx.lineTo(p.x, p.y))
    ctx.lineTo(points[points.length - 1].x, pad.top + ch)
    ctx.closePath()
    ctx.fillStyle = gradient
    ctx.fill()

    // Line (Apple Blue)
    ctx.beginPath()
    ctx.strokeStyle = '#0a84ff'
    ctx.lineWidth = 2
    ctx.lineJoin = 'round'
    points.forEach((p, i) => i === 0 ? ctx.moveTo(p.x, p.y) : ctx.lineTo(p.x, p.y))
    ctx.stroke()

    // Dots
    points.forEach(p => {
      if (p.isAnomaly) {
        // Anomaly dot — Critical Red Glow
        ctx.beginPath()
        ctx.arc(p.x, p.y, 6, 0, Math.PI * 2)
        ctx.fillStyle = 'rgba(239, 68, 68, 0.3)' // glow
        ctx.fill()
        ctx.beginPath()
        ctx.arc(p.x, p.y, 4, 0, Math.PI * 2)
        ctx.fillStyle = '#ef4444' // solid red
        ctx.fill()
      } else {
        // Normal dot — Apple Blue
        ctx.beginPath()
        ctx.arc(p.x, p.y, 3, 0, Math.PI * 2)
        ctx.fillStyle = '#0a84ff'
        ctx.fill()
      }
    })

    // X-axis labels
    ctx.fillStyle = textColor
    ctx.font = '10px -apple-system, BlinkMacSystemFont, monospace'
    ctx.textAlign = 'center'
    const indices = [0, Math.floor(n / 2), n - 1]
    indices.forEach(i => {
      if (scoreHistory[i]?.scanned_at) {
        const d = new Date(scoreHistory[i].scanned_at)
        const label = `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`
        ctx.fillText(label, points[i].x, h - 8)
      }
    })
  }, [scoreHistory, theme])

  if (!scoreHistory || scoreHistory.length < 2) {
    return <div className="timeline-empty muted">Waiting for more scans to render timeline…</div>
  }

  return (
    <div className="timeline-section">
      <h3 className="section-title">Risk Score Timeline</h3>
      <div className="timeline-chart-wrap">
        <canvas ref={canvasRef} className="timeline-canvas" />
      </div>
      <div className="timeline-legend">
        <span className="legend-item"><span className="legend-dot" style={{background:'#0a84ff'}} />Normal</span>
        <span className="legend-item"><span className="legend-dot legend-dot-anomaly" style={{background:'#ff453a'}} />Anomaly</span>
      </div>
    </div>
  )
}

// ── Confirm Dialog ────────────────────────────────────────────────────────────
function ConfirmDialog({ message, onConfirm, onCancel }) {
  return (
    <div className="modal-overlay" onClick={onCancel}>
      <div className="confirm-dialog" onClick={e => e.stopPropagation()}>
        <div className="confirm-icon"><TriangleAlert size={48} /></div>
        <p className="confirm-msg">{message}</p>
        <div className="confirm-actions">
          <button id="confirm-fix-btn" className="btn btn-danger" onClick={onConfirm}>Yes, Apply Fix</button>
          <button id="cancel-fix-btn" className="btn btn-ghost" onClick={onCancel}>Cancel</button>
        </div>
      </div>
    </div>
  )
}

// ── Login Page ────────────────────────────────────────────────────────────────
function LoginPage({ onLogin }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!username || !password) { setError('Please fill in both fields.'); return }
    setLoading(true); setError('')
    try {
      const res = await apiFetch('/admin/login', {
        method: 'POST', body: JSON.stringify({ username, password }),
      })
      if (res.ok) {
        const data = await res.json()
        onLogin(data.access_token, data.username)
      } else {
        const err = await res.json().catch(() => ({}))
        setError(err.detail || 'Login failed. Check credentials.')
      }
    } catch {
      setError('Cannot reach server. Is the backend running on ' + API_BASE + '?')
    } finally { setLoading(false) }
  }

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-logo"><Shield size={56} strokeWidth={1.5} /></div>
        <h1 className="login-title">R3P Admin</h1>
        <p className="login-sub">Ransomware Readiness &amp; Risk Profiler</p>
        <form className="login-form" onSubmit={handleSubmit}>
          <div className="field">
            <label htmlFor="username">Username</label>
            <input id="username" type="text" autoComplete="username"
              value={username} onChange={e => setUsername(e.target.value)}
              placeholder="admin" disabled={loading} />
          </div>
          <div className="field">
            <label htmlFor="password">Password</label>
            <input id="password" type="password" autoComplete="current-password"
              value={password} onChange={e => setPassword(e.target.value)}
              placeholder="••••••••" disabled={loading} />
          </div>
          {error && <div className="login-error">{error}</div>}
          <button type="submit" id="login-submit-btn" className="btn btn-primary btn-full" disabled={loading}>
            {loading ? 'Signing in…' : 'Sign In →'}
          </button>
        </form>
        <p className="login-hint">Default: admin / R3P-Admin-2025!</p>
      </div>
    </div>
  )
}

// ── Machine Detail Panel ──────────────────────────────────────────────────────
function MachineDetail({ machine, token, onClose, liveData, theme }) {
  const [detail, setDetail] = useState(null)       // from /machines/{h}/detail
  const [cmdHistory, setCmdHistory] = useState([])
  const [availCmds, setAvailCmds] = useState([])
  const [cmdState, setCmdState] = useState({})      // param_key → 'idle'|'sending'|'queued'
  const [confirm, setConfirm] = useState(null)
  const [loading, setLoading] = useState(true)
  const [histKey, setHistKey] = useState(0)
  const [expandedIssues, setExpandedIssues] = useState({})
  const hostname = machine.hostname

  // Merge DB detail with live WebSocket data
  const live = liveData[hostname]
  const score = live?.risk_score ?? detail?.risk_score ?? machine.last_risk_score
  const riskClass = live?.risk_class ?? detail?.risk_class ?? machine.last_risk_class
  const flagged = live?.flagged ?? detail?.flagged ?? {}
  const trend = live?.trend ?? detail?.trend
  const lastSeen = live?.timestamp ?? machine.last_seen
  const offline = isStale(lastSeen)
  const anomaly = live?.anomaly ?? detail?.anomaly

  // Load DB detail + available commands + history
  useEffect(() => {
    setLoading(true)
    Promise.all([
      apiFetch(`/machines/${encodeURIComponent(hostname)}/detail`, {}, token)
        .then(r => r.ok ? r.json() : null),
      apiFetch('/remediation/available', {}, token)
        .then(r => r.ok ? r.json() : []),
      apiFetch(`/commands/${encodeURIComponent(hostname)}/history?limit=20`, {}, token)
        .then(r => r.ok ? r.json() : []),
    ]).then(([det, cmds, hist]) => {
      setDetail(det)
      setAvailCmds(cmds)
      setCmdHistory(hist)
      // Pre-populate cmdState with existing queued/executing commands
      if (hist && cmds) {
        const active = {}
        hist.forEach(h => {
          if (h.status === 'pending' || h.status === 'executing') {
            const cmd = cmds.find(c => c.key === h.command_key)
            if (cmd) active[cmd.param_key] = 'queued'
          }
        })
        setCmdState(active)
      }
    }).finally(() => setLoading(false))
  }, [hostname, token, histKey])

  const handleFixClick = (paramKey) => {
    const cmd = availCmds.find(c => c.param_key === paramKey)
    if (!cmd) return
    setConfirm({ paramKey, commandKey: cmd.key, label: cmd.label })
  }

  const handleConfirm = async () => {
    const { paramKey, commandKey } = confirm
    setConfirm(null)
    setCmdState(s => ({ ...s, [paramKey]: 'sending' }))
    try {
      const res = await apiFetch(`/commands/${encodeURIComponent(hostname)}`, {
        method: 'POST', body: JSON.stringify({ command_key: commandKey }),
      }, token)
      if (res.ok) {
        setCmdState(s => ({ ...s, [paramKey]: 'queued' }))
        setHistKey(k => k + 1)
      } else {
        const err = await res.json().catch(() => ({}))
        alert('Error: ' + (err.detail || 'Could not queue command'))
        setCmdState(s => ({ ...s, [paramKey]: 'idle' }))
      }
    } catch {
      alert('Network error — could not reach backend')
      setCmdState(s => ({ ...s, [paramKey]: 'idle' }))
    }
  }

  const toggleExpand = (param) => {
    setExpandedIssues(prev => ({ ...prev, [param]: !prev[param] }))
  }

  const statusIcon = { pending: <Clock size={14} />, executing: <Settings size={14} />, done: <CheckCircle2 size={14} />, failed: <XCircle size={14} /> }
  const trendIcon = trend === 'up' ? <TrendingUp size={14} /> : trend === 'down' ? <TrendingDown size={14} /> : <Minus size={14} />
  const trendClass = trend === 'up' ? 'trend-up' : trend === 'down' ? 'trend-down' : 'trend-stable'
  const totalFlagged = Object.values(flagged).reduce((n, arr) => n + arr.length, 0)

  return (
    <div className="detail-overlay" onClick={onClose}>
      {confirm && (
        <ConfirmDialog
          message={`Apply fix "${confirm.label}" on ${hostname}?\n\nThe agent will execute the PowerShell script on its next poll cycle (~30s).`}
          onConfirm={handleConfirm}
          onCancel={() => setConfirm(null)}
        />
      )}
      <div className="detail-panel" onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div className="detail-header">
          <div>
            <h2 className="detail-hostname">{hostname}</h2>
            <p className="detail-meta">{machine.ip_address} · {machine.os_version || 'Unknown OS'}</p>
          </div>
          <div className="detail-header-right">
            <span className={`online-dot ${offline ? 'offline' : 'online'}`} />
            <span className={offline ? 'offline-text' : 'online-text'}>{offline ? 'Offline' : 'Live'}</span>
            <button id="close-detail-btn" className="btn btn-ghost btn-sm" onClick={onClose}><X size={16} style={{marginRight: 4, verticalAlign: 'text-bottom'}} /> Close</button>
          </div>
        </div>

        {/* Posture Drift Alert Banner */}
        {anomaly?.is_anomaly && (
          <div className="anomaly-alert">
            <div className="anomaly-alert-icon"><TriangleAlert size={28} /></div>
            <div className="anomaly-alert-body">
              <span className="anomaly-alert-title">Posture Drift Detected</span>
              <span className="anomaly-alert-msg">
                Risk score deviated {anomaly.direction === 'spike' ? 'upward ↑' : 'downward ↓'} —
                Z-score: <strong>{anomaly.z_score?.toFixed(2)}</strong>
                {anomaly.rolling_mean != null && ` (mean: ${anomaly.rolling_mean.toFixed(1)}, σ: ${anomaly.rolling_std?.toFixed(1)})`}
              </span>
              {detail?.posture_diff && (
                <div className="posture-diff-block" style={{marginTop: 8, padding: 8, background: 'rgba(0,0,0,0.2)', borderRadius: 4, fontFamily: 'monospace', fontSize: 12}}>
                  <strong>Configuration Changes:</strong><br/>
                  {detail.posture_diff.split('\n').map((line, i) => (
                    <div key={i} style={{color: line.startsWith('+') ? 'var(--critical)' : line.startsWith('-') ? 'var(--safe)' : 'inherit'}}>
                      {line}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Score + trend */}
        <div className="score-section">
          <ScoreGauge score={score} riskClass={riskClass} />
          <div className="score-info">
            <div className={`risk-badge ${RISK_CLASS_COLOR[riskClass] || ''}`}>{riskClass}</div>
            <div className="trend-row">
              <span className={`trend-arrow ${trendClass}`}>{trendIcon}</span>
              <span className="muted">vs previous scan</span>
            </div>
            <p className="score-num">{score} / 100</p>
            <p className="muted">{totalFlagged} misconfiguration{totalFlagged !== 1 ? 's' : ''} found</p>
            {detail?.scanned_at && <p className="muted">Scanned {timeSince(detail.scanned_at)}</p>}
            {detail?.anomaly_streak > 0 && (
              <p className="anomaly-streak-label">🔥 Posture drift streak: {detail.anomaly_streak}</p>
            )}
          </div>
        </div>

        {/* Risk Timeline Chart */}
        {!loading && <RiskTimeline scoreHistory={detail?.score_history} theme={theme} />}

        {loading && <div className="loading-row"><div className="skeleton skeleton-block" /><div className="skeleton skeleton-block" style={{ width: '70%' }} /></div>}

        {/* Kill-chain phase breakdown with Fix buttons + MITRE badges */}
        {!loading && totalFlagged > 0 && (
          <div className="phases-section">
            <h3 className="section-title">Misconfigurations by Kill-Chain Phase</h3>
            {Object.entries(flagged).map(([phase, params]) => {
              if (!params || params.length === 0) return null
              const worstSev = params.reduce((best, p) => {
                const s = PARAM_SEVERITY[p] || 'LOW'
                const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }
                return order[s] < order[best] ? s : best
              }, 'LOW')
              return (
                <div key={phase} className="phase-row">
                  <div className="phase-header">
                    <span className="phase-name"><Crosshair size={16} style={{marginRight: 8, verticalAlign: 'text-bottom'}} /> {phase}</span>
                    <span className={`sev-dot ${SEVERITY_COLOR[worstSev]}`} />
                    <span className="phase-count">{params.length} issue{params.length > 1 ? 's' : ''}</span>
                  </div>
                  <div className="phase-bar-wrap">
                    <div className="phase-bar-bg">
                      <div className={`phase-bar-fill ${SEVERITY_COLOR[worstSev]}`}
                        style={{ width: `${Math.min(100, params.length * 25)}%` }} />
                    </div>
                  </div>
                  <div className="issues-list">
                    {params.map(param => {
                      const sev = PARAM_SEVERITY[param] || 'LOW'
                      const fixCmd = availCmds.find(c => c.param_key === param)
                      const st = cmdState[param]
                      const mitre = MITRE_MAPPING[param]
                      const isExpanded = expandedIssues[param]
                      return (
                        <div key={param} className="issue-card" onClick={() => toggleExpand(param)}>
                          <div className="issue-left">
                            <span className={`sev-badge ${SEVERITY_COLOR[sev]}`}>{sev}</span>
                            <div className="issue-text">
                              <div className="issue-name-row">
                                <span className="issue-name">{PARAM_LABELS[param] || param.replace(/_/g, ' ')}</span>
                                {mitre && <span className="mitre-badge" title={`${mitre.name} — ${mitre.tactic}`}>{mitre.id}</span>}
                              </div>
                              {isExpanded && (
                                <div className="issue-expanded">
                                  <span className="issue-desc">{PARAM_DESCRIPTIONS[param] || ''}</span>
                                  {!fixCmd && (
                                    <div className="fix-area">
                                      {param.includes('mock_attack') ? (
                                        <p className="muted" style={{color: 'var(--critical)'}}>This is an active validation failure. You must investigate your EDR/AV policies to ensure they properly block ransomware behaviors.</p>
                                      ) : (
                                        <p className="muted">This issue must be remediated locally.</p>
                                      )}
                                    </div>
                                  )}
                                  {mitre && (
                                    <div className="mitre-detail">
                                      <span className="mitre-label">MITRE ATT&CK:</span>
                                      <span className="mitre-technique">{mitre.id} — {mitre.name}</span>
                                      <span className="mitre-tactic">Tactic: {mitre.tactic}</span>
                                    </div>
                                  )}
                                </div>
                              )}
                            </div>
                          </div>
                          <div className="issue-right" onClick={e => e.stopPropagation()}>
                            {fixCmd ? (
                              st === 'queued' ? (
                                <span className="fix-queued">⏳ Fix Queued</span>
                              ) : st === 'sending' ? (
                                <span className="fix-queued">Sending…</span>
                              ) : (
                                <button
                                  id={`fix-btn-${param}`}
                                  className="btn btn-fix"
                                  onClick={() => handleFixClick(param)}
                                >
                                  <Zap size={14} style={{verticalAlign: 'text-bottom'}} /> Fix
                                </button>
                              )
                            ) : (
                              <span className="no-fix muted">Manual fix</span>
                            )}
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </div>
              )
            })}
          </div>
        )}

        {!loading && totalFlagged === 0 && (
          <div className="all-clear">
            <span><ShieldCheck size={48} color="var(--safe)" /></span>
            <p>No misconfigurations detected — machine looks clean!</p>
          </div>
        )}

        {/* Remediation history */}
        <div className="cmd-history">
          <h3 className="section-title">Remediation Command History</h3>
          {cmdHistory.length === 0 ? (
            <p className="muted empty-history">No fix commands issued yet. Click "⚡ Fix" on any issue above to start.</p>
          ) : (
            <div className="cmd-table-wrap">
              <table className="cmd-table">
                <thead>
                  <tr><th>Command</th><th>Status</th><th>Issued</th><th>Completed</th><th>Output</th></tr>
                </thead>
                <tbody>
                  {cmdHistory.map(cmd => (
                    <tr key={cmd.id} className={`cmd-row cmd-${cmd.status}`}>
                      <td><code>{cmd.command_key}</code></td>
                      <td><span className={`status-badge status-${cmd.status}`}>{statusIcon[cmd.status] || '?'} {cmd.status}</span></td>
                      <td className="muted">{timeSince(cmd.issued_at)}</td>
                      <td className="muted">{cmd.completed_at ? timeSince(cmd.completed_at) : '—'}</td>
                      <td className="cmd-output" title={cmd.output || ''}>{cmd.output ? cmd.output.slice(0, 80) : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

      </div>
    </div>
  )
}

// ── Fleet Overview ────────────────────────────────────────────────────────────
function FleetOverview({ token, onLogout, username, theme, toggleTheme }) {
  const [machines, setMachines] = useState([])
  const [liveData, setLiveData] = useState({})
  const [selected, setSelected] = useState(null)
  const [wsStatus, setWsStatus] = useState('connecting')
  const [lastUpdate, setLastUpdate] = useState(null)
  const [sortField, setSortField] = useState('last_risk_score')
  const [sortDir, setSortDir] = useState('desc')
  const [searchQ, setSearchQ] = useState('')
  const [toasts, setToasts] = useState([])
  const [activeTab, setActiveTab] = useState('overview')
  const wsRef = useRef(null)
  const toastIdRef = useRef(0)

  const addToast = useCallback((type, title, message) => {
    const id = ++toastIdRef.current
    setToasts(prev => [...prev, { id, type, title, message }])
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 8000)
  }, [])

  const dismissToast = useCallback((id) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  const fetchMachines = useCallback(() => {
    apiFetch('/machines', {}, token)
      .then(r => r.ok ? r.json() : [])
      .then(data => { setMachines(data); setLastUpdate(new Date()) })
      .catch(() => { })
  }, [token])

  useEffect(() => { fetchMachines() }, [fetchMachines])

  // WebSocket
  useEffect(() => {
    const wsUrl = `${API_BASE.replace(/^http/, 'ws')}/ws/live?token=${token}&ngrok-skip-browser-warning=true`
    let retryTimer = null
    const connect = () => {
      try {
        const ws = new WebSocket(wsUrl)
        wsRef.current = ws
        ws.onopen = () => setWsStatus('connected')
        ws.onclose = () => {
          setWsStatus('reconnecting')
          retryTimer = setTimeout(connect, 4000)
        }
        ws.onerror = () => setWsStatus('error')
        ws.onmessage = (evt) => {
          try {
            const data = JSON.parse(evt.data)
            if (data.event === 'scan') {
              setLiveData(prev => ({ ...prev, [data.hostname]: data }))
              setLastUpdate(new Date())
              setMachines(prev => {
                const idx = prev.findIndex(m => m.hostname === data.hostname)
                if (idx === -1) { fetchMachines(); return prev }
                const updated = [...prev]
                updated[idx] = {
                  ...updated[idx],
                  last_risk_score: data.risk_score,
                  last_risk_class: data.risk_class,
                  last_seen: data.timestamp,
                }
                return updated
              })

              // Anomaly toast notification
              if (data.anomaly?.is_anomaly) {
                addToast(
                  'anomaly',
                  `Anomaly: ${data.hostname}`,
                  `Risk score ${data.anomaly.direction === 'spike' ? 'spiked ↑' : 'dropped ↓'} to ${data.risk_score} (z=${data.anomaly.z_score?.toFixed(2)})`
                )
              }
            }
          } catch { }
        }
      } catch { }
    }
    connect()
    return () => { wsRef.current?.close(); clearTimeout(retryTimer) }
  }, [token, fetchMachines, addToast])

  const stats = {
    total: machines.length,
    critical: machines.filter(m => m.last_risk_class === 'CRITICAL').length,
    high: machines.filter(m => m.last_risk_class === 'HIGH RISK').length,
    low: machines.filter(m => m.last_risk_class === 'LOW RISK').length,
    safe: machines.filter(m => m.last_risk_class === 'SAFE').length,
  }

  const sorted = [...machines]
    .filter(m => m.hostname.toLowerCase().includes(searchQ.toLowerCase()) || m.ip_address.includes(searchQ))
    .sort((a, b) => {
      const av = a[sortField] ?? '', bv = b[sortField] ?? ''
      return sortDir === 'asc' ? (av > bv ? 1 : -1) : (av < bv ? 1 : -1)
    })

  const toggleSort = (f) => {
    if (sortField === f) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortField(f); setSortDir('desc') }
  }

  const selectedMachine = machines.find(m => m.hostname === selected)
  const wsIcon = {
    connected: <Circle fill="var(--safe)" stroke="none" size={10} />,
    reconnecting: <Circle fill="var(--low)" stroke="none" size={10} />,
    error: <Circle fill="var(--critical)" stroke="none" size={10} />,
    connecting: <Circle fill="var(--subtle)" stroke="none" size={10} />
  }

  return (
    <div className="dashboard layout-apple">
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      {/* Sidebar */}
      <aside className="apple-sidebar">
        <div className="sidebar-brand">
          <Shield size={32} strokeWidth={1.5} className="brand-icon" />
          <div className="brand-text">
            <span className="brand-name">R3P Admin</span>
            <span className="brand-sub">Ransomware Readiness</span>
          </div>
        </div>

        <nav className="sidebar-nav">
          <div className={`nav-item ${activeTab === 'overview' ? 'active' : ''}`} onClick={() => setActiveTab('overview')}><Monitor size={18} /> Overview</div>
          <div className={`nav-item ${activeTab === 'map' ? 'active' : ''}`} onClick={() => setActiveTab('map')}><Map size={18} /> Network Map</div>
          <div className={`nav-item ${activeTab === 'analytics' ? 'active' : ''}`} onClick={() => setActiveTab('analytics')}><Activity size={18} /> Analytics</div>
          <div className={`nav-item ${activeTab === 'remediation' ? 'active' : ''}`} onClick={() => setActiveTab('remediation')}><Zap size={18} /> Remediation</div>
          <div className={`nav-item ${activeTab === 'policies' ? 'active' : ''}`} onClick={() => setActiveTab('policies')}><FileKey size={18} /> Policies</div>
          <div className={`nav-item ${activeTab === 'about' ? 'active' : ''}`} onClick={() => setActiveTab('about')}><Info size={18} /> About</div>
        </nav>

        <div className="sidebar-footer">
          <div className="status-row">
            <span className="ws-status" title={`WebSocket: ${wsStatus}`}>{wsIcon[wsStatus]} Live</span>
            {lastUpdate && <span className="last-update muted">{timeSince(lastUpdate.toISOString())}</span>}
          </div>
          
          <div className="theme-switch-row">
            <span className="muted" style={{fontWeight:500, fontSize:13}}>Theme</span>
            <div className="theme-switch" onClick={toggleTheme} title="Toggle Theme">
              <div className={`theme-switch-knob ${theme}`}></div>
            </div>
          </div>

          <div className="user-profile">
            <div className="avatar"><User size={18} /></div>
            <div className="user-info">
              <span className="user-name">{username}</span>
              <span className="user-role">Administrator</span>
            </div>
            <button id="logout-btn" className="btn-icon" onClick={onLogout} title="Sign Out"><LogOut size={16}/></button>
          </div>
        </div>
      </aside>

      <main className="dashboard-main">
        {activeTab === 'policies' && <PoliciesView token={token} />}
        {activeTab === 'remediation' && <RemediationView token={token} />}
        {activeTab === 'analytics' && <AnalyticsView token={token} />}
        {activeTab === 'map' && <NetworkMapView token={token} />}
        {activeTab === 'about' && <AboutView />}
        
        {activeTab === 'overview' && (
          <>
            <div className="main-header">
              <h1 className="page-title">Fleet Overview</h1>
              <div className="fleet-controls">
                <input id="search-machines" type="text" className="search-input"
                  placeholder="Search hostname or IP…"
                  value={searchQ} onChange={e => setSearchQ(e.target.value)} />
                <button className="btn btn-ghost btn-sm" onClick={fetchMachines}>↻ Refresh</button>
              </div>
            </div>

            <div className="apple-widgets">
              <div className="widget widget-hero">
                <div className="stat-header">
                  <div className="stat-label">Total Machines</div>
                  <div className="stat-icon"><Monitor size={18} /></div>
                </div>
                <div className="stat-value">{stats.total}</div>
              </div>
              <div className="widget">
                <div className="stat-header">
                  <div className="stat-label">Critical</div>
                  <div className="stat-icon"><ShieldAlert size={18} color="var(--critical)" /></div>
                </div>
                <div className="stat-value">{stats.critical}</div>
              </div>
              <div className="widget">
                <div className="stat-header">
                  <div className="stat-label">High Risk</div>
                  <div className="stat-icon"><TriangleAlert size={18} color="var(--high)" /></div>
                </div>
                <div className="stat-value">{stats.high}</div>
              </div>
              <div className="widget">
                <div className="stat-header">
                  <div className="stat-label">Low Risk</div>
                  <div className="stat-icon"><Info size={18} color="var(--low)" /></div>
                </div>
                <div className="stat-value">{stats.low}</div>
              </div>
              <div className="widget">
                <div className="stat-header">
                  <div className="stat-label">Safe</div>
                  <div className="stat-icon"><ShieldCheck size={18} color="var(--safe)" /></div>
                </div>
                <div className="stat-value">{stats.safe}</div>
              </div>
            </div>

            {/* Fleet Table */}
            <div className="fleet-section">
              <div className="table-wrap">
                <table className="machine-table">
                  <thead>
                    <tr>
                      <th></th>
                      <th className="sortable" onClick={() => toggleSort('hostname')}>
                        Hostname {sortField === 'hostname' ? (sortDir === 'asc' ? '↑' : '↓') : ''}
                      </th>
                      <th>IP Address</th>
                      <th>OS</th>
                      <th className="sortable" onClick={() => toggleSort('last_risk_score')}>
                        Risk Score {sortField === 'last_risk_score' ? (sortDir === 'asc' ? '↑' : '↓') : ''}
                      </th>
                      <th>Risk Class</th>
                      <th>Trend</th>
                      <th className="sortable" onClick={() => toggleSort('last_seen')}>
                        Last Seen {sortField === 'last_seen' ? (sortDir === 'asc' ? '↑' : '↓') : ''}
                      </th>
                      <th>Status</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {sorted.length === 0 && (
                      <tr><td colSpan={10} className="empty-row">
                        No machines registered yet. Run R3P_Agent.exe on a Windows machine and point it to this server.
                      </td></tr>
                    )}
                    {sorted.map(m => {
                      const live = liveData[m.hostname]
                      const score = live?.risk_score ?? m.last_risk_score
                      const cls = live?.risk_class ?? m.last_risk_class
                      const trend = live?.trend
                      const lastSeen = live?.timestamp || m.last_seen
                      const offline = isStale(lastSeen)
                      const hasAnomaly = live?.anomaly?.is_anomaly
                      return (
                        <tr key={m.hostname}
                          className={`machine-row ${selected === m.hostname ? 'machine-row-active' : ''}`}
                          onClick={() => setSelected(m.hostname)}>
                          <td><span className={`row-dot ${offline ? 'offline' : 'online'}`} /></td>
                          <td className="hostname-cell">
                            <strong>{m.hostname}</strong>
                            {hasAnomaly && <span className="anomaly-indicator" title="Posture drift detected"><TriangleAlert size={14} color="var(--critical)" style={{marginLeft: 8, verticalAlign: 'text-bottom'}} /></span>}
                          </td>
                          <td className="muted">{m.ip_address}</td>
                          <td className="muted os-cell">{m.os_version || '—'}</td>
                          <td>
                            <div className="score-bar-wrap">
                              <span className="score-num-sm">{score}</span>
                              <div className="score-bar-bg">
                                <div className={`score-bar-fill ${RISK_CLASS_COLOR[cls] || ''}`}
                                  style={{ width: `${score}%` }} />
                              </div>
                            </div>
                          </td>
                          <td><span className={`risk-badge-sm ${RISK_CLASS_COLOR[cls] || ''}`}>{cls}</span></td>
                          <td>
                            {trend === 'up' ? <span className="trend-arrow trend-up"><TrendingUp size={16} /></span>
                              : trend === 'down' ? <span className="trend-arrow trend-down"><TrendingDown size={16} /></span>
                                : <span className="trend-arrow trend-stable"><Minus size={16} /></span>}
                          </td>
                          <td className="muted">{timeSince(lastSeen)}</td>
                          <td><span className={offline ? 'offline-text' : 'online-text'}>{offline ? 'Offline' : 'Online'}</span></td>
                          <td>
                            <button id={`details-btn-${m.hostname}`} className="btn btn-ghost btn-sm"
                              onClick={e => { e.stopPropagation(); setSelected(m.hostname) }}>
                              Details →
                            </button>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}
      </main>

      {selected && selectedMachine && (
        <MachineDetail
          machine={selectedMachine}
          token={token}
          onClose={() => setSelected(null)}
          liveData={liveData}
          theme={theme}
        />
      )}
    </div>
  )
}

// ── Root App ──────────────────────────────────────────────────────────────────
export default function App() {
  // Use localStorage so token survives page reload
  const [token, setToken] = useState(() => localStorage.getItem('r3p_token') || '')
  const [username, setUsername] = useState(() => localStorage.getItem('r3p_user') || '')
  const [theme, setTheme] = useState(() => localStorage.getItem('r3p_theme') || 'dark')

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('r3p_theme', theme)
  }, [theme])

  const toggleTheme = () => setTheme(t => t === 'dark' ? 'light' : 'dark')

  const handleLogin = (tok, user) => {
    localStorage.setItem('r3p_token', tok)
    localStorage.setItem('r3p_user', user)
    setToken(tok); setUsername(user)
  }
  const handleLogout = () => {
    localStorage.removeItem('r3p_token')
    localStorage.removeItem('r3p_user')
    setToken(''); setUsername('')
  }

  if (!token) return <LoginPage onLogin={handleLogin} />
  return <FleetOverview token={token} username={username} onLogout={handleLogout} theme={theme} toggleTheme={toggleTheme} />
}
