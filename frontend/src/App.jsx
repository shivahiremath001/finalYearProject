import { useState, useEffect, useRef, useCallback } from 'react'
import './App.css'

// ── API config ────────────────────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'

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
const PARAM_LABELS = {
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
}
const PARAM_SEVERITY = {
  smb_v1_enabled: 'CRITICAL', lsass_protection_off: 'CRITICAL',
  vss_deleted: 'CRITICAL', backup_absent: 'CRITICAL', bitlocker_off: 'CRITICAL',
  rdp_enabled: 'HIGH', macro_execution_enabled: 'HIGH',
  powershell_unrestricted: 'HIGH', defender_disabled: 'HIGH', firewall_disabled: 'HIGH',
  uac_disabled: 'MEDIUM', tamper_protection_off: 'MEDIUM',
  event_logging_disabled: 'MEDIUM', admin_shares_enabled: 'MEDIUM',
  open_network_shares: 'MEDIUM', guest_account_active: 'MEDIUM',
  autorun_enabled: 'LOW', applocker_absent: 'LOW',
}
const PARAM_DESCRIPTIONS = {
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
}

// ── MITRE ATT&CK Mapping ─────────────────────────────────────────────────────
const MITRE_MAPPING = {
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
          <span className="toast-icon">{t.type === 'anomaly' ? '⚠' : t.type === 'success' ? '✅' : 'ℹ'}</span>
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
  const cmap  = { CRITICAL:'#ef4444','HIGH RISK':'#f97316','LOW RISK':'#eab308', SAFE:'#10b981' }
  const col   = cmap[riskClass] || '#00e5ff'
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
        <span className="gauge-score" style={{color:col, textShadow: `0 0 12px ${col}66`}}>{score}</span>
        <span className="gauge-label">/100</span>
      </div>
    </div>
  )
}

// ── Risk Timeline Chart (Canvas-based) ────────────────────────────────────────
function RiskTimeline({ scoreHistory }) {
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

    // Clear
    ctx.clearRect(0, 0, w, h)

    // Grid lines (Subtle tactical map grid)
    ctx.strokeStyle = '#3f3f46'
    ctx.lineWidth = 1
    for (let i = 0; i <= 4; i++) {
      const y = pad.top + (ch / 4) * i
      ctx.beginPath()
      ctx.moveTo(pad.left, y)
      ctx.lineTo(w - pad.right, y)
      ctx.stroke()
      // Labels
      ctx.fillStyle = '#a1a1aa'
      ctx.font = '10px JetBrains Mono, monospace'
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

    // Line (Tech Cyan)
    ctx.beginPath()
    ctx.strokeStyle = '#00e5ff'
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
        // Normal dot — Tech Cyan
        ctx.beginPath()
        ctx.arc(p.x, p.y, 3, 0, Math.PI * 2)
        ctx.fillStyle = '#00e5ff'
        ctx.fill()
      }
    })

    // X-axis labels
    ctx.fillStyle = '#a1a1aa'
    ctx.font = '10px JetBrains Mono, monospace'
    ctx.textAlign = 'center'
    const indices = [0, Math.floor(n / 2), n - 1]
    indices.forEach(i => {
      if (scoreHistory[i]?.scanned_at) {
        const d = new Date(scoreHistory[i].scanned_at)
        const label = `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`
        ctx.fillText(label, points[i].x, h - 8)
      }
    })
  }, [scoreHistory])

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
        <span className="legend-item"><span className="legend-dot" style={{background:'#00e5ff'}} />Normal</span>
        <span className="legend-item"><span className="legend-dot legend-dot-anomaly" style={{background:'#ef4444', boxShadow: '0 0 8px #ef4444'}} />Anomaly</span>
      </div>
    </div>
  )
}

// ── Confirm Dialog ────────────────────────────────────────────────────────────
function ConfirmDialog({ message, onConfirm, onCancel }) {
  return (
    <div className="modal-overlay" onClick={onCancel}>
      <div className="confirm-dialog" onClick={e => e.stopPropagation()}>
        <div className="confirm-icon">⚠</div>
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
        <div className="login-logo">🛡</div>
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
function MachineDetail({ machine, token, onClose, liveData }) {
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

  const statusIcon = { pending: '⏳', executing: '⚙', done: '✅', failed: '❌' }
  const trendIcon = trend === 'up' ? '▲' : trend === 'down' ? '▼' : '='
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
            <button id="close-detail-btn" className="btn btn-ghost btn-sm" onClick={onClose}>✕ Close</button>
          </div>
        </div>

        {/* Anomaly Alert Banner */}
        {anomaly?.is_anomaly && (
          <div className="anomaly-alert">
            <div className="anomaly-alert-icon">⚠</div>
            <div className="anomaly-alert-body">
              <span className="anomaly-alert-title">Anomaly Detected</span>
              <span className="anomaly-alert-msg">
                Risk score deviated {anomaly.direction === 'spike' ? 'upward ↑' : 'downward ↓'} —
                Z-score: <strong>{anomaly.z_score?.toFixed(2)}</strong>
                {anomaly.rolling_mean != null && ` (mean: ${anomaly.rolling_mean.toFixed(1)}, σ: ${anomaly.rolling_std?.toFixed(1)})`}
              </span>
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
              <p className="anomaly-streak-label">🔥 Anomaly streak: {detail.anomaly_streak}</p>
            )}
          </div>
        </div>

        {/* Risk Timeline Chart */}
        {!loading && <RiskTimeline scoreHistory={detail?.score_history} />}

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
                    <span className="phase-name">⚔ {phase}</span>
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
                                  ⚡ Fix
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
            <span>✅</span>
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
function FleetOverview({ token, onLogout, username }) {
  const [machines, setMachines] = useState([])
  const [liveData, setLiveData] = useState({})
  const [selected, setSelected] = useState(null)
  const [wsStatus, setWsStatus] = useState('connecting')
  const [lastUpdate, setLastUpdate] = useState(null)
  const [sortField, setSortField] = useState('last_risk_score')
  const [sortDir, setSortDir] = useState('desc')
  const [searchQ, setSearchQ] = useState('')
  const [toasts, setToasts] = useState([])
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
  const wsIcon = { connected: '🟢', reconnecting: '🟡', error: '🔴', connecting: '⚪' }

  return (
    <div className="dashboard">
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />

      {/* Navbar */}
      <nav className="navbar">
        <div className="navbar-brand">
          <span className="brand-shield">🛡</span>
          <span className="brand-name">R3P</span>
          <span className="brand-sub">Admin Dashboard</span>
        </div>
        <div className="navbar-right">
          <span className="ws-status" title={`WebSocket: ${wsStatus}`}>{wsIcon[wsStatus]} Live Feed</span>
          {lastUpdate && <span className="last-update muted">Updated {timeSince(lastUpdate.toISOString())}</span>}
          <span className="admin-user">👤 {username}</span>
          <button id="logout-btn" className="btn btn-ghost btn-sm" onClick={onLogout}>Sign Out</button>
        </div>
      </nav>

      <div className="dashboard-body">
        {/* Stat Cards */}
        <div className="stat-cards">
          <div className="stat-card stat-card-total">
            <div className="stat-icon">🖥</div>
            <div className="stat-value">{stats.total}</div>
            <div className="stat-label">Total Machines</div>
          </div>
          <div className="stat-card stat-card-critical">
            <div className="stat-icon">🔴</div>
            <div className="stat-value">{stats.critical}</div>
            <div className="stat-label">Critical</div>
          </div>
          <div className="stat-card stat-card-high">
            <div className="stat-icon">🟠</div>
            <div className="stat-value">{stats.high}</div>
            <div className="stat-label">High Risk</div>
          </div>
          <div className="stat-card stat-card-low">
            <div className="stat-icon">🟡</div>
            <div className="stat-value">{stats.low}</div>
            <div className="stat-label">Low Risk</div>
          </div>
          <div className="stat-card stat-card-safe">
            <div className="stat-icon">🟢</div>
            <div className="stat-value">{stats.safe}</div>
            <div className="stat-label">Safe</div>
          </div>
        </div>

        {/* Fleet Table */}
        <div className="fleet-section">
          <div className="fleet-header">
            <h2 className="fleet-title">Fleet Overview</h2>
            <div className="fleet-controls">
              <input id="search-machines" type="text" className="search-input"
                placeholder="Search hostname or IP…"
                value={searchQ} onChange={e => setSearchQ(e.target.value)} />
              <button className="btn btn-ghost btn-sm" onClick={fetchMachines}>↻ Refresh</button>
            </div>
          </div>
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
                        {hasAnomaly && <span className="anomaly-indicator" title="Anomaly detected">⚠</span>}
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
                        {trend === 'up' ? <span className="trend-arrow trend-up">▲</span>
                          : trend === 'down' ? <span className="trend-arrow trend-down">▼</span>
                            : <span className="trend-arrow trend-stable">=</span>}
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
      </div>

      {selected && selectedMachine && (
        <MachineDetail
          machine={selectedMachine}
          token={token}
          onClose={() => setSelected(null)}
          liveData={liveData}
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
  return <FleetOverview token={token} username={username} onLogout={handleLogout} />
}
