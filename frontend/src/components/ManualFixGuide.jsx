import React, { useState } from 'react'
import { Copy, Check, Terminal, ShieldAlert, CheckCircle2, Monitor, AlertTriangle } from 'lucide-react'

export default function ManualFixGuide({ param, guide }) {
  const [activeOs, setActiveOs] = useState('win11')
  const [copied, setCopied] = useState(false)

  if (!guide) {
    return (
      <div className="manual-fix-empty">
        <p className="muted">No specific manual remediation guidance is available for this parameter.</p>
      </div>
    )
  }

  const tabs = guide.tabs || {
    win11: {
      label: 'Windows 11',
      gui: guide.steps || [],
      cli: ''
    }
  }

  const availableTabs = Object.keys(tabs)
  // Ensure activeOs exists in availableTabs
  const currentTabKey = tabs[activeOs] ? activeOs : availableTabs[0] || 'win11'
  const currentTab = tabs[currentTabKey] || { gui: [], cli: '' }

  const handleCopy = (text) => {
    if (!text) return
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }).catch(err => {
      console.error('Failed to copy text: ', err)
    })
  }

  return (
    <div className="manual-fix-container">
      {guide.summary && (
        <div className="manual-fix-summary">
          <p>{guide.summary}</p>
        </div>
      )}

      {/* OS Version Tabs */}
      <div className="manual-fix-os-tabs">
        {Object.entries(tabs).map(([osKey, osData]) => {
          const isActive = osKey === currentTabKey
          const icon = osKey === 'server' ? '🖥️' : '🪟'
          return (
            <button
              key={osKey}
              type="button"
              className={`manual-fix-os-tab ${isActive ? 'active' : ''}`}
              onClick={(e) => {
                e.stopPropagation()
                setActiveOs(osKey)
              }}
            >
              <span className="os-tab-icon">{icon}</span>
              <span className="os-tab-label">{osData.label || osKey.toUpperCase()}</span>
            </button>
          )
        })}
      </div>

      {/* Tab Content */}
      <div className="manual-fix-tab-content">
        {/* GUI Walkthrough */}
        <div className="manual-fix-section">
          <h4 className="manual-fix-subtitle">
            <Monitor size={15} style={{ verticalAlign: 'text-bottom', marginRight: 6, color: 'var(--primary)' }} />
            GUI Step-by-Step Walkthrough ({tabs[currentTabKey]?.label})
          </h4>
          <ol className="manual-fix-steps">
            {(currentTab.gui || []).map((step, index) => (
              <li key={index} className="manual-fix-step-item">
                <span className="step-num">{String(index + 1).padStart(2, '0')}</span>
                <span className="step-text">{step}</span>
              </li>
            ))}
          </ol>
        </div>

        {/* Quick CLI / PowerShell Command */}
        {currentTab.cli && (
          <div className="manual-fix-section">
            <div className="cli-header-row">
              <h4 className="manual-fix-subtitle">
                <Terminal size={15} style={{ verticalAlign: 'text-bottom', marginRight: 6, color: 'var(--accent)' }} />
                Quick CLI / PowerShell Fix (Run as Administrator)
              </h4>
              <button
                type="button"
                className={`btn btn-copy ${copied ? 'copied' : ''}`}
                onClick={(e) => {
                  e.stopPropagation()
                  handleCopy(currentTab.cli)
                }}
                title="Copy PowerShell command to clipboard"
              >
                {copied ? (
                  <>
                    <Check size={13} style={{ marginRight: 4 }} /> Copied!
                  </>
                ) : (
                  <>
                    <Copy size={13} style={{ marginRight: 4 }} /> Copy Command
                  </>
                )}
              </button>
            </div>
            <div className="cli-terminal-box">
              <div className="cli-terminal-prompt">PS C:\&gt;</div>
              <code className="cli-terminal-code">{currentTab.cli}</code>
            </div>
          </div>
        )}

        {/* Verification */}
        {guide.verify && (
          <div className="manual-fix-verify-card">
            <div className="verify-header">
              <CheckCircle2 size={16} color="var(--safe)" style={{ marginRight: 6 }} />
              <strong>How to Verify</strong>
            </div>
            <p className="verify-text">{guide.verify}</p>
          </div>
        )}

        {/* Caution / Admin Notes */}
        {guide.caution && (
          <div className="manual-fix-caution-card">
            <div className="caution-header">
              <AlertTriangle size={16} color="var(--warning)" style={{ marginRight: 6 }} />
              <strong>Important Caution &amp; Notes</strong>
            </div>
            <p className="caution-text">{guide.caution}</p>
          </div>
        )}
      </div>
    </div>
  )
}
