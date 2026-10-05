import React, { useState, useEffect } from 'react';
import { Zap, Server, Loader2, Search, BookOpen, ChevronDown, ChevronUp, ShieldCheck, Crosshair } from 'lucide-react';
import { API_BASE, PARAM_LABELS, PARAM_SEVERITY, SEVERITY_COLOR, MANUAL_FIX_GUIDES } from '../constants';
import ManualFixGuide from '../components/ManualFixGuide';

export default function RemediationView({ token }) {
  const [loading, setLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('ALL');
  const [expandedParam, setExpandedParam] = useState(null);

  const handleGlobalFix = async (commandKey) => {
    if (!window.confirm(`Are you sure you want to run ${commandKey} on ALL vulnerable machines?`)) return;
    setLoading(true);
    try {
      const res = await fetch(`${API_BASE}/commands/global`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ command_key: commandKey })
      });
      if (res.ok) {
        const data = await res.json();
        alert(`Success! Queued ${commandKey} for ${data.count} vulnerable machines.`);
      }
    } catch (e) {
      console.error(e);
      alert('Failed to execute global remediation.');
    }
    setLoading(false);
  };

  const automatedActions = [
    { key: 'disable_smb_v1', title: 'Disable SMBv1 Globally', desc: 'Finds all machines with SMBv1 enabled and queues a PowerShell fix to disable it.' },
    { key: 'disable_rdp', title: 'Disable RDP Globally', desc: 'Finds all machines with Remote Desktop exposed and disables it.' },
    { key: 'enable_defender', title: 'Enable Windows Defender', desc: 'Finds machines with Defender disabled and forces it back on.' },
    { key: 'enable_firewall', title: 'Enable Windows Firewall', desc: 'Finds machines with Firewall disabled and turns it on for all profiles.' },
  ];

  const categories = {
    'Entry Vector': ['smb_v1_enabled', 'rdp_enabled', 'autorun_enabled', 'open_network_shares', 'nla_disabled'],
    'Execution': ['macro_execution_enabled', 'powershell_unrestricted', 'uac_disabled', 'applocker_absent', 'always_install_elevated'],
    'Evasion & Persistence': ['defender_disabled', 'firewall_disabled', 'tamper_protection_off', 'event_logging_disabled', 'vulnerable_driver_blocklist_enabled', 'hvci_enabled', 'asr_rules_configured'],
    'Lateral Movement': ['admin_shares_enabled', 'lsass_protection_off', 'guest_account_active', 'wdigest_enabled', 'laps_absent'],
    'Resilience & Recovery': ['vss_deleted', 'backup_absent', 'bitlocker_off'],
    'Active Validation': ['mock_attack_vss_enum_succeeded', 'mock_attack_mass_rename_succeeded'],
  };

  const allParams = Object.keys(PARAM_LABELS);

  const filteredParams = allParams.filter(param => {
    const title = PARAM_LABELS[param] || param;
    const matchesSearch = title.toLowerCase().includes(searchQuery.toLowerCase()) || param.toLowerCase().includes(searchQuery.toLowerCase());
    if (!matchesSearch) return false;
    if (selectedCategory === 'ALL') return true;
    return categories[selectedCategory]?.includes(param);
  });

  return (
    <div className="view-container" style={{ display: 'flex', flexDirection: 'column', gap: 32 }}>
      <div className="main-header">
        <h1 className="page-title">Global Remediation Center</h1>
        <p style={{ color: 'var(--subtle)', marginTop: 8 }}>
          Execute one-click automated fixes across your fleet or browse comprehensive manual remediation playbooks for Windows 10, Windows 11, and Windows Server.
        </p>
      </div>

      {/* Fleet-wide one-click actions */}
      <div>
        <h2 style={{ fontSize: 18, color: 'var(--text)', marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
          <Zap size={20} color="var(--accent)" /> Automated Fleet-Wide Actions
        </h2>
        <div className="apple-widgets" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 20 }}>
          {automatedActions.map(action => (
            <div key={action.key} className="widget" style={{ padding: 24, gap: 16, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 8 }}>
                  <h3 style={{ fontSize: 16, color: 'var(--text)', margin: 0 }}>{action.title}</h3>
                  <div className="stat-icon" style={{ background: 'var(--overlay)', padding: 8, borderRadius: 8 }}>
                    <Server size={18} color="var(--accent)" />
                  </div>
                </div>
                <p style={{ fontSize: 13, color: 'var(--subtle)', lineHeight: 1.5, margin: 0 }}>{action.desc}</p>
              </div>
              
              <button 
                className="btn btn-primary" 
                style={{ width: '100%', display: 'flex', justifyContent: 'center', gap: 8, padding: '10px 14px', fontSize: 13 }}
                onClick={() => handleGlobalFix(action.key)}
                disabled={loading}
              >
                {loading ? <Loader2 size={16} className="spin" /> : <Zap size={16} />}
                Execute Fleet Fix
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Complete Manual Remediation Playbook Directory */}
      <div style={{ background: 'var(--card)', border: '1px solid var(--border2)', borderRadius: 16, padding: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 16, marginBottom: 20 }}>
          <div>
            <h2 style={{ fontSize: 18, color: 'var(--text)', margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
              <BookOpen size={20} color="var(--primary)" /> Multi-OS Manual Fix Directory ({filteredParams.length})
            </h2>
            <p style={{ fontSize: 13, color: 'var(--subtle)', margin: '4px 0 0 0' }}>
              Step-by-step GUI instructions, copyable PowerShell scripts, verification checks, and cautions across Windows 10, 11 &amp; Server.
            </p>
          </div>

          <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
            {/* Search Input */}
            <div style={{ position: 'relative', minWidth: 220 }}>
              <Search size={14} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--subtle)' }} />
              <input
                type="text"
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                placeholder="Search fix guides..."
                style={{
                  background: 'var(--overlay)',
                  border: '1px solid var(--border2)',
                  borderRadius: 8,
                  padding: '7px 12px 7px 32px',
                  color: 'var(--text)',
                  fontSize: 13,
                  width: '100%'
                }}
              />
            </div>

            {/* Category Filter */}
            <select
              value={selectedCategory}
              onChange={e => setSelectedCategory(e.target.value)}
              style={{
                background: 'var(--overlay)',
                border: '1px solid var(--border2)',
                borderRadius: 8,
                padding: '7px 12px',
                color: 'var(--text)',
                fontSize: 13,
                cursor: 'pointer'
              }}
            >
              <option value="ALL">All Kill-Chain Phases</option>
              {Object.keys(categories).map(cat => (
                <option key={cat} value={cat}>{cat}</option>
              ))}
            </select>
          </div>
        </div>

        {/* List of finding guides */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {filteredParams.length === 0 ? (
            <div style={{ textAlign: 'center', padding: 32, color: 'var(--subtle)' }}>
              No manual fix guides match your search.
            </div>
          ) : (
            filteredParams.map(param => {
              const isExpanded = expandedParam === param;
              const sev = PARAM_SEVERITY[param] || 'LOW';
              const label = PARAM_LABELS[param] || param;
              const guide = MANUAL_FIX_GUIDES[param];

              return (
                <div
                  key={param}
                  style={{
                    background: isExpanded ? 'var(--overlay)' : 'rgba(255, 255, 255, 0.02)',
                    border: '1px solid var(--border2)',
                    borderRadius: 10,
                    overflow: 'hidden',
                    transition: 'all 0.2s'
                  }}
                >
                  <div
                    onClick={() => setExpandedParam(isExpanded ? null : param)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '14px 18px',
                      cursor: 'pointer',
                      userSelect: 'none'
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                      <span className={`sev-badge ${SEVERITY_COLOR[sev]}`} style={{ fontSize: 10, padding: '3px 8px' }}>
                        {sev}
                      </span>
                      <strong style={{ color: 'var(--text)', fontSize: 14 }}>{label}</strong>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <span style={{ fontSize: 12, color: 'var(--primary)' }}>
                        {isExpanded ? 'Hide playbook' : 'View playbook'}
                      </span>
                      {isExpanded ? <ChevronUp size={16} color="var(--subtle)" /> : <ChevronDown size={16} color="var(--subtle)" />}
                    </div>
                  </div>

                  {isExpanded && (
                    <div style={{ padding: '0 18px 18px 18px', borderTop: '1px solid var(--border2)' }}>
                      <ManualFixGuide param={param} guide={guide} />
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
