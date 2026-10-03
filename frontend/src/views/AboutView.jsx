import React, { useState } from 'react';
import { Target, BookOpen, List, ChevronDown, CheckCircle2, Shield, Settings, Activity, Calculator } from 'lucide-react';
import { PARAM_LABELS, PARAM_DESCRIPTIONS, PARAM_EXTENDED_INFO, MITRE_MAPPING, SCORING_SEVERITY, SCORING_LIKELIHOOD } from '../constants';

export default function AboutView() {
  const [activeTab, setActiveTab] = useState('purpose');
  const [openParam, setOpenParam] = useState(null);
  const [openScoreParam, setOpenScoreParam] = useState(null);

  const toggleParam = (key) => {
    if (openParam === key) setOpenParam(null);
    else setOpenParam(key);
  };

  return (
    <div className="view-container fade-in" style={{ padding: '40px', maxWidth: '900px', margin: '0 auto' }}>
      
      {/* Apple-style Header */}
      <div style={{ textAlign: 'center', marginBottom: '24px' }}>
        <div style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: '48px', height: '48px', borderRadius: '12px', background: 'linear-gradient(135deg, var(--primary), #5e5ce6)', boxShadow: '0 4px 10px rgba(0,0,0,0.15)', marginBottom: '12px' }}>
          <Shield size={24} color="white" strokeWidth={1.5} />
        </div>
        <h1 style={{ fontSize: '22px', fontWeight: '700', letterSpacing: '-0.5px', marginBottom: '4px' }}>About R3P</h1>
        <p className="muted" style={{ fontSize: '14px', maxWidth: '600px', margin: '0 auto' }}>
          Ransomware Readiness & Risk Profiler
        </p>
      </div>

      {/* Apple-style Segmented Control */}
      <div style={{ display: 'flex', background: 'var(--overlay)', padding: '4px', borderRadius: '12px', marginBottom: '32px', boxShadow: 'inset 0 1px 3px rgba(0,0,0,0.1)' }}>
        {[
          { id: 'purpose', label: 'Purpose', icon: <Target size={16} /> },
          { id: 'guide', label: 'Guide', icon: <BookOpen size={16} /> },
          { id: 'params', label: 'Parameters', icon: <List size={16} /> },
          { id: 'scoring', label: 'Scoring Logic', icon: <Calculator size={16} /> }
        ].map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            style={{
              flex: 1,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '8px',
              padding: '10px 0',
              border: 'none',
              background: activeTab === tab.id ? 'var(--surface)' : 'transparent',
              color: activeTab === tab.id ? 'var(--text)' : 'var(--subtle)',
              borderRadius: '8px',
              fontWeight: activeTab === tab.id ? '600' : '500',
              boxShadow: activeTab === tab.id ? '0 2px 5px rgba(0,0,0,0.1)' : 'none',
              cursor: 'pointer',
              transition: 'all 0.2s ease'
            }}
          >
            {tab.icon} {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div style={{ background: 'var(--surface)', borderRadius: '16px', padding: '32px', boxShadow: '0 4px 20px rgba(0,0,0,0.05)', border: '1px solid var(--border)' }}>
        
        {activeTab === 'purpose' && (
          <div className="slide-in">
            <h2 style={{ fontSize: '24px', fontWeight: '600', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Target size={24} color="var(--primary)" /> Project Purpose
            </h2>
            <div style={{ lineHeight: '1.7', fontSize: '15px', color: 'var(--subtle)' }}>
              <p style={{ marginBottom: '16px' }}>
                The <strong style={{color:'var(--text)'}}>Ransomware Readiness & Risk Profiler (R3P)</strong> is a continuous security monitoring platform. It assesses Windows endpoints against known ransomware exploit vectors and active threats, generating a quantified risk score and MITRE ATT&CK mapping.
              </p>
              <p style={{ marginBottom: '16px' }}>
                Instead of just checking configurations passively, R3P actively validates endpoint defenses using mock ransomware attacks (e.g., simulating VSS enumeration or mass file renames) to ensure your EDR/AV controls are truly effective.
              </p>
              <div style={{ background: 'var(--overlay)', padding: '16px', borderRadius: '12px', marginTop: '24px' }}>
                <h4 style={{ color: 'var(--text)', marginBottom: '12px' }}>Key Objectives:</h4>
                <ul style={{ listStyle: 'none', padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  <li style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
                    <CheckCircle2 size={18} color="var(--safe)" style={{ flexShrink: 0, marginTop: '2px' }} />
                    <span>Detect misconfigurations across the 5-phase Ransomware Kill-Chain.</span>
                  </li>
                  <li style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
                    <CheckCircle2 size={18} color="var(--safe)" style={{ flexShrink: 0, marginTop: '2px' }} />
                    <span>Alert administrators to sudden Posture Drift (statistical anomalies).</span>
                  </li>
                  <li style={{ display: 'flex', gap: '12px', alignItems: 'flex-start' }}>
                    <CheckCircle2 size={18} color="var(--safe)" style={{ flexShrink: 0, marginTop: '2px' }} />
                    <span>Enable secure, one-click remote remediation without allowing arbitrary code execution.</span>
                  </li>
                </ul>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'guide' && (
          <div className="slide-in">
            <h2 style={{ fontSize: '24px', fontWeight: '600', marginBottom: '24px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <BookOpen size={24} color="var(--primary)" /> Comprehensive Setup & Usage Guide
            </h2>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '20px' }}>
              {[
                { step: 1, title: 'Server Configuration', icon: <Settings size={18}/>, desc: 'Start the R3P FastAPI backend server and Vite frontend. Ensure the .env file contains your secure API_KEY and JWT_SECRET. The server uses an SQLite WAL database for high concurrency.' },
                { step: 2, title: 'Deploy Telemetry Agents', icon: <Shield size={18}/>, desc: 'Compile collector.py into an executable using PyInstaller. Distribute this agent to your Windows endpoints. It requires Administrator privileges to accurately query WMI, Registry, and Security center states.' },
                { step: 3, title: 'Continuous Monitoring', icon: <Activity size={18}/>, desc: 'Agents ping the server every 60 seconds with their current security posture. R3P calculates a weighted risk score (0-100) and tracks it over time. The React dashboard streams these updates live via WebSockets.' },
                { step: 4, title: 'Investigate Anomalies', icon: <Target size={18}/>, desc: 'R3P utilizes a rolling z-score algorithm to detect sudden drops or spikes in risk posture. If an attacker disables your firewall, R3P flags this as Posture Drift and alerts you immediately.' },
                { step: 5, title: 'Automated Remediation', icon: <CheckCircle2 size={18}/>, desc: 'Click on a vulnerable machine to view its Kill-Chain breakdown. Click the ⚡ Fix button to issue a secure string command to the endpoint. The agent will execute the approved PowerShell snippet to remediate the misconfiguration.' },
                { step: 6, title: 'Policy Exceptions', icon: <List size={18}/>, desc: 'If a machine requires a vulnerable configuration (e.g., an exposed RDP port for a legacy app), administrators can log a Policy Exception in the dashboard, providing an auditable business justification.' }
              ].map(item => (
                <div key={item.step} style={{ background: 'var(--overlay)', padding: '20px', borderRadius: '16px', border: '1px solid var(--border2)' }}>
                  <div style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: '32px', height: '32px', borderRadius: '50%', background: 'var(--primary)', color: 'white', fontWeight: '600', marginBottom: '12px' }}>
                    {item.step}
                  </div>
                  <h3 style={{ fontSize: '17px', fontWeight: '600', marginBottom: '8px', color: 'var(--text)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                    {item.icon} {item.title}
                  </h3>
                  <p style={{ fontSize: '14px', color: 'var(--subtle)', lineHeight: '1.6' }}>{item.desc}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {activeTab === 'params' && (
          <div className="slide-in">
            <h2 style={{ fontSize: '24px', fontWeight: '600', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <List size={24} color="var(--primary)" /> Security Parameters
            </h2>
            <p className="muted" style={{ marginBottom: '24px' }}>Click on a parameter to understand what it checks and why it is critical.</p>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {Object.entries(PARAM_DESCRIPTIONS).map(([key, desc], index) => {
                const isOpen = openParam === key;
                return (
                  <div 
                    key={key} 
                    style={{ 
                      background: isOpen ? 'var(--overlay)' : 'transparent', 
                      border: '1px solid var(--border2)', 
                      borderRadius: '12px', 
                      overflow: 'hidden',
                      transition: 'all 0.2s ease'
                    }}
                  >
                    <button 
                      onClick={() => toggleParam(key)}
                      style={{ 
                        width: '100%', 
                        padding: '16px 20px', 
                        display: 'flex', 
                        alignItems: 'center', 
                        justifyContent: 'space-between',
                        background: 'transparent',
                        border: 'none',
                        color: 'var(--text)',
                        fontWeight: '500',
                        fontSize: '15px',
                        cursor: 'pointer',
                        textAlign: 'left'
                      }}
                    >
                      <span>{index + 1}. {PARAM_LABELS[key] || key}</span>
                      <span style={{ 
                        transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)', 
                        transition: 'transform 0.2s ease',
                        color: 'var(--subtle)'
                      }}>
                        <ChevronDown size={20} />
                      </span>
                    </button>
                    
                    {/* Accordion Content */}
                    <div style={{ 
                      maxHeight: isOpen ? '400px' : '0', 
                      opacity: isOpen ? 1 : 0,
                      overflow: 'hidden',
                      transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
                      padding: isOpen ? '0 20px 16px 20px' : '0 20px',
                      color: 'var(--subtle)',
                      lineHeight: '1.6',
                      fontSize: '14px'
                    }}>
                      <div style={{ paddingTop: '8px', borderTop: '1px solid var(--border)' }}>
                        <p style={{ marginBottom: '16px', marginTop: '8px' }}>
                          {PARAM_EXTENDED_INFO[key] || desc}
                        </p>
                        
                        {MITRE_MAPPING[key] && (
                          <div style={{ background: 'var(--surface)', padding: '12px', borderRadius: '8px', border: '1px solid var(--border)', fontSize: '13px' }}>
                            <strong style={{ color: 'var(--text)', display: 'block', marginBottom: '6px' }}>MITRE ATT&CK Info:</strong>
                            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                              <span style={{ padding: '4px 8px', background: 'rgba(255,255,255,0.05)', borderRadius: '6px', border: '1px solid var(--border2)' }}>
                                <span style={{color: 'var(--subtle)', marginRight: '4px'}}>ID:</span>
                                <a href={`https://attack.mitre.org/techniques/${MITRE_MAPPING[key].id.split('.')[0]}`} target="_blank" rel="noreferrer" style={{color: 'var(--primary)', textDecoration: 'none', fontWeight: '600'}}>
                                  {MITRE_MAPPING[key].id}
                                </a>
                              </span>
                              <span style={{ padding: '4px 8px', background: 'rgba(255,255,255,0.05)', borderRadius: '6px', border: '1px solid var(--border2)' }}>
                                <span style={{color: 'var(--subtle)', marginRight: '4px'}}>Name:</span>
                                <span style={{color: 'var(--text)'}}>{MITRE_MAPPING[key].name}</span>
                              </span>
                              <span style={{ padding: '4px 8px', background: 'rgba(255,255,255,0.05)', borderRadius: '6px', border: '1px solid var(--border2)' }}>
                                <span style={{color: 'var(--subtle)', marginRight: '4px'}}>Tactic:</span>
                                <span style={{color: 'var(--text)'}}>{MITRE_MAPPING[key].tactic}</span>
                              </span>
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {activeTab === 'scoring' && (
          <div className="slide-in">
            <h2 style={{ fontSize: '24px', fontWeight: '600', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Calculator size={24} color="var(--primary)" /> How the risk score works
            </h2>
            <p className="muted" style={{ marginBottom: '24px', lineHeight: '1.6' }}>
              R3P scores each endpoint from 0 to 100. The score combines the security checks that failed with how severe and likely each risk is, then adjusts for the importance of the asset.
            </p>

            <div style={{ background: 'var(--overlay)', border: '1px solid var(--border2)', borderRadius: '12px', padding: '20px', marginBottom: '20px' }}>
              <h3 style={{ color: 'var(--text)', fontSize: '16px', marginBottom: '12px' }}>The formula</h3>
              <div style={{ color: 'var(--text)', fontFamily: 'ui-monospace, SFMono-Regular, Consolas, monospace', fontSize: '14px', lineHeight: '1.8', overflowWrap: 'anywhere' }}>
                Check contribution = Severity × Likelihood × Asset criticality<br />
                Score = min(100, total contributions ÷ 80.3 × 100)
              </div>
              <p style={{ color: 'var(--subtle)', fontSize: '13px', lineHeight: '1.6', marginTop: '12px', marginBottom: 0 }}>
                The denominator, 80.3, is the maximum combined Severity × Likelihood for all 27 checks at workstation criticality. This keeps the baseline score on a comparable 0–100 scale.
              </p>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px', marginBottom: '20px' }}>
              {[
                { title: 'Severity (1–5)', text: 'How much damage the weakness could cause. Higher severity adds more risk.' },
                { title: 'Likelihood (0.1–1.0)', text: 'How commonly the risk is associated with real-world ransomware activity. Higher likelihood adds more risk.' },
                { title: 'Asset criticality', text: 'Workstation = 1.0, Server = 1.3, Domain Controller = 1.6. More critical assets receive higher scores for the same findings.' }
              ].map(item => (
                <div key={item.title} style={{ background: 'var(--overlay)', border: '1px solid var(--border2)', borderRadius: '12px', padding: '16px' }}>
                  <h3 style={{ color: 'var(--text)', fontSize: '15px', marginBottom: '8px' }}>{item.title}</h3>
                  <p style={{ color: 'var(--subtle)', fontSize: '13px', lineHeight: '1.6', margin: 0 }}>{item.text}</p>
                </div>
              ))}
            </div>

            <div style={{ marginBottom: '20px' }}>
              <h3 style={{ color: 'var(--text)', fontSize: '16px', marginBottom: '12px' }}>Risk bands and escalation rules</h3>
              <div style={{ display: 'grid', gap: '8px' }}>
                {[
                  ['0–24.99', 'SAFE'], ['25–49.99', 'LOW RISK'], ['50–74.99', 'HIGH RISK'], ['75–100', 'CRITICAL']
                ].map(([range, label]) => (
                  <div key={label} style={{ display: 'flex', justifyContent: 'space-between', gap: '12px', padding: '11px 14px', borderRadius: '9px', background: 'var(--overlay)', color: 'var(--subtle)', fontSize: '14px' }}>
                    <span>{range} score</span><strong style={{ color: 'var(--text)' }}>{label}</strong>
                  </div>
                ))}
              </div>
              <p style={{ color: 'var(--subtle)', fontSize: '13px', lineHeight: '1.6', marginTop: '12px' }}>
                A successful mock attack sets the effective score to at least 75, so the number and CRITICAL label agree. The underlying weighted findings are still available in the parameter explanations. Any failed check with severity 5 raises the classification to at least HIGH RISK.
              </p>
            </div>

            <div style={{ background: 'var(--overlay)', border: '1px solid var(--border2)', borderRadius: '12px', padding: '16px' }}>
              <h3 style={{ color: 'var(--text)', fontSize: '15px', marginBottom: '8px' }}>Example</h3>
              <p style={{ color: 'var(--subtle)', fontSize: '13px', lineHeight: '1.6', margin: 0 }}>
                If a workstation has a failed check with severity 4 and likelihood 0.9, it adds 3.6 raw risk points (4 × 0.9 × 1.0). The contributions from all failed checks are summed and normalized. The dashboard also surfaces the largest individual contributors to help explain what is driving a result.
              </p>
            </div>

            <div style={{ marginTop: '28px' }}>
              <h3 style={{ color: 'var(--text)', fontSize: '18px', marginBottom: '8px' }}>Parameter-by-parameter scoring</h3>
              <p style={{ color: 'var(--subtle)', fontSize: '13px', lineHeight: '1.6', marginBottom: '16px' }}>
                Expand any check to see what it measures, when it counts as a failure, its exact backend weights, and the raw points it contributes when failed. “Raw contribution” is before the final normalization to 0–100.
              </p>
              {[
                { phase: 'Entry Vector', keys: ['smb_v1_enabled', 'rdp_enabled', 'autorun_enabled', 'open_network_shares', 'nla_disabled'] },
                { phase: 'Execution', keys: ['macro_execution_enabled', 'powershell_unrestricted', 'uac_disabled', 'applocker_absent', 'always_install_elevated'] },
                { phase: 'Evasion & Persistence', keys: ['defender_disabled', 'firewall_disabled', 'tamper_protection_off', 'event_logging_disabled', 'vulnerable_driver_blocklist_enabled', 'hvci_enabled', 'asr_rules_configured'] },
                { phase: 'Lateral Movement', keys: ['admin_shares_enabled', 'lsass_protection_off', 'guest_account_active', 'wdigest_enabled', 'laps_absent'] },
                { phase: 'Recovery Prevention', keys: ['vss_deleted', 'backup_absent', 'bitlocker_off'] },
                { phase: 'Active Validation (Mock Attacks)', keys: ['mock_attack_vss_enum_succeeded', 'mock_attack_mass_rename_succeeded'] }
              ].map(({ phase, keys }) => (
                <section key={phase} style={{ marginBottom: '18px' }}>
                  <h4 style={{ color: 'var(--text)', fontSize: '14px', fontWeight: '600', marginBottom: '8px' }}>{phase}</h4>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '7px' }}>
                    {keys.map(key => {
                      const isOpen = openScoreParam === key;
                      const severity = SCORING_SEVERITY[key];
                      const likelihood = SCORING_LIKELIHOOD[key];
                      const explanation = PARAM_EXTENDED_INFO[key] || PARAM_DESCRIPTIONS[key] || 'This security posture check contributes to the endpoint risk score when it fails.';
                      const failureMeaning = key === 'rdp_enabled'
                        ? 'RDP is reported as open (collector field: rdp_open).'
                        : key === 'firewall_disabled'
                          ? 'The collector reports the firewall as off (firewall_on is false).'
                          : key === 'backup_absent'
                            ? 'The collector reports that backup is not configured (backup_configured is false).'
                            : key === 'vulnerable_driver_blocklist_enabled' || key === 'hvci_enabled' || key === 'asr_rules_configured'
                              ? 'The corresponding protection is not enabled or configured; the backend inverts the collector’s enabled/configured state before scoring.'
                              : key.startsWith('mock_attack_')
                                ? 'The simulated behavior was not blocked. If the test did not run (result is null), this check is not counted as failed.'
                                : 'The collector reports the risky state named by this check (for example, “disabled” or “enabled” in the label).';
                      return (
                        <div key={key} style={{ border: '1px solid var(--border2)', borderRadius: '10px', overflow: 'hidden', background: isOpen ? 'var(--overlay)' : 'transparent' }}>
                          <button
                            type="button"
                            aria-expanded={isOpen}
                            onClick={() => setOpenScoreParam(isOpen ? null : key)}
                            style={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px', padding: '13px 15px', border: 'none', background: 'transparent', color: 'var(--text)', textAlign: 'left', cursor: 'pointer' }}
                          >
                            <span style={{ fontSize: '14px', fontWeight: '500' }}>{PARAM_LABELS[key] || key}</span>
                            <span style={{ display: 'flex', alignItems: 'center', gap: '10px', flexShrink: 0, color: 'var(--subtle)', fontSize: '12px' }}>
                              S {severity} · L {likelihood}
                              <ChevronDown size={17} style={{ transform: isOpen ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s ease' }} />
                            </span>
                          </button>
                          {isOpen && (
                            <div style={{ padding: '0 15px 15px', color: 'var(--subtle)', fontSize: '13px', lineHeight: '1.65' }}>
                              <p style={{ paddingTop: '12px', borderTop: '1px solid var(--border)', margin: '0 0 10px' }}>{explanation}</p>
                              <p style={{ margin: '0 0 8px' }}><strong style={{ color: 'var(--text)' }}>When it is scored:</strong> {failureMeaning}</p>
                              <p style={{ margin: 0 }}>
                                <strong style={{ color: 'var(--text)' }}>Weights and points:</strong> Severity {severity} × Likelihood {likelihood} × asset multiplier. This adds <strong style={{ color: 'var(--text)' }}>{(severity * likelihood).toFixed(2)} raw points</strong> on a workstation, {(severity * likelihood * 1.3).toFixed(2)} on a server, or {(severity * likelihood * 1.6).toFixed(2)} on a domain controller. A passing check adds 0 points.
                              </p>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </section>
              ))}
              <p style={{ color: 'var(--subtle)', fontSize: '12px', lineHeight: '1.6', marginTop: '12px' }}>
                The displayed Severity and Likelihood values are the scoring engine’s exact weights. They are model inputs, not a live probability that an attack will occur. For active validation, a mock test that was not run is treated as unfailed rather than as a pass or failure.
              </p>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
