import React, { useState } from 'react';
import { Info, Target, BookOpen, List, ChevronDown, ChevronRight, CheckCircle2, Shield, Settings, Activity } from 'lucide-react';
import { PARAM_LABELS, PARAM_DESCRIPTIONS, PARAM_EXTENDED_INFO, MITRE_MAPPING } from '../App';

export default function AboutView() {
  const [activeTab, setActiveTab] = useState('purpose');
  const [openParam, setOpenParam] = useState(null);

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
          { id: 'params', label: 'Parameters', icon: <List size={16} /> }
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

      </div>
    </div>
  );
}
