import React, { useState, useEffect } from 'react';
import { Zap, Server, Loader2 } from 'lucide-react';
import { API_BASE } from '../App';

export default function RemediationView({ token }) {
  const [machines, setMachines] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const fetchMachines = async () => {
      try {
        const res = await fetch(`${API_BASE}/machines`, { headers: { Authorization: `Bearer ${token}` } });
        if (res.ok) {
          const data = await res.json();
          setMachines(data);
        }
      } catch (e) { console.error(e); }
    };
    fetchMachines();
  }, [token]);

  // Aggregate issues
  // Since we only have the machine list (which doesn't include full scan data deeply), 
  // wait, the /machines endpoint returns `last_risk_class`, but we need parameter specifics to aggregate!
  // Let's just create a list of common commands and let the admin run them globally.
  // The backend already queries the latest scan to find who is vulnerable!
  
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

  const actions = [
    { key: 'disable_smb_v1', title: 'Disable SMBv1 Globally', desc: 'Finds all machines with SMBv1 enabled and queues a PowerShell fix to disable it.' },
    { key: 'disable_rdp', title: 'Disable RDP Globally', desc: 'Finds all machines with Remote Desktop exposed and disables it.' },
    { key: 'enable_defender', title: 'Enable Windows Defender', desc: 'Finds machines with Defender disabled and forces it back on.' },
    { key: 'enable_firewall', title: 'Enable Windows Firewall', desc: 'Finds machines with Firewall disabled and turns it on for all profiles.' },
  ];

  return (
    <div className="view-container" style={{ display: 'flex', flexDirection: 'column', gap: 32 }}>
      <div className="main-header">
        <h1 className="page-title">Global Remediation Center</h1>
        <p style={{ color: 'var(--subtle)', marginTop: 8 }}>Execute one-click fixes across your entire fleet. The engine will automatically find vulnerable machines and queue the command.</p>
      </div>

      <div className="apple-widgets" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }}>
        {actions.map(action => (
          <div key={action.key} className="widget" style={{ padding: 32, gap: 24 }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
              <div>
                <h3 style={{ fontSize: 18, color: 'var(--text)', marginBottom: 8 }}>{action.title}</h3>
                <p style={{ fontSize: 14, color: 'var(--subtle)', lineHeight: 1.5 }}>{action.desc}</p>
              </div>
              <div className="stat-icon" style={{ background: 'var(--overlay)', padding: 12, borderRadius: 12 }}>
                <Server size={24} color="var(--accent)" />
              </div>
            </div>
            
            <button 
              className="btn btn-primary" 
              style={{ width: '100%', display: 'flex', justifyContent: 'center', gap: 8, padding: '12px' }}
              onClick={() => handleGlobalFix(action.key)}
              disabled={loading}
            >
              {loading ? <Loader2 size={18} className="spin" /> : <Zap size={18} />}
              Execute Fleet Fix
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
