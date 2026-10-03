import React, { useState, useEffect, useCallback } from 'react';
import { X, Plus, ChevronDown } from 'lucide-react';
import { API_BASE } from '../constants';

export default function PoliciesView({ token, target, onViewSystem, onClearTarget }) {
  const [policies, setPolicies] = useState([]);
  const [machines, setMachines] = useState([]);
  const [showModal, setShowModal] = useState(false);
  const [newPolicy, setNewPolicy] = useState({ hostname: '', param_key: 'smb_v1_enabled', reason: '' });
  const visiblePolicies = target
    ? policies.filter(p => p.hostname === target.hostname && p.param_key === target.param_key)
    : policies;

  const fetchPolicies = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/policies`, { headers: { Authorization: `Bearer ${token}` } });
      if (res.ok) {
        const data = await res.json();
        setPolicies(data);
      }
    } catch (e) { console.error(e); }
  }, [token]);

  const fetchMachines = useCallback(async () => {
    try {
      const res = await fetch(`${API_BASE}/machines`, { headers: { Authorization: `Bearer ${token}` } });
      if (res.ok) {
        const data = await res.json();
        setMachines(data);
        if (data.length > 0) setNewPolicy(p => ({ ...p, hostname: data[0].hostname }));
      }
    } catch (e) { console.error(e); }
  }, [token]);

  useEffect(() => {
    fetchPolicies();
    fetchMachines();
  }, [fetchPolicies, fetchMachines]);

  const handleDelete = async (id) => {
    try {
      await fetch(`${API_BASE}/policies/${id}`, { method: 'DELETE', headers: { Authorization: `Bearer ${token}` } });
      fetchPolicies();
    } catch (e) { console.error(e); }
  };

  const handleCreate = async (e) => {
    e.preventDefault();
    try {
      await fetch(`${API_BASE}/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify(newPolicy)
      });
      setShowModal(false);
      fetchPolicies();
    } catch (e) { console.error(e); }
  };

  return (
    <div className="view-container" style={{ display: 'flex', flexDirection: 'column', gap: 32 }}>
      <div className="main-header">
        <h1 className="page-title">Policy Exceptions</h1>
        <div className="fleet-controls">
          <button className="btn btn-primary btn-sm" onClick={() => setShowModal(true)}>
            <Plus size={16} /> Add Exception
          </button>
        </div>
      </div>

      {target && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, padding: '14px 18px', background: 'var(--overlay)', border: '1px solid var(--border2)', borderRadius: 12 }}>
          <div style={{ color: 'var(--subtle)', fontSize: 14 }}>
            Showing exception for <strong style={{ color: 'var(--text)' }}>{target.hostname}</strong> · <strong style={{ color: 'var(--text)' }}>{target.param_key}</strong>
          </div>
          <button className="btn btn-ghost btn-sm" onClick={onClearTarget}>Show all policies</button>
        </div>
      )}

      <div className="table-wrap">
        <table className="machine-table">
          <thead>
            <tr>
              <th>Hostname</th>
              <th>Ignored Parameter</th>
              <th>Reason</th>
              <th>Created</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {visiblePolicies.length === 0 ? (
              <tr><td colSpan="5" className="empty-row">{target ? 'No matching active policy exception was found.' : 'No active policy exceptions.'}</td></tr>
            ) : visiblePolicies.map(p => (
              <tr key={p.id} className="machine-row">
                <td className="hostname-cell">{p.hostname}</td>
                <td><span className="mitre-badge" style={{ margin: 0 }}>{p.param_key}</span></td>
                <td style={{ color: 'var(--subtle)', fontSize: 13 }}>{p.reason || 'No reason provided'}</td>
                <td style={{ color: 'var(--subtle)', fontSize: 13 }}>{new Date(p.created_at).toLocaleString()}</td>
                <td>
                  <button className="btn btn-ghost btn-sm" onClick={() => onViewSystem?.(p.hostname)} style={{ marginRight: 6 }}>
                    View system
                  </button>
                  <button className="btn btn-ghost btn-sm" onClick={() => handleDelete(p.id)} style={{ color: 'var(--critical)' }}>
                    Revoke
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {showModal && (
        <div className="detail-overlay">
          <div className="detail-panel" style={{ width: 500, height: 'auto', gap: 24 }}>
            <div className="detail-header">
              <h2 className="detail-hostname" style={{ fontSize: 24 }}>Add Exception</h2>
              <button className="btn-icon" onClick={() => setShowModal(false)}><X size={24} /></button>
            </div>
            <form onSubmit={handleCreate} className="login-form">
              <div className="field">
                <label>Target Machine</label>
                <div style={{ position: 'relative' }}>
                  <select value={newPolicy.hostname} onChange={e => setNewPolicy({...newPolicy, hostname: e.target.value})} className="search-input" style={{ width: '100%', background: 'var(--overlay)', cursor: 'pointer' }}>
                    {machines.map(m => (
                      <option key={m.hostname} value={m.hostname}>{m.hostname} ({m.ip_address})</option>
                    ))}
                  </select>
                  <ChevronDown size={16} color="var(--subtle)" style={{ position: 'absolute', right: 16, top: '50%', transform: 'translateY(-50%)', pointerEvents: 'none' }} />
                </div>
              </div>
              <div className="field">
                <label>Vulnerability Parameter</label>
                <div style={{ position: 'relative' }}>
                  <select value={newPolicy.param_key} onChange={e => setNewPolicy({...newPolicy, param_key: e.target.value})} className="search-input" style={{ width: '100%', background: 'var(--overlay)', cursor: 'pointer' }}>
                    <optgroup label="Entry Vector">
                    <option value="smb_v1_enabled">SMBv1 Enabled</option>
                    <option value="rdp_enabled">RDP Exposed</option>
                    <option value="autorun_enabled">AutoRun Enabled</option>
                    <option value="open_network_shares">Open Network Shares</option>
                    <option value="nla_disabled">RDP NLA Disabled</option>
                  </optgroup>
                  <optgroup label="Execution">
                    <option value="macro_execution_enabled">Macro Execution Enabled</option>
                    <option value="powershell_unrestricted">PowerShell Unrestricted</option>
                    <option value="uac_disabled">UAC Disabled</option>
                    <option value="applocker_absent">AppLocker Absent</option>
                    <option value="always_install_elevated">AlwaysInstallElevated Enabled</option>
                  </optgroup>
                  <optgroup label="Evasion & Persistence">
                    <option value="defender_disabled">Defender Disabled</option>
                    <option value="firewall_disabled">Firewall Disabled</option>
                    <option value="tamper_protection_off">Tamper Protection Off</option>
                    <option value="event_logging_disabled">Event Logging Disabled</option>
                    <option value="vulnerable_driver_blocklist_enabled">Vulnerable Driver Blocklist Disabled (BYOVD Risk)</option>
                    <option value="hvci_enabled">HVCI Memory Integrity Disabled</option>
                    <option value="asr_rules_configured">ASR Rules Not Configured</option>
                  </optgroup>
                  <optgroup label="Lateral Movement">
                    <option value="admin_shares_enabled">Admin Shares Enabled</option>
                    <option value="lsass_protection_off">LSASS Protection Off</option>
                    <option value="guest_account_active">Guest Account Active</option>
                    <option value="wdigest_enabled">WDigest Credentials Enabled</option>
                    <option value="laps_absent">LAPS Absent</option>
                  </optgroup>
                  <optgroup label="Recovery Prevention">
                    <option value="vss_deleted">VSS Deleted</option>
                    <option value="backup_absent">Backup Absent</option>
                    <option value="bitlocker_off">BitLocker Off</option>
                  </optgroup>
                  <optgroup label="Active Validation (Mock Attacks)">
                    <option value="mock_attack_vss_enum_succeeded">Failed Mock Attack: VSS Enumeration (Ransomware Behavior)</option>
                    <option value="mock_attack_mass_rename_succeeded">Failed Mock Attack: Mass File Rename (Ransomware Behavior)</option>
                  </optgroup>
                  </select>
                  <ChevronDown size={16} color="var(--subtle)" style={{ position: 'absolute', right: 16, top: '50%', transform: 'translateY(-50%)', pointerEvents: 'none' }} />
                </div>
              </div>
              <div className="field">
                <label>Business Justification (Reason)</label>
                <input type="text" value={newPolicy.reason} onChange={e => setNewPolicy({...newPolicy, reason: e.target.value})} placeholder="e.g. Legacy software requirement" />
              </div>
              <button type="submit" className="btn btn-primary" style={{ marginTop: 12 }}>Create Exception</button>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
