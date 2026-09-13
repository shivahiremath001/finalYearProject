import React, { useState, useEffect } from 'react';
import { Shield, ShieldCheck, X, Plus } from 'lucide-react';
import { API_BASE } from '../App';

export default function PoliciesView({ token }) {
  const [policies, setPolicies] = useState([]);
  const [machines, setMachines] = useState([]);
  const [showModal, setShowModal] = useState(false);
  const [newPolicy, setNewPolicy] = useState({ hostname: '', param_key: 'smb_v1_enabled', reason: '' });

  const fetchPolicies = async () => {
    try {
      const res = await fetch(`${API_BASE}/policies`, { headers: { Authorization: `Bearer ${token}` } });
      if (res.ok) {
        const data = await res.json();
        setPolicies(data);
      }
    } catch (e) { console.error(e); }
  };

  const fetchMachines = async () => {
    try {
      const res = await fetch(`${API_BASE}/machines`, { headers: { Authorization: `Bearer ${token}` } });
      if (res.ok) {
        const data = await res.json();
        setMachines(data);
        if (data.length > 0) setNewPolicy(p => ({ ...p, hostname: data[0].hostname }));
      }
    } catch (e) { console.error(e); }
  };

  useEffect(() => {
    fetchPolicies();
    fetchMachines();
  }, [token]);

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
            {policies.length === 0 ? (
              <tr><td colSpan="5" className="empty-row">No active policy exceptions.</td></tr>
            ) : policies.map(p => (
              <tr key={p.id} className="machine-row">
                <td className="hostname-cell">{p.hostname}</td>
                <td><span className="mitre-badge" style={{ margin: 0 }}>{p.param_key}</span></td>
                <td style={{ color: 'var(--subtle)', fontSize: 13 }}>{p.reason || 'No reason provided'}</td>
                <td style={{ color: 'var(--subtle)', fontSize: 13 }}>{new Date(p.created_at).toLocaleString()}</td>
                <td>
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
                <select value={newPolicy.hostname} onChange={e => setNewPolicy({...newPolicy, hostname: e.target.value})} className="search-input" style={{ width: '100%', background: 'var(--overlay)' }}>
                  {machines.map(m => (
                    <option key={m.hostname} value={m.hostname}>{m.hostname} ({m.ip_address})</option>
                  ))}
                </select>
              </div>
              <div className="field">
                <label>Vulnerability Parameter</label>
                <select value={newPolicy.param_key} onChange={e => setNewPolicy({...newPolicy, param_key: e.target.value})} className="search-input" style={{ width: '100%', background: 'var(--overlay)' }}>
                  <option value="smb_v1_enabled">SMBv1 Enabled</option>
                  <option value="rdp_enabled">RDP Exposed</option>
                  <option value="defender_disabled">Defender Disabled</option>
                  <option value="firewall_disabled">Firewall Disabled</option>
                  <option value="admin_shares_enabled">Admin Shares Enabled</option>
                  <option value="wdigest_enabled">WDigest Credentials Enabled</option>
                  <option value="laps_absent">LAPS Absent</option>
                  <option value="nla_disabled">RDP NLA Disabled</option>
                  <option value="always_install_elevated">AlwaysInstallElevated Enabled</option>
                </select>
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
