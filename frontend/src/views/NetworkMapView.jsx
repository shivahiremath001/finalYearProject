import React, { useState, useEffect, useRef } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { API_BASE } from '../constants';

export default function NetworkMapView({ token, onViewSystem }) {
  const [rawMachines, setRawMachines] = useState([]);
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });
  const [selectedNode, setSelectedNode] = useState(null);
  const [viewMode, setViewMode] = useState('default'); // 'default', 'heatmap', 'isolate'
  const containerRef = useRef();
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });

  useEffect(() => {
    if (containerRef.current) {
      setDimensions({
        width: containerRef.current.clientWidth,
        height: containerRef.current.clientHeight
      });
    }
  }, []);

  useEffect(() => {
    const fetchMachines = async () => {
      try {
        const res = await fetch(`${API_BASE}/machines`, { headers: { Authorization: `Bearer ${token}` } });
        if (res.ok) {
          const machines = await res.json();
          setRawMachines(machines);
        }
      } catch (e) { console.error(e); }
    };
    fetchMachines();
  }, [token]);

  useEffect(() => {
    if (!rawMachines || rawMachines.length === 0) return;

    let filteredMachines = rawMachines;
    if (viewMode === 'isolate') {
      filteredMachines = rawMachines.filter(m => m.last_risk_class !== 'SAFE');
    }

    const nodes = [];
    const links = [];

    // Root node
    nodes.push({ id: 'root', name: 'Corporate Network', val: 10, color: '#0a84ff', type: 'root' });

    const subnets = {};
    filteredMachines.forEach(m => {
      const parts = m.ip_address.split('.');
      if (parts.length === 4) {
        const subnet = `${parts[0]}.${parts[1]}.${parts[2]}.x`;
        if (!subnets[subnet]) {
          subnets[subnet] = true;
          nodes.push({ id: subnet, name: `Subnet: ${subnet}`, val: 5, color: 'rgba(255,255,255,0.4)', type: 'subnet' });
          links.push({ source: 'root', target: subnet });
        }
        
        // Compute Color
        let mColor = '#34c759'; // Apple Green (SAFE)
        if (m.status !== 'ONLINE') {
          mColor = 'rgba(150, 150, 150, 0.4)'; // Dim offline machines
        } else if (viewMode === 'heatmap') {
          // Heatmap: Green to Red gradient based on numeric score
          const g = Math.max(0, 255 - (m.last_risk_score * 2.5));
          const r = Math.min(255, m.last_risk_score * 3);
          mColor = `rgb(${r}, ${g}, 50)`;
        } else {
          if (m.last_risk_class === 'CRITICAL') mColor = '#ff3b30'; // Apple Red
          else if (m.last_risk_class === 'HIGH RISK') mColor = '#ff9500'; // Apple Orange
          else if (m.last_risk_class === 'LOW RISK') mColor = '#ffcc00'; // Apple Yellow
        }

        // Geometry Selection based on float value
        let shape = 'circle';
        if (m.asset_criticality >= 1.6) shape = 'diamond';
        else if (m.asset_criticality >= 1.3) shape = 'square';

        nodes.push({ 
          id: m.hostname, 
          name: m.hostname, 
          val: m.asset_criticality >= 1.6 ? 9 : (m.asset_criticality >= 1.3 ? 6.5 : 4.5), 
          color: mColor,
          type: 'machine',
          shape: shape,
          machineData: m
        });
        links.push({ source: subnet, target: m.hostname });
      }
    });

    setGraphData({ nodes, links });
  }, [rawMachines, viewMode]);

  const handleNodeClick = (node) => {
    if (node && node.type === 'machine') {
      setSelectedNode(node.machineData);
    } else {
      setSelectedNode(null);
    }
  };

  const renderNodeCanvas = (node, ctx, globalScale) => {
    const isSelected = selectedNode && selectedNode.hostname === node.id;
    const isOffline = node.type === 'machine' && node.machineData.status !== 'ONLINE';

    if (node.type === 'machine') {
      const size = node.val;
      
      // Draw Red Pulse if Anomaly and online
      if (!isOffline && node.machineData && node.machineData.anomaly_streak > 0) {
        ctx.beginPath();
        ctx.arc(node.x, node.y, size * 2.5, 0, 2 * Math.PI, false);
        ctx.fillStyle = 'rgba(255, 59, 48, 0.2)';
        ctx.fill();
      }

      ctx.beginPath();
      
      // Minimalist Geometry
      if (node.shape === 'diamond') {
        ctx.moveTo(node.x, node.y - size * 1.5);
        ctx.lineTo(node.x + size * 1.5, node.y);
        ctx.lineTo(node.x, node.y + size * 1.5);
        ctx.lineTo(node.x - size * 1.5, node.y);
        ctx.closePath();
      } else if (node.shape === 'square') {
        const r = 2; // border radius
        const s = size * 2.2;
        const x = node.x - s/2;
        const y = node.y - s/2;
        ctx.moveTo(x + r, y);
        ctx.lineTo(x + s - r, y);
        ctx.arcTo(x + s, y, x + s, y + r, r);
        ctx.lineTo(x + s, y + s - r);
        ctx.arcTo(x + s, y + s, x + s - r, y + s, r);
        ctx.lineTo(x + r, y + s);
        ctx.arcTo(x, y + s, x, y + s - r, r);
        ctx.lineTo(x, y + r);
        ctx.arcTo(x, y, x + r, y, r);
        ctx.closePath();
      } else {
        ctx.arc(node.x, node.y, size, 0, 2 * Math.PI, false);
      }

      // Sleek Apple-style styling
      ctx.fillStyle = node.color;
      ctx.fill();
      
      ctx.lineWidth = isSelected ? 1.5 : 0.5;
      ctx.strokeStyle = isSelected ? '#ffffff' : (isOffline ? 'rgba(255,255,255,0.1)' : 'rgba(255,255,255,0.4)');
      ctx.stroke();

      // Inner dot for detail
      ctx.beginPath();
      ctx.arc(node.x, node.y, size * 0.2, 0, 2 * Math.PI, false);
      ctx.fillStyle = isOffline ? 'rgba(150,150,150,0.5)' : 'rgba(255,255,255,0.8)';
      ctx.fill();

    } else {
      // Subnet / Root nodes
      ctx.beginPath();
      ctx.arc(node.x, node.y, node.val, 0, 2 * Math.PI, false);
      ctx.fillStyle = node.color;
      ctx.fill();
      ctx.lineWidth = 0.5;
      ctx.strokeStyle = 'rgba(255,255,255,0.2)';
      ctx.stroke();
    }
  };

  return (
    <div className="view-container" style={{ display: 'flex', flexDirection: 'column', gap: 16, height: '100%', overflow: 'hidden' }}>
      <div className="main-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 className="page-title">Network Topology Map</h1>
          <p style={{ color: 'var(--subtle)', marginTop: 8 }}>Visualizing machine distribution across subnets. Click nodes to investigate.</p>
        </div>
        
        {/* Dynamic Filters Bar */}
        <div style={{ display: 'flex', gap: 8, background: 'var(--panel)', padding: '8px', borderRadius: '8px' }}>
          <button 
            className={`btn ${viewMode === 'default' ? 'btn-primary' : 'btn-outline'}`}
            onClick={() => setViewMode('default')}
          >
            Default View
          </button>
          <button 
            className={`btn ${viewMode === 'heatmap' ? 'btn-primary' : 'btn-outline'}`}
            onClick={() => setViewMode('heatmap')}
          >
            Risk Heatmap
          </button>
          <button 
            className={`btn ${viewMode === 'isolate' ? 'btn-primary' : 'btn-outline'}`}
            onClick={() => setViewMode('isolate')}
          >
            Isolate Compromised
          </button>
        </div>
      </div>

      <div style={{ display: 'flex', flex: 1, gap: 16, minHeight: 0 }}>
        {/* Graph Container */}
        <div 
          ref={containerRef} 
          className="table-wrap" 
          style={{ flex: 1, display: 'flex', background: 'var(--bg)', position: 'relative', overflow: 'hidden', borderRadius: '8px' }}
        >
          {graphData.nodes.length > 0 && (
            <ForceGraph2D
              key={`graph-${viewMode}`}
              width={dimensions.width}
              height={dimensions.height}
              graphData={graphData}
              nodeLabel="name"
              nodeCanvasObject={renderNodeCanvas}
              onNodeClick={handleNodeClick}
              
              // Skip initial unfold/spin animation by pre-computing physics
              warmupTicks={200}
              cooldownTicks={100}
              
              // Structured Enterprise Layout (Concentric Solar System)
              dagMode="radialOut"
              dagLevelDistance={250}
              d3VelocityDecay={0.2}
              d3AlphaDecay={0.05}
              
              // Dynamic Link Styling for "Blast Radius"
              linkColor={(link) => {

                if (selectedNode) {
                  const selectedSubnet = (() => {
                    const parts = selectedNode.ip_address.split('.');
                    return `${parts[0]}.${parts[1]}.${parts[2]}.x`;
                  })();
                  if (link.source.id === selectedSubnet || link.target.id === selectedSubnet || 
                      link.source === selectedSubnet || link.target === selectedSubnet) {
                    return 'rgba(255, 59, 48, 0.8)';
                  }
                  return 'rgba(255,255,255,0.05)';
                }
                return 'rgba(255,255,255,0.15)';
              }}
              linkWidth={(link) => {
                if (selectedNode) {
                  const selectedSubnet = (() => {
                    const parts = selectedNode.ip_address.split('.');
                    return `${parts[0]}.${parts[1]}.${parts[2]}.x`;
                  })();
                  if (link.source.id === selectedSubnet || link.target.id === selectedSubnet || 
                      link.source === selectedSubnet || link.target === selectedSubnet) {
                    return 2;
                  }
                }
                return 1;
              }}

              
              // Live Telemetry Particles
              linkDirectionalParticles={(link) => {
                const machineNode = link.source.type === 'machine' ? link.source : (link.target.type === 'machine' ? link.target : null);
                if (machineNode && machineNode.machineData && machineNode.machineData.status !== 'ONLINE') {
                  return 0; // No telemetry flow if offline
                }

                if (selectedNode) {
                  const selectedSubnet = (() => {
                    const parts = selectedNode.ip_address.split('.');
                    return `${parts[0]}.${parts[1]}.${parts[2]}.x`;
                  })();
                  if (link.source.id === selectedSubnet || link.target.id === selectedSubnet || 
                      link.source === selectedSubnet || link.target === selectedSubnet) {
                    return 4;
                  }
                }
                return 2;
              }}
              linkDirectionalParticleSpeed={0.005}
              linkDirectionalParticleWidth={(link) => {
                if (selectedNode) {
                  const selectedSubnet = (() => {
                    const parts = selectedNode.ip_address.split('.');
                    return `${parts[0]}.${parts[1]}.${parts[2]}.x`;
                  })();
                  if (link.source.id === selectedSubnet || link.target.id === selectedSubnet || 
                      link.source === selectedSubnet || link.target === selectedSubnet) {
                    return 3;
                  }
                }
                return 1.5;
              }}
              linkDirectionalParticleColor={(link) => {
                if (selectedNode) {
                  const selectedSubnet = (() => {
                    const parts = selectedNode.ip_address.split('.');
                    return `${parts[0]}.${parts[1]}.${parts[2]}.x`;
                  })();
                  if (link.source.id === selectedSubnet || link.target.id === selectedSubnet || 
                      link.source === selectedSubnet || link.target === selectedSubnet) {
                    return 'rgba(255, 59, 48, 1)';
                  }
                }
                return 'rgba(10, 132, 255, 0.6)';
              }}
              backgroundColor="transparent"
            />
          )}
        </div>

        {/* Side Panel */}

        {selectedNode && (
          <div className="table-wrap" style={{ width: '350px', background: 'var(--panel)', padding: '24px', display: 'flex', flexDirection: 'column', gap: '24px', overflowY: 'auto' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <h2 style={{ margin: 0, fontSize: '1.2rem' }}>{selectedNode.hostname}</h2>
                {selectedNode.status !== 'ONLINE' && (
                  <span style={{ fontSize: '0.75rem', background: '#333', padding: '2px 6px', borderRadius: '4px', color: '#999' }}>OFFLINE</span>
                )}
              </div>
              <button 
                className="btn btn-outline" 
                style={{ padding: '4px 8px' }} 
                onClick={() => setSelectedNode(null)}
              >
                ✕
              </button>
            </div>
            
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <div style={{
                background: selectedNode.last_risk_class === 'CRITICAL' ? 'var(--critical)' : 
                            selectedNode.last_risk_class === 'HIGH RISK' ? 'var(--high)' : 
                            selectedNode.last_risk_class === 'LOW RISK' ? 'var(--low)' : 'var(--safe)',
                padding: '8px 16px',
                borderRadius: '8px',
                fontWeight: 'bold',
                color: '#fff',
                opacity: selectedNode.status !== 'ONLINE' ? 0.5 : 1
              }}>
                {selectedNode.last_risk_score.toFixed(1)} / 100
              </div>
              <span style={{ color: 'var(--subtle)', fontWeight: 'bold' }}>{selectedNode.last_risk_class}</span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--subtle)' }}>IP Address</span>
                <span style={{ fontFamily: 'monospace' }}>{selectedNode.ip_address}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--subtle)' }}>MAC Address</span>
                <span style={{ fontFamily: 'monospace' }}>{selectedNode.mac_address || 'N/A'}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--subtle)' }}>OS Version</span>
                <span>{selectedNode.os_version || 'Unknown'}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--subtle)' }}>Asset Type</span>
                <span>
                  {selectedNode.asset_criticality >= 1.6 ? '👑 Domain Controller' : 
                   selectedNode.asset_criticality >= 1.3 ? '🖥️ Server' : '💻 Workstation'}
                </span>
              </div>
            </div>

            {selectedNode.anomaly_streak > 0 && selectedNode.status === 'ONLINE' && (
              <div style={{ background: 'rgba(255, 59, 48, 0.1)', border: '1px solid var(--critical)', padding: '16px', borderRadius: '8px' }}>
                <h4 style={{ color: 'var(--critical)', margin: '0 0 8px 0' }}>⚠️ Active Anomaly Detected</h4>
                <p style={{ margin: 0, fontSize: '0.9rem', color: 'var(--subtle)' }}>
                  This machine has exhibited abnormal security telemetry for {selectedNode.anomaly_streak} consecutive scans.
                </p>
              </div>
            )}
            
            <div style={{ marginTop: 'auto', paddingTop: '16px' }}>
              <button 
                className="btn btn-primary"
                style={{ width: '100%', padding: '12px' }}
                onClick={() => {
                  if (onViewSystem) {
                    onViewSystem(selectedNode.hostname);
                  }
                }}
              >
                Investigate & Fix Endpoint
              </button>
            </div>
            
          </div>
        )}
      </div>
    </div>
  );
}
