import React, { useState, useEffect, useRef } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { API_BASE } from '../constants';

export default function NetworkMapView({ token }) {
  const [graphData, setGraphData] = useState({ nodes: [], links: [] });
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
          
          const nodes = [];
          const links = [];
          
          // Root node
          nodes.push({ id: 'root', name: 'Corporate Network', val: 10, color: '#0a84ff' });

          // Map subnets
          const subnets = {};
          machines.forEach(m => {
            const parts = m.ip_address.split('.');
            if (parts.length === 4) {
              const subnet = `${parts[0]}.${parts[1]}.${parts[2]}.x`;
              if (!subnets[subnet]) {
                subnets[subnet] = true;
                nodes.push({ id: subnet, name: `Subnet: ${subnet}`, val: 5, color: 'rgba(255,255,255,0.4)' });
                links.push({ source: 'root', target: subnet });
              }
              
              // Machine Node
              let mColor = 'var(--safe)';
              if (m.last_risk_class === 'CRITICAL') mColor = 'var(--critical)';
              else if (m.last_risk_class === 'HIGH RISK') mColor = 'var(--high)';
              else if (m.last_risk_class === 'LOW RISK') mColor = 'var(--low)';
              
              if (m.anomaly_streak > 0) mColor = '#ff3b30'; // red pulse

              nodes.push({ 
                id: m.hostname, 
                name: `${m.hostname} (${m.ip_address})`, 
                val: 3, 
                color: mColor 
              });
              links.push({ source: subnet, target: m.hostname });
            }
          });

          setGraphData({ nodes, links });
        }
      } catch (e) { console.error(e); }
    };
    fetchMachines();
  }, [token]);

  return (
    <div className="view-container" style={{ display: 'flex', flexDirection: 'column', gap: 32, height: '100%' }}>
      <div className="main-header">
        <h1 className="page-title">Network Topology Map</h1>
        <p style={{ color: 'var(--subtle)', marginTop: 8 }}>Visualizing machine distribution across subnets. Anomalies are highlighted in red.</p>
      </div>

      <div 
        ref={containerRef} 
        className="table-wrap" 
        style={{ flex: 1, minHeight: 600, display: 'flex', background: 'var(--bg)', position: 'relative' }}
      >
        {graphData.nodes.length > 0 && (
          <ForceGraph2D
            width={dimensions.width}
            height={dimensions.height}
            graphData={graphData}
            nodeLabel="name"
            nodeColor="color"
            nodeRelSize={4}
            linkColor={() => 'rgba(255,255,255,0.1)'}
            linkWidth={1}
            backgroundColor="transparent"
          />
        )}
      </div>
    </div>
  );
}
