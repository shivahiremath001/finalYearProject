import React, { useState, useEffect, useRef } from 'react';
import { Download } from 'lucide-react';
import { API_BASE } from '../App';
import Chart from 'chart.js/auto';

export default function AnalyticsView({ token }) {
  const [history, setHistory] = useState([]);
  const chartRef = useRef(null);
  const chartInstance = useRef(null);

  useEffect(() => {
    const fetchAnalytics = async () => {
      try {
        const res = await fetch(`${API_BASE}/analytics/history`, { headers: { Authorization: `Bearer ${token}` } });
        if (res.ok) {
          const data = await res.json();
          setHistory(data.history);
        }
      } catch (e) { console.error(e); }
    };
    fetchAnalytics();
  }, [token]);

  useEffect(() => {
    if (!chartRef.current || history.length === 0) return;

    if (chartInstance.current) {
      chartInstance.current.destroy();
    }

    const ctx = chartRef.current.getContext('2d');
    
    // Create gradient
    const gradient = ctx.createLinearGradient(0, 0, 0, 400);
    gradient.addColorStop(0, 'rgba(10, 132, 255, 0.4)');
    gradient.addColorStop(1, 'rgba(10, 132, 255, 0.0)');

    chartInstance.current = new Chart(ctx, {
      type: 'line',
      data: {
        labels: history.map(d => d.date),
        datasets: [{
          label: 'Average Risk Score',
          data: history.map(d => d.avgRisk),
          borderColor: '#0a84ff',
          backgroundColor: gradient,
          borderWidth: 3,
          pointBackgroundColor: '#fff',
          pointBorderColor: '#0a84ff',
          pointBorderWidth: 2,
          pointRadius: 4,
          fill: true,
          tension: 0.4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: 'rgba(0,0,0,0.8)',
            padding: 12,
            titleFont: { size: 14, family: 'Inter' },
            bodyFont: { size: 14, family: 'Inter' },
            displayColors: false,
          }
        },
        scales: {
          y: { grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: 'rgba(255,255,255,0.5)' }, min: 0, max: 100 },
          x: { grid: { display: false }, ticks: { color: 'rgba(255,255,255,0.5)' } }
        }
      }
    });

    return () => {
      if (chartInstance.current) chartInstance.current.destroy();
    };
  }, [history]);

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="view-container analytics-view" style={{ display: 'flex', flexDirection: 'column', gap: 32 }}>
      <div className="main-header">
        <h1 className="page-title">Historical Analytics</h1>
        <div className="fleet-controls no-print">
          <button className="btn btn-ghost btn-sm" onClick={handlePrint}>
            <Download size={16} /> Export PDF Report
          </button>
        </div>
      </div>

      <div className="table-wrap print-container" style={{ padding: 40 }}>
        <h2 style={{ marginBottom: 24, fontSize: 20 }}>Fleet Average Risk (Past 30 Days)</h2>
        <div style={{ height: 400, width: '100%' }}>
          {history.length > 0 ? <canvas ref={chartRef}></canvas> : <p style={{color: 'var(--subtle)'}}>No historical data available.</p>}
        </div>
      </div>
    </div>
  );
}
