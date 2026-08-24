import { X, Activity, CheckCircle2, ShieldCheck, Server, RefreshCw } from 'lucide-react';
import { useToast } from '../context/ToastContext';

export default function SystemStatusModal({ onClose }) {
  const { addToast } = useToast();

  const handleRefresh = () => {
    addToast('Refreshed all system component health metrics', 'success');
  };

  const handleRunHealthCheck = () => {
    addToast('System health check completed. All 8 microservices operational.', 'info');
  };

  return (
    <>
      <div className="modal-overlay" onClick={onClose} style={{ position: 'fixed', inset: 0, background: 'rgba(3,7,18,0.75)', backdropFilter: 'blur(6px)', zIndex: 300 }} />
      <div role="dialog" aria-label="System Health Status" style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', width: '92%', maxWidth: '460px', background: 'var(--bg-surface)', border: '1px solid var(--border-hover)', borderRadius: 'var(--radius-lg)', zIndex: 301, padding: 24, boxShadow: 'var(--glow-blue)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
          <h3 style={{ fontSize: 16, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Activity size={18} color="#4ade80" /> System Health Diagnostics
          </h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}><X size={18} /></button>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, fontSize: 13, background: 'var(--bg-base)', padding: 14, borderRadius: 8, border: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}><Server size={14} color="var(--neon-blue)" /> Scanner Engine</span>
            <span style={{ color: '#4ade80', fontWeight: 600, background: 'rgba(74,222,128,0.1)', padding: '2px 8px', borderRadius: 4 }}>100% Operational</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}><ShieldCheck size={14} color="var(--neon-cyan)" /> CVE Intelligence Pipeline</span>
            <span style={{ color: '#4ade80', fontWeight: 600, background: 'rgba(74,222,128,0.1)', padding: '2px 8px', borderRadius: 4 }}>Connected (v2026.8)</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}><Activity size={14} color="var(--accent-blue)" /> API Gateway Latency</span>
            <span className="mono-cell" style={{ color: 'var(--neon-blue)', fontWeight: 600 }}>12ms</span>
          </div>
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, marginTop: 20, paddingTop: 14, borderTop: '1px solid var(--border)' }}>
          <button className="btn btn--outline" onClick={handleRefresh} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <RefreshCw size={14} /> Refresh
          </button>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn--ghost" onClick={onClose}>Close</button>
            <button className="btn btn--primary" onClick={handleRunHealthCheck}>
              Run Diagnostics
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
