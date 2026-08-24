import { X, AlertTriangle, ShieldAlert, Cpu, Ban, Search } from 'lucide-react';
import { useToast } from '../context/ToastContext';

export default function ThreatModal({ threat, onClose }) {
  const { addToast } = useToast();
  if (!threat) return null;

  const handleBlockThreat = () => {
    addToast(`Added threat indicator ${threat.cveId || threat.title} to firewall blocklist`, 'warning');
    onClose();
  };

  const handleInvestigate = () => {
    addToast(`Initiated SOC threat investigation workflow`, 'info');
    onClose();
  };

  return (
    <>
      <div className="modal-overlay" onClick={onClose} style={{ position: 'fixed', inset: 0, background: 'rgba(3,7,18,0.75)', backdropFilter: 'blur(6px)', zIndex: 300 }} />
      <div role="dialog" aria-label={`Threat Details - ${threat.title}`} style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', width: '92%', maxWidth: '540px', background: 'var(--bg-surface)', border: '1px solid var(--border-hover)', borderRadius: 'var(--radius-lg)', zIndex: 301, padding: 24, boxShadow: 'var(--glow-critical)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
          <h3 style={{ fontSize: 16, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8, color: 'var(--critical)' }}>
            <AlertTriangle size={18} /> {threat.title || 'Critical Zero-Day Advisory'}
          </h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}><X size={18} /></button>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, fontSize: 13, color: 'var(--text-secondary)' }}>
          <div>CVE / Advisory ID: <strong className="mono-cell" style={{ color: 'var(--neon-blue)', background: 'var(--bg-raised)', padding: '2px 6px', borderRadius: 4 }}>{threat.cveId || 'CVE-2025-9981'}</strong></div>
          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            <div>CVSS Rating: <span className="cvss-pill">{threat.cvssScore || '9.4'}</span></div>
            <div>Severity: <span className={`severity-badge ${(threat.severity || 'CRITICAL').toLowerCase()}`}>{threat.severity || 'CRITICAL'}</span></div>
          </div>
          <div>Target Asset: <span className="mono-cell">{threat.affectedAsset || 'auth.production.domain'}</span></div>
          <div>Description: <p style={{ marginTop: 4, color: 'var(--text-primary)', lineHeight: 1.5, background: 'var(--bg-base)', padding: 10, borderRadius: 6 }}>{threat.description || 'Active exploitation detected in wild targeting authentication modules.'}</p></div>
          <div>Recommended Action: <p style={{ marginTop: 4, color: '#4ade80', lineHeight: 1.5, fontWeight: 600, background: 'rgba(34, 197, 94, 0.1)', padding: 10, borderRadius: 6 }}>{threat.remediation || 'Isolate affected instance and apply emergency hotfix.'}</p></div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, marginTop: 24, paddingTop: 14, borderTop: '1px solid var(--border)' }}>
          <button className="btn btn--outline" onClick={handleBlockThreat} style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#ef4444', borderColor: 'rgba(239,68,68,0.4)' }}>
            <Ban size={14} /> Block Indicator
          </button>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn--ghost" onClick={onClose}>Dismiss</button>
            <button className="btn btn--primary" onClick={handleInvestigate} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <Search size={14} /> Investigate
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
