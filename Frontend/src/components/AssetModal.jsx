import { X, Server, Globe, Shield, Clock, RefreshCw, Copy } from 'lucide-react';
import { useToast } from '../context/ToastContext';

export default function AssetModal({ asset, onClose }) {
  const { addToast } = useToast();
  if (!asset) return null;

  const handleCopyIP = () => {
    navigator.clipboard?.writeText(asset.ipAddress || '192.168.1.1');
    addToast(`Copied ${asset.ipAddress || 'IP'} to clipboard`, 'success');
  };

  const handleRescan = () => {
    addToast(`Initiated deep port scan on asset ${asset.name || asset.ipAddress}`, 'info');
    onClose();
  };

  return (
    <>
      <div className="modal-overlay" onClick={onClose} style={{ position: 'fixed', inset: 0, background: 'rgba(3,7,18,0.75)', backdropFilter: 'blur(6px)', zIndex: 300 }} />
      <div role="dialog" aria-label={`Asset Details - ${asset.name}`} style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', width: '92%', maxWidth: '540px', background: 'var(--bg-surface)', border: '1px solid var(--border-hover)', borderRadius: 'var(--radius-lg)', zIndex: 301, padding: 24, boxShadow: 'var(--glow-blue)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
          <h3 style={{ fontSize: 16, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Globe size={18} color="var(--neon-blue)" /> {asset.name || 'api.internal.domain.com'}
          </h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}><X size={18} /></button>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, fontSize: 13, color: 'var(--text-secondary)' }}>
          <div>Type: <strong style={{ color: 'var(--text-primary)' }}>{asset.type || 'Subdomain'}</strong></div>
          <div>IP Address: <span className="mono-cell" style={{ color: 'var(--neon-blue)', background: 'var(--bg-raised)', padding: '2px 6px', borderRadius: 4 }}>{asset.ipAddress || '192.168.1.100'}</span></div>
          <div style={{ display: 'flex', gap: 12 }}>
            <div>Status: <span className={`status-badge ${(asset.status || 'Active') === 'Active' ? 'safe' : 'high'}`}>{asset.status || 'Active'}</span></div>
            <div>Risk Level: <span className={`status-badge ${(asset.riskLevel || 'High').toLowerCase()}`}>{asset.riskLevel || 'High'}</span></div>
          </div>
          <div>Open Ports: {asset.openPorts?.map(p => <span key={p} className="port-tag" style={{ marginLeft: 4 }}>:{p}</span>) || <span className="port-tag">:443</span>}</div>
          <div>Tech Stack: <strong style={{ color: 'var(--text-primary)' }}>{asset.technologies?.join(', ') || 'Nginx, React, Node.js'}</strong></div>
          <div>Last Scanned: <span className="mono-cell">{asset.lastScanned || '10 mins ago'}</span></div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, marginTop: 24, paddingTop: 14, borderTop: '1px solid var(--border)' }}>
          <button className="btn btn--outline" onClick={handleCopyIP} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Copy size={14} /> Copy IP
          </button>
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn--ghost" onClick={onClose}>Close</button>
            <button className="btn btn--primary" onClick={handleRescan} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <RefreshCw size={14} /> Re-Scan Asset
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
