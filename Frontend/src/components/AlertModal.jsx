import { X, Bell, CheckCircle, Save } from 'lucide-react';
import { useToast } from '../context/ToastContext';

export default function AlertModal({ alert: alertData, onClose }) {
  const { addToast } = useToast();

  const handleSave = () => {
    addToast(`Saved alert notification preferences and threshold rules`, 'success');
    onClose();
  };

  const handleAcknowledgeAlert = () => {
    addToast(`Acknowledged security alert: ${alertData?.title || 'System Alert'}`, 'info');
    onClose();
  };

  return (
    <>
      <div className="modal-overlay" onClick={onClose} style={{ position: 'fixed', inset: 0, background: 'rgba(3,7,18,0.75)', backdropFilter: 'blur(6px)', zIndex: 300 }} />
      <div role="dialog" aria-label="Alert Details & Notification Rules" style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', width: '92%', maxWidth: '480px', background: 'var(--bg-surface)', border: '1px solid var(--border-hover)', borderRadius: 'var(--radius-lg)', zIndex: 301, padding: 24, boxShadow: 'var(--glow-blue)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
          <h3 style={{ fontSize: 16, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8, color: 'var(--neon-blue)' }}>
            <Bell size={18} /> {alertData?.title || 'Alert Notification Thresholds'}
          </h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}><X size={18} /></button>
        </div>

        {alertData ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12, fontSize: 13, color: 'var(--text-secondary)', marginBottom: 16 }}>
            <div>Source Component: <strong style={{ color: 'var(--text-primary)' }}>{alertData.source || 'Threat Intelligence Engine'}</strong></div>
            <div>Severity: <span className={`status-badge ${(alertData.severity || 'high').toLowerCase()}`}>{alertData.severity || 'HIGH'}</span></div>
            <div>Timestamp: <span className="mono-cell">{alertData.time || 'Just now'}</span></div>
            <div>Message: <p style={{ marginTop: 4, color: 'var(--text-primary)', background: 'var(--bg-base)', padding: 10, borderRadius: 6, lineHeight: 1.5 }}>{alertData.message || alertData.title}</p></div>
          </div>
        ) : (
          <>
            <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: 16 }}>
              Configure automated email, Slack, and SIEM notification thresholds for critical security events.
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginBottom: 16 }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 13, cursor: 'pointer' }}>
                <input type="checkbox" defaultChecked style={{ accentColor: 'var(--accent-blue)' }} /> Notify immediately on Critical CVE detection (CVSS 9.0+)
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 13, cursor: 'pointer' }}>
                <input type="checkbox" defaultChecked style={{ accentColor: 'var(--accent-blue)' }} /> Notify on exposed database ports (5432, 3306, 27017)
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 13, cursor: 'pointer' }}>
                <input type="checkbox" defaultChecked style={{ accentColor: 'var(--accent-blue)' }} /> Send daily summary digest at 08:00 UTC
              </label>
            </div>
          </>
        )}

        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 20, paddingTop: 14, borderTop: '1px solid var(--border)' }}>
          <button className="btn btn--ghost" onClick={onClose}>Cancel</button>
          {alertData ? (
            <button className="btn btn--primary" onClick={handleAcknowledgeAlert} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <CheckCircle size={14} /> Acknowledge Alert
            </button>
          ) : (
            <button className="btn btn--primary" onClick={handleSave} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <Save size={14} /> Save Alert Settings
            </button>
          )}
        </div>
      </div>
    </>
  );
}
