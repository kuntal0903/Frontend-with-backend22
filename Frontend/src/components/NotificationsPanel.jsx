import { useState } from 'react';
import { X, Bell, AlertTriangle, ShieldCheck, CheckCheck } from 'lucide-react';
import { useToast } from '../context/ToastContext';

const INITIAL_NOTIFS = [
  { id: 'n1', title: 'Critical Vulnerability Detected', desc: 'CVE-2024-3094 matched on api-prod-01', time: '10m ago', unread: true, target: 'vulnerabilities' },
  { id: 'n2', title: 'SSL Certificate Expiring', desc: 'Wildcard cert expires in 22 days', time: '1h ago', unread: true, target: 'assets' },
  { id: 'n3', title: 'Domain Scan Completed', desc: 'acme-corp.com scan finished with 0 critical errors', time: '3h ago', unread: false, target: 'domain-scan' },
];

export default function NotificationsPanel({ isOpen, onClose, onNavigate, onOpenModal }) {
  const { addToast } = useToast();
  const [notifs, setNotifs] = useState(INITIAL_NOTIFS);

  if (!isOpen) return null;

  const handleMarkAllRead = () => {
    setNotifs((prev) => prev.map((n) => ({ ...n, unread: false })));
    addToast('Marked all security notifications as read', 'info');
  };

  const handleItemClick = (n) => {
    setNotifs((prev) => prev.map((item) => item.id === n.id ? { ...item, unread: false } : item));
    onClose();
    if (n.target) {
      onNavigate(n.target);
    }
  };

  return (
    <>
      <div className="modal-overlay" onClick={onClose} style={{ position: 'fixed', inset: 0, background: 'rgba(3,7,18,0.5)', backdropFilter: 'blur(3px)', zIndex: 400 }} />
      <div style={{ position: 'fixed', top: 70, right: 24, width: 360, background: 'var(--bg-surface)', border: '1px solid var(--border-hover)', borderRadius: 'var(--radius-lg)', padding: 18, zIndex: 401, boxShadow: 'var(--glow-blue)', animation: 'fadeIn 0.2s ease-out' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
          <h4 style={{ fontSize: 14, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Bell size={16} color="var(--neon-blue)" /> Security Notifications
          </h4>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <button onClick={handleMarkAllRead} title="Mark All as Read" style={{ background: 'none', border: 'none', color: 'var(--text-accent)', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 4, fontSize: 12 }}>
              <CheckCheck size={14} /> Read
            </button>
            <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}><X size={14} /></button>
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 10, maxHeight: 320, overflowY: 'auto' }}>
          {notifs.map(n => (
            <div
              key={n.id}
              onClick={() => handleItemClick(n)}
              className="clickable-row"
              style={{
                padding: 12,
                background: n.unread ? 'var(--bg-raised)' : 'var(--bg-card)',
                borderRadius: 'var(--radius-md)',
                border: n.unread ? '1px solid rgba(59, 130, 246, 0.3)' : '1px solid var(--border)',
                position: 'relative',
              }}
            >
              {n.unread && <span style={{ position: 'absolute', top: 10, right: 10, width: 6, height: 6, borderRadius: '50%', background: 'var(--neon-blue)' }} />}
              <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>{n.title}</div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 3, lineHeight: 1.4 }}>{n.desc}</div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 6 }}>{n.time}</div>
            </div>
          ))}
        </div>

        <button
          className="btn btn--primary"
          style={{ width: '100%', marginTop: 14, justifyContent: 'center', fontSize: 12 }}
          onClick={() => { onClose(); onNavigate('alerts'); }}
        >
          View Alert Center
        </button>
      </div>
    </>
  );
}
