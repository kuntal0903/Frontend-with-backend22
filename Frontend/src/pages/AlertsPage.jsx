import { useState } from 'react';
import { Bell, AlertTriangle, CheckCircle, ShieldAlert, Radio, Trash2, CheckCheck } from 'lucide-react';
import { useToast } from '../context/ToastContext';

const MOCK_ALERTS = [
  { id: 'alt1', title: 'New Critical CVE-2024-3094 Detected on api-prod-01', type: 'Critical', time: '10m ago', unread: true, message: 'RCE vulnerability detected during automated port scan.' },
  { id: 'alt2', title: 'Exposed Database Port 5432 on dev-db.internal', type: 'Critical', time: '40m ago', unread: true, message: 'PostgreSQL database listener accessible from external network.' },
  { id: 'alt3', title: 'SSL Certificate Expiration Warning (22 Days Left)', type: 'High', time: '2h ago', unread: false, message: 'Wildcard SSL certificate expiring soon. Renewal recommended.' },
  { id: 'alt4', title: 'Unauthorized Port Scan Detected from IP 198.51.100.99', type: 'Medium', time: '5h ago', unread: false, message: 'Multiple SYN packets logged on port range 1-1024.' },
];

export default function AlertsPage({ onOpenModal }) {
  const { addToast } = useToast();
  const [alerts, setAlerts] = useState(MOCK_ALERTS);

  const handleClearAll = () => {
    setAlerts([]);
    addToast('Cleared all security alerts from feed', 'info');
  };

  const handleMarkAllRead = () => {
    setAlerts(prev => prev.map(a => ({ ...a, unread: false })));
    addToast('Marked all alerts as acknowledged', 'success');
  };

  return (
    <div className="page-content">
      <div className="page-header">
        <div className="page-header__left">
          <h1 className="page-header__title">
            Alert <span>Center</span>
          </h1>
          <p className="page-header__subtitle">
            Real-time security notifications, threshold triggers, and automated incident routing.
          </p>
        </div>
        <div className="flex-gap-md" style={{ display: 'flex', gap: 12 }}>
          <button className="export-btn" onClick={handleMarkAllRead}>
            <CheckCheck size={14} /> Acknowledge All
          </button>
          <button className="export-btn" onClick={() => onOpenModal?.('alert')}>
            <Bell size={14} /> Rule Settings
          </button>
          <button className="export-btn" onClick={handleClearAll}>
            <Trash2 size={14} /> Clear Feed
          </button>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {alerts.map(a => (
          <div
            key={a.id}
            className="dash-card clickable-row"
            onClick={() => onOpenModal?.('alert', a)}
            style={{
              display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              borderLeft: a.type === 'Critical' ? '4px solid var(--critical)' : '4px solid var(--high)',
              background: a.unread ? 'var(--bg-raised)' : 'var(--bg-surface)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <AlertTriangle size={18} color={a.type === 'Critical' ? 'var(--critical)' : 'var(--high)'} />
              <div>
                <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>{a.title}</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{a.time}</div>
              </div>
            </div>
            <span className={`status-badge ${a.type.toLowerCase()}`}>{a.type}</span>
          </div>
        ))}
        {alerts.length === 0 && (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)', background: 'var(--bg-surface)', borderRadius: 'var(--radius-lg)', border: '1px solid var(--border)' }}>
            No active alerts at this time. All systems secure.
          </div>
        )}
      </div>
    </div>
  );
}
