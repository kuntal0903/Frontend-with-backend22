import { Activity, ShieldAlert, AlertTriangle, Radio } from 'lucide-react';

const MOCK_FEEDS = [
  { id: 'f1', type: 'Critical', text: 'CVE-2024-3094 SSH Backdoor payload signature matched', asset: 'api-prod-01', time: '5m ago' },
  { id: 'f2', type: 'High', text: 'Exposed PostgreSQL database port 5432 detected', asset: 'dev-db.internal', time: '18m ago' },
  { id: 'f3', type: 'Medium', text: 'TLS 1.0 handshake enabled on legacy proxy gateway', asset: 'gw-external', time: '1h ago' },
  { id: 'f4', type: 'Safe', text: 'Daily automated domain scan completed (104 subdomains)', asset: 'acme-corp.com', time: '2h ago' },
];

export default function ThreatFeed({ onSelectThreat }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div className="dash-card__header" style={{ marginBottom: 16 }}>
        <h3 className="dash-card__title">
          <Activity size={18} color="var(--neon-blue)" /> Threat Intelligence Stream
        </h3>
        <span className="tab-badge" style={{ background: 'rgba(34,197,94,0.15)', color: '#4ade80' }}>Live</span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 10, flex: 1, overflowY: 'auto' }}>
        {MOCK_FEEDS.map((feed) => (
          <div
            key={feed.id}
            className="dash-threat-item"
            onClick={() => onSelectThreat({
              id: feed.id,
              cveId: feed.type === 'Critical' ? 'CVE-2024-3094' : 'CVE-2023-4863',
              title: feed.text,
              severity: feed.type === 'Safe' ? 'Low' : feed.type,
              cvssScore: feed.type === 'Critical' ? 10.0 : 7.5,
              affectedAsset: feed.asset,
              discoveredAt: feed.time,
              description: feed.text,
              remediation: 'Apply system updates and restrict open ports.'
            })}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span className={`status-badge ${feed.type.toLowerCase()}`}>{feed.type}</span>
              <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>{feed.text}</span>
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
              Asset: {feed.asset} · {feed.time}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
