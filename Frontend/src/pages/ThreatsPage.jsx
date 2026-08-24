import { useState, useMemo } from 'react';
import { Zap, Radio, ShieldAlert, Cpu, Activity, Search, Ban, RefreshCw } from 'lucide-react';
import { useToast } from '../context/ToastContext';

const MOCK_THREAT_FEEDS = [
  { id: 'tf1', cveId: 'CVE-2024-3094', title: 'xz-utils Backdoor Active Exploitation', severity: 'Critical', cvssScore: 10.0, affectedAsset: 'api-prod-01.corp.internal', discoveredAt: '15m ago', description: 'Active in-the-wild exploitation targeting Linux SSH authentication daemons using compromised xz-utils compression binaries.', remediation: 'Downgrade or patch xz-utils to 5.4.x stable distribution release.' },
  { id: 'tf2', cveId: 'CVE-2023-4863', title: 'Zero-Day WebP Rendering Exploit', severity: 'Critical', cvssScore: 9.8, affectedAsset: 'app.acme-corp.com', discoveredAt: '1h ago', description: 'Malicious WebP images crafted to execute arbitrary shellcode when rendered in Chrome or Electron wrapper applications.', remediation: 'Update libwebp library and browser runtimes.' },
  { id: 'tf3', cveId: 'CVE-2023-22515', title: 'Confluence Data Center Auth Bypass', severity: 'High', cvssScore: 8.5, affectedAsset: 'wiki.corp.internal', discoveredAt: '3h ago', description: 'Threat actors creating admin accounts by bypassing setup wizard validation checks.', remediation: 'Apply vendor hotfix or isolate Confluence from public ingress.' },
];

export default function ThreatsPage({ onOpenModal }) {
  const { addToast } = useToast();
  const [searchQuery, setSearchQuery] = useState('');

  const filteredThreats = useMemo(() => {
    return MOCK_THREAT_FEEDS.filter(t => 
      t.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      t.cveId.toLowerCase().includes(searchQuery.toLowerCase()) ||
      t.affectedAsset.toLowerCase().includes(searchQuery.toLowerCase())
    );
  }, [searchQuery]);

  const handleRefreshFeed = () => {
    addToast('Updated threat intelligence feed from global SOC networks', 'info');
  };

  return (
    <div className="page-content">
      <div className="page-header">
        <div className="page-header__left">
          <h1 className="page-header__title">
            Threat <span>Intelligence Feed</span>
          </h1>
          <p className="page-header__subtitle">
            Global CVE threat feeds, zero-day indicators, and exploit correlation feeds updated in real-time.
          </p>
        </div>
        <button className="export-btn" onClick={handleRefreshFeed}>
          <RefreshCw size={14} /> Refresh Feed
        </button>
      </div>

      <div className="tab-controls" style={{ marginBottom: 20 }}>
        <div className="table-search-box" style={{ width: 340 }}>
          <Search size={14} color="var(--text-muted)" />
          <input
            type="text"
            placeholder="Filter threat intelligence feed..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        {filteredThreats.map(t => (
          <div key={t.id} className="dash-card clickable-row" onClick={() => onOpenModal?.('threat', t)}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span className={`severity-badge ${t.severity.toLowerCase()}`}>{t.severity}</span>
                <span style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)' }}>{t.title}</span>
              </div>
              <span className="cvss-pill">{t.cvssScore}</span>
            </div>
            <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: 12 }}>
              {t.description}
            </p>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', display: 'flex', gap: 16 }}>
              <span>Asset: <strong style={{ color: 'var(--neon-blue)' }}>{t.affectedAsset}</strong></span>
              <span>Discovered: {t.discoveredAt}</span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
