import { useState, useMemo } from 'react';
import { useToast } from '../context/ToastContext';
import KpiCard          from '../components/KpiCard';
import RiskChart        from '../components/RiskChart';
import ThreatFeed       from '../components/ThreatFeed';
import VulnerabilityTable from '../components/VulnerabilityTable';

import {
  ShieldAlert, ShieldCheck, Globe, Radio, AlertTriangle,
  Activity, Bell, FileText, ChevronRight, RefreshCw, Zap
} from 'lucide-react';

const MOCK_TOP_THREATS = [
  { id: 't1', title: 'CVE-2024-3094 (xz-utils RCE)', severity: 'Critical', asset: 'api-prod-01.corp.internal', time: '12m ago', score: 10.0 },
  { id: 't2', title: 'Exposed PostgreSQL Port 5432', severity: 'Critical', asset: 'db-secondary.staging.net', time: '45m ago', score: 9.8 },
  { id: 't3', title: 'TLS 1.0 Enabled on Public Gateway', severity: 'High', asset: 'gw-external.corp.internal', time: '2h ago', score: 7.5 },
  { id: 't4', title: 'Expired Wildcard SSL Certificate', severity: 'High', asset: '*.legacy.corp.internal', time: '5h ago', score: 7.2 },
  { id: 't5', title: 'Unauthenticated Redis Instance', severity: 'Medium', asset: 'cache-03.internal', time: '1d ago', score: 5.4 },
];

const MOCK_RECENT_ASSETS = [
  { id: 'a1', domain: 'api.acme-corp.com', ip: '104.21.44.181', type: 'API Endpoint', status: 'Active', risk: 'Safe' },
  { id: 'a2', domain: 'dev-db.internal.acme-corp.com', ip: '192.168.1.104', type: 'Database Server', status: 'Exposed', risk: 'Critical' },
  { id: 'a3', domain: 'vpn.acme-corp.com', ip: '198.51.100.45', type: 'VPN Gateway', status: 'Active', risk: 'Medium' },
  { id: 'a4', domain: 'staging.acme-corp.com', ip: '104.21.44.199', type: 'Web Server', status: 'Restricted', risk: 'High' },
  { id: 'a5', domain: 'mail.acme-corp.com', ip: '198.51.100.12', type: 'Mail Server', status: 'Active', risk: 'Safe' },
];

export default function Dashboard({ onExport, onVulnClick, onOpenModal }) {
  const { addToast } = useToast();
  const [isScanning, setIsScanning] = useState(false);

  const handleQuickScan = () => {
    setIsScanning(true);
    addToast('Initiating background surface scan on all registered domains...', 'info');
    setTimeout(() => {
      setIsScanning(false);
      addToast('Scan complete! 1,428 assets verified, 0 new critical threats found.', 'success');
    }, 2000);
  };

  const openThreatDetail = (item) => {
    if (onOpenModal) {
      onOpenModal('threat', {
        id: item.id,
        cveId: item.title.split(' ')[0],
        title: item.title,
        severity: item.severity,
        cvssScore: item.score,
        affectedAsset: item.asset,
        discoveredAt: item.time,
        description: 'High priority vulnerability detected on exposed infrastructure requiring immediate patch deployment.',
        remediation: 'Apply vendor patch release or restrict endpoint access via IP firewall rules.'
      });
    }
  };

  const openAssetDetail = (asset) => {
    if (onOpenModal) {
      onOpenModal('asset', {
        id: asset.id,
        name: asset.domain,
        type: asset.type,
        ipAddress: asset.ip,
        status: asset.status,
        riskLevel: asset.risk,
        owner: 'Infrastructure DevOps',
        openPorts: [80, 443, 8080],
        technologies: ['Nginx', 'Node.js', 'Docker', 'Cloudflare Edge'],
        vulnerabilitiesCount: asset.risk === 'Critical' ? 4 : 1,
        firstDiscovered: '2026-01-12',
        lastScanned: '10 minutes ago'
      });
    }
  };

  return (
    <div className="page-content dashboard-container">
      <div className="page-header">
        <div className="page-header__left">
          <h1 className="page-header__title">
            Attack Surface <span>Overview</span>
          </h1>
          <p className="page-header__subtitle">
            Real-time asset discovery, vulnerability correlation, and threat intelligence dashboard.
          </p>
        </div>
        <div className="flex-gap-md" style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <button className="export-btn" onClick={handleQuickScan} disabled={isScanning}>
            <RefreshCw size={14} className={isScanning ? 'spin-slow' : ''} /> {isScanning ? 'Scanning...' : 'Quick Scan'}
          </button>
          <button className="export-btn" onClick={() => onOpenModal?.('status')}>
            <Activity size={14} /> System Health
          </button>
          <button className="export-btn" onClick={() => onOpenModal?.('alert')}>
            <Bell size={14} /> Alert Rules
          </button>
          <button className="export-btn btn--primary" onClick={onExport}>
            <FileText size={14} /> Export Report
          </button>
        </div>
      </div>

      <div className="kpi-grid">
        <div onClick={() => addToast('Filtering assets by discovered count', 'info')} style={{ cursor: 'pointer' }}>
          <KpiCard title="Total Discovered Assets" value="1,428" trend="+12% this week" trendUp={true} color="blue" icon={Globe} />
        </div>
        <div onClick={onVulnClick} style={{ cursor: 'pointer' }}>
          <KpiCard title="Critical Vulnerabilities" value="23" trend="-4 since yesterday" trendUp={true} color="red" icon={ShieldAlert} />
        </div>
        <div onClick={() => addToast('184 open ports under active monitoring', 'info')} style={{ cursor: 'pointer' }}>
          <KpiCard title="Exposed Open Ports" value="184" trend="3 high risk ports" trendUp={false} color="purple" icon={Radio} />
        </div>
        <div onClick={() => addToast('Attack Surface Security Grade: A- (82/100)', 'success')} style={{ cursor: 'pointer' }}>
          <KpiCard title="Attack Surface Score" value="82/100" trend="Grade A- (Good)" trendUp={true} color="green" icon={ShieldCheck} />
        </div>
      </div>

      <div className="dashboard-grid">
        <div className="dashboard-chart-card">
          <RiskChart />
        </div>
        <div className="dashboard-feed-card">
          <ThreatFeed onSelectThreat={(threat) => onOpenModal?.('threat', threat)} />
        </div>
      </div>

      <div className="dashboard-grid-2col" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: 24, marginTop: 24 }}>
        <div className="dash-card">
          <div className="dash-card__header">
            <h3 className="dash-card__title">
              <AlertTriangle size={18} color="var(--critical)" /> Critical Threat Priority
            </h3>
            <button className="dash-card__action" onClick={onVulnClick}>
              View All <ChevronRight size={14} />
            </button>
          </div>
          <div className="dash-threat-list">
            {MOCK_TOP_THREATS.map((item) => (
              <div
                key={item.id}
                className="dash-threat-item clickable-row"
                onClick={() => openThreatDetail(item)}
              >
                <div className="dash-threat-item__left">
                  <div className={`severity-badge ${item.severity.toLowerCase()}`}>{item.severity}</div>
                  <div>
                    <div className="dash-threat-item__title">{item.title}</div>
                    <div className="dash-threat-item__asset">{item.asset}</div>
                  </div>
                </div>
                <div className="dash-threat-item__right">
                  <span className="cvss-pill">{item.score}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="dash-card">
          <div className="dash-card__header">
            <h3 className="dash-card__title">
              <Globe size={18} color="var(--neon-blue)" /> Discovered Surface Endpoints
            </h3>
            <span className="tab-badge" style={{ fontSize: 11 }}>Live Feed</span>
          </div>
          <div className="dash-asset-list">
            {MOCK_RECENT_ASSETS.map((asset) => (
              <div
                key={asset.id}
                className="dash-asset-item clickable-row"
                onClick={() => openAssetDetail(asset)}
              >
                <div className="dash-asset-item__info">
                  <div className="dash-asset-item__domain">{asset.domain}</div>
                  <div className="dash-asset-item__meta">{asset.ip} · {asset.type}</div>
                </div>
                <span className={`status-badge ${asset.risk.toLowerCase()}`}>{asset.risk}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div style={{ marginTop: 24 }}>
        <VulnerabilityTable onSelectVuln={(vuln) => onOpenModal?.('vulnerability', vuln)} />
      </div>
    </div>
  );
}
