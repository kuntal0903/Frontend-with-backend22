import { useState, useMemo } from 'react';
import { Server, Search, Filter, ShieldCheck, AlertTriangle, ExternalLink, RefreshCw, Cpu, Database, Cloud, Radio, Plus, Download } from 'lucide-react';
import { useToast } from '../context/ToastContext';

const MOCK_ASSETS = [
  { id: 'a1', name: 'api.acme-corp.com', type: 'API Endpoint', ipAddress: '104.21.44.181', status: 'Active', riskLevel: 'Safe', owner: 'DevOps', openPorts: [80, 443], technologies: ['Node.js', 'Express', 'Cloudflare Edge'], vulnerabilitiesCount: 0, firstDiscovered: '2025-11-10', lastScanned: '5 mins ago' },
  { id: 'a2', name: 'dev-db.internal.acme-corp.com', type: 'Database Server', ipAddress: '192.168.1.104', status: 'Exposed', riskLevel: 'Critical', owner: 'Backend Team', openPorts: [5432], technologies: ['PostgreSQL 14', 'Linux Ubuntu'], vulnerabilitiesCount: 3, firstDiscovered: '2026-01-05', lastScanned: '12 mins ago' },
  { id: 'a3', name: 'staging.acme-corp.com', type: 'Web Server', ipAddress: '104.21.44.199', status: 'Restricted', riskLevel: 'High', owner: 'QA Team', openPorts: [80, 443, 8080], technologies: ['Apache 2.4.41', 'PHP 8.1'], vulnerabilitiesCount: 2, firstDiscovered: '2025-12-18', lastScanned: '1 hour ago' },
  { id: 'a4', name: 'vpn.acme-corp.com', type: 'VPN Gateway', ipAddress: '198.51.100.45', status: 'Active', riskLevel: 'Medium', owner: 'SecOps', openPorts: [443, 1194], technologies: ['OpenVPN 2.5'], vulnerabilitiesCount: 1, firstDiscovered: '2025-08-20', lastScanned: '3 hours ago' },
  { id: 'a5', name: 'mail.acme-corp.com', type: 'Mail Server', ipAddress: '198.51.100.12', status: 'Active', riskLevel: 'Safe', owner: 'IT Ops', openPorts: [25, 465, 993], technologies: ['Postfix', 'Dovecot'], vulnerabilitiesCount: 0, firstDiscovered: '2025-06-14', lastScanned: '2 hours ago' },
  { id: 'a6', name: 'app.acme-corp.com', type: 'Frontend App', ipAddress: '104.21.44.182', status: 'Active', riskLevel: 'Safe', owner: 'Frontend Team', openPorts: [80, 443], technologies: ['React', 'Vite', 'Nginx'], vulnerabilitiesCount: 0, firstDiscovered: '2025-10-01', lastScanned: '15 mins ago' },
  { id: 'a7', name: 'jenkins.acme-corp.com', type: 'CI/CD Server', ipAddress: '198.51.100.88', status: 'Exposed', riskLevel: 'High', owner: 'DevOps', openPorts: [8080], technologies: ['Jenkins 2.319', 'Java OpenJDK'], vulnerabilitiesCount: 4, firstDiscovered: '2026-02-01', lastScanned: '30 mins ago' },
];

export default function AssetsPage({ onOpenModal }) {
  const { addToast } = useToast();
  const [searchFilter, setSearchFilter] = useState('');
  const [riskFilter, setRiskFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');

  const filteredAssets = useMemo(() => {
    return MOCK_ASSETS.filter(a => {
      const matchesSearch = a.name.toLowerCase().includes(searchFilter.toLowerCase()) ||
                            a.ipAddress.includes(searchFilter) ||
                            a.technologies.some(t => t.toLowerCase().includes(searchFilter.toLowerCase()));
      const matchesRisk = riskFilter === 'all' || a.riskLevel.toLowerCase() === riskFilter;
      const matchesType = typeFilter === 'all' || a.type.toLowerCase().includes(typeFilter);
      return matchesSearch && matchesRisk && matchesType;
    });
  }, [searchFilter, riskFilter, typeFilter]);

  const handleAddAsset = () => {
    const assetName = prompt('Enter domain name or IP address to discover:');
    if (assetName) {
      addToast(`Queued discovery scan for new target: ${assetName}`, 'success');
    }
  };

  const handleRescanInventory = () => {
    addToast('Refreshing attack surface asset inventory...', 'info');
  };

  return (
    <div className="page-content">
      <div className="page-header">
        <div className="page-header__left">
          <h1 className="page-header__title">
            Asset <span>Inventory</span>
          </h1>
          <p className="page-header__subtitle">
            Centralized management and attack surface profiling of all corporate domains, IPs, and cloud endpoints.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button className="export-btn" onClick={handleRescanInventory}>
            <RefreshCw size={14} /> Refresh Inventory
          </button>
          <button className="export-btn btn--primary" onClick={handleAddAsset}>
            <Plus size={14} /> Add Asset Target
          </button>
        </div>
      </div>

      <div className="tab-controls" style={{ marginBottom: 20, display: 'flex', gap: 14, flexWrap: 'wrap', alignItems: 'center' }}>
        <div className="table-search-box" style={{ width: 320 }}>
          <Search size={14} color="var(--text-muted)" />
          <input
            type="text"
            placeholder="Search asset, IP, technology stack..."
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
          />
        </div>

        <select className="domain-select" value={riskFilter} onChange={(e) => setRiskFilter(e.target.value)}>
          <option value="all">All Risk Levels</option>
          <option value="critical">Critical Risk</option>
          <option value="high">High Risk</option>
          <option value="medium">Medium Risk</option>
          <option value="safe">Safe / Low Risk</option>
        </select>

        <select className="domain-select" value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}>
          <option value="all">All Asset Types</option>
          <option value="api">API Endpoints</option>
          <option value="database">Database Servers</option>
          <option value="web">Web Servers</option>
          <option value="vpn">VPN Gateways</option>
        </select>

        <div style={{ marginLeft: 'auto', fontSize: 13, color: 'var(--text-secondary)' }}>
          Showing <strong>{filteredAssets.length}</strong> of <strong>{MOCK_ASSETS.length}</strong> assets
        </div>
      </div>

      <table className="domain-data-table" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-xl)' }}>
        <thead>
          <tr>
            <th>Asset Name / Domain</th>
            <th>Type</th>
            <th>IP Address</th>
            <th>Status</th>
            <th>Tech Stack</th>
            <th>Vulns</th>
            <th>Risk Rating</th>
          </tr>
        </thead>
        <tbody>
          {filteredAssets.map(a => (
            <tr key={a.id} className="clickable-row" onClick={() => onOpenModal?.('asset', a)}>
              <td className="mono-cell" style={{ fontWeight: 700, color: 'var(--neon-blue)' }}>
                {a.name}
              </td>
              <td style={{ fontSize: 12 }}>{a.type}</td>
              <td className="mono-cell">{a.ipAddress}</td>
              <td>
                <span className={`status-dot status-dot--${a.status === 'Active' ? 'live' : 'warning'}`} style={{ display: 'inline-block', marginRight: 6 }} />
                <span style={{ fontSize: 12 }}>{a.status}</span>
              </td>
              <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                {a.technologies.slice(0, 2).join(', ')}
                {a.technologies.length > 2 && <span style={{ color: 'var(--text-muted)' }}> +{a.technologies.length - 2}</span>}
              </td>
              <td className="mono-cell" style={{ fontWeight: 700, color: a.vulnerabilitiesCount > 0 ? 'var(--high)' : 'var(--low)' }}>
                {a.vulnerabilitiesCount}
              </td>
              <td>
                <span className={`status-badge ${a.riskLevel.toLowerCase()}`}>
                  {a.riskLevel}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
