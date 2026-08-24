import { useState, useMemo } from 'react';
import { ShieldAlert, Search, Filter, AlertTriangle, ExternalLink, CheckCircle, Clock, Download, CheckSquare } from 'lucide-react';
import { useToast } from '../context/ToastContext';

const MOCK_VULNS = [
  { id: 'v1', cveId: 'CVE-2024-3094', title: 'xz-utils Backdoor RCE', severity: 'Critical', cvssScore: 10.0, affectedAsset: 'api-prod-01.corp.internal', discoveredAt: '2026-03-29', status: 'Active', category: 'Remote Code Execution', description: 'Malicious code in xz-utils tarball payload leading to unauthenticated SSH authentication bypass.', remediation: 'Upgrade xz-utils library immediately to version 5.6.2 or higher.' },
  { id: 'v2', cveId: 'CVE-2023-4863', title: 'Heap Buffer Overflow in WebP', severity: 'Critical', cvssScore: 9.8, affectedAsset: 'app.acme-corp.com', discoveredAt: '2026-02-14', status: 'Active', category: 'Memory Corruption', description: 'Heap buffer overflow in WebP image parsing engine allowing arbitrary remote code execution.', remediation: 'Update libwebp dependency to version 1.3.2.' },
  { id: 'v3', cveId: 'CVE-2023-38606', title: 'Apple Kernel Privilege Escalation', severity: 'High', cvssScore: 8.8, affectedAsset: 'mac-runner-04.corp', discoveredAt: '2026-01-20', status: 'In Review', category: 'Privilege Escalation', description: 'App may be able to modify sensitive kernel state via unauthorized memory access.', remediation: 'Deploy macOS 14.1 patch to runner cluster nodes.' },
  { id: 'v4', cveId: 'CVE-2023-22515', title: 'Confluence Unauthenticated RCE', severity: 'High', cvssScore: 8.5, affectedAsset: 'wiki.corp.internal', discoveredAt: '2026-02-01', status: 'Active', category: 'Authentication Bypass', description: 'Privilege escalation vulnerability in Atlassian Confluence Data Center allows setup completion bypass.', remediation: 'Restrict external access to /setup/* endpoints and update Confluence to 8.5.2.' },
  { id: 'v5', cveId: 'CVE-2023-3519', title: 'NetScaler ADC Code Injection', severity: 'Medium', cvssScore: 6.5, affectedAsset: 'citrix-lb.corp.net', discoveredAt: '2026-03-05', status: 'Mitigated', category: 'Code Injection', description: 'Unauthenticated remote code execution on Citrix Gateway appliances.', remediation: 'Apply Citrix security update payload NS13.1-49.15.' },
];

export default function VulnerabilitiesPage({ onOpenModal }) {
  const { addToast } = useToast();
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [statusTab, setStatusTab] = useState('all');

  const filteredVulns = useMemo(() => {
    return MOCK_VULNS.filter(v => {
      const matchesSearch = v.cveId.toLowerCase().includes(searchQuery.toLowerCase()) ||
                            v.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
                            v.affectedAsset.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesSev = severityFilter === 'all' || v.severity.toLowerCase() === severityFilter;
      const matchesStatus = statusTab === 'all' || v.status.toLowerCase() === statusTab.toLowerCase();
      return matchesSearch && matchesSev && matchesStatus;
    });
  }, [searchQuery, severityFilter, statusTab]);

  const handleBulkRemediate = () => {
    addToast(`Scheduled automated patch deployment for ${filteredVulns.length} vulnerabilities`, 'info');
  };

  const handleExportCSV = () => {
    addToast('Downloaded vulnerability report CSV', 'success');
  };

  return (
    <div className="page-content">
      <div className="page-header">
        <div className="page-header__left">
          <h1 className="page-header__title">
            Vulnerability <span>Intelligence</span>
          </h1>
          <p className="page-header__subtitle">
            Correlated CVE threats, exposure scores, and patch remediation advisories across all target assets.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button className="export-btn" onClick={handleExportCSV}>
            <Download size={14} /> Export List
          </button>
          <button className="export-btn btn--primary" onClick={handleBulkRemediate}>
            <CheckSquare size={14} /> Batch Patch ({filteredVulns.length})
          </button>
        </div>
      </div>

      <div className="tab-controls" style={{ marginBottom: 20, display: 'flex', gap: 14, flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <div className="table-search-box" style={{ width: 340 }}>
            <Search size={14} color="var(--text-muted)" />
            <input
              type="text"
              placeholder="Search CVE ID, title, asset..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          <select className="domain-select" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
            <option value="all">All Severities</option>
            <option value="critical">Critical (CVSS 9.0+)</option>
            <option value="high">High (CVSS 7.0 - 8.9)</option>
            <option value="medium">Medium (CVSS 4.0 - 6.9)</option>
          </select>
        </div>

        <div style={{ display: 'flex', gap: 6, background: 'var(--bg-surface)', padding: 4, borderRadius: 'var(--radius-md)', border: '1px solid var(--border)' }}>
          {['all', 'Active', 'In Review', 'Mitigated'].map((tab) => (
            <button
              key={tab}
              onClick={() => setStatusTab(tab)}
              className={`tab-btn ${statusTab === tab ? 'active' : ''}`}
              style={{
                padding: '6px 12px',
                fontSize: 12,
                fontWeight: 600,
                borderRadius: 'var(--radius-sm)',
                border: 'none',
                background: statusTab === tab ? 'var(--accent-blue-dim)' : 'transparent',
                color: statusTab === tab ? '#fff' : 'var(--text-secondary)',
                cursor: 'pointer',
              }}
            >
              {tab.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      <table className="domain-data-table" style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-xl)' }}>
        <thead>
          <tr>
            <th>CVE Identifier</th>
            <th>Vulnerability Name</th>
            <th>Affected Endpoint</th>
            <th>CVSS</th>
            <th>Category</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {filteredVulns.map(v => (
            <tr key={v.id} className="clickable-row" onClick={() => onOpenModal?.('vulnerability', v)}>
              <td className="mono-cell" style={{ fontWeight: 700, color: 'var(--neon-blue)' }}>
                {v.cveId}
              </td>
              <td style={{ fontWeight: 600 }}>{v.title}</td>
              <td className="mono-cell" style={{ fontSize: 12 }}>{v.affectedAsset}</td>
              <td>
                <span className="cvss-pill">{v.cvssScore}</span>
              </td>
              <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{v.category}</td>
              <td>
                <span className={`status-badge ${v.severity.toLowerCase()}`}>{v.status}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
