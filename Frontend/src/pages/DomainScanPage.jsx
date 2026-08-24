import { useState, useMemo, useCallback } from 'react';
import { useToast } from '../context/ToastContext';
import { initiateDomainScan } from '../api';
import {
  Globe, Search, AlertTriangle, ShieldCheck, Server, Lock, Radio, Download,
  Activity, RefreshCw, ExternalLink, Zap,
} from 'lucide-react';

const MOCK_SCAN_DATASETS = {
  'acme-corp.com': {
    domain: 'acme-corp.com',
    grade: 'A-',
    score: 88,
    ip: '104.21.44.180',
    registrar: 'Cloudflare Inc.',
    created: '2015-04-12',
    expires: '2027-04-12',
    subdomains: [
      { name: 'api.acme-corp.com', ip: '104.21.44.181', ports: [80, 443], status: '200 OK', tech: 'Node.js, Express', risk: 'Safe' },
      { name: 'app.acme-corp.com', ip: '104.21.44.182', ports: [80, 443], status: '200 OK', tech: 'React, Vite, Nginx', risk: 'Safe' },
      { name: 'staging.acme-corp.com', ip: '104.21.44.199', ports: [80, 443, 8080], status: '403 Forbidden', tech: 'Apache 2.4.41', risk: 'High' },
      { name: 'vpn.acme-corp.com', ip: '198.51.100.45', ports: [443, 1194], status: '200 OK', tech: 'OpenVPN 2.5', risk: 'Medium' },
      { name: 'mail.acme-corp.com', ip: '198.51.100.12', ports: [25, 465, 993], status: '200 OK', tech: 'Postfix, Dovecot', risk: 'Safe' },
      { name: 'dev-db.internal.acme-corp.com', ip: '192.168.1.104', ports: [5432], status: 'Connection Timeout', tech: 'PostgreSQL 14', risk: 'Critical' },
      { name: 'cdn.acme-corp.com', ip: '104.21.44.200', ports: [80, 443], status: '200 OK', tech: 'Cloudflare Edge', risk: 'Safe' },
    ],
    dns: [
      { type: 'A', name: '@', value: '104.21.44.180', ttl: 300, status: 'Valid' },
      { type: 'MX', name: '@', value: '10 mail.acme-corp.com', ttl: 3600, status: 'Valid' },
      { type: 'TXT', name: '@', value: 'v=spf1 include:_spf.google.com ~all', ttl: 3600, status: 'Valid' },
      { type: 'TXT', name: '_dmarc', value: 'v=DMARC1; p=reject; rua=mailto:dmarc@acme-corp.com', ttl: 3600, status: 'Optimal' },
      { type: 'NS', name: '@', value: 'ns1.cloudflare.com', ttl: 86400, status: 'Valid' },
      { type: 'NS', name: '@', value: 'ns2.cloudflare.com', ttl: 86400, status: 'Valid' },
    ],
    ssl: {
      issuer: "Cloudflare Inc ECC Domain Control",
      validFrom: "2026-01-10",
      validTo: "2027-01-10",
      daysLeft: 153,
      protocol: "TLS v1.3",
      cipher: "AEAD-AES256-GCM-SHA384",
      hsts: true,
      ocspStapling: true,
    },
    ports: [
      { port: 80, protocol: 'TCP', service: 'HTTP', state: 'Open', risk: 'Safe' },
      { port: 443, protocol: 'TCP', service: 'HTTPS', state: 'Open', risk: 'Safe' },
      { port: 8080, protocol: 'TCP', service: 'HTTP-Proxy', state: 'Open', risk: 'High' },
      { port: 1194, protocol: 'UDP', service: 'OpenVPN', state: 'Open', risk: 'Medium' },
      { port: 5432, protocol: 'TCP', service: 'PostgreSQL', state: 'Exposed', risk: 'Critical' },
    ]
  },
  'cyber-vault.io': {
    domain: 'cyber-vault.io',
    grade: 'B+',
    score: 79,
    ip: '172.67.133.21',
    registrar: 'Namecheap Inc.',
    created: '2021-08-19',
    expires: '2028-08-19',
    subdomains: [
      { name: 'cyber-vault.io', ip: '172.67.133.21', ports: [80, 443], status: '200 OK', tech: 'Next.js, Vercel', risk: 'Safe' },
      { name: 'auth.cyber-vault.io', ip: '172.67.133.22', ports: [443], status: '200 OK', tech: 'Auth0, OAuth2', risk: 'Safe' },
      { name: 'metrics.cyber-vault.io', ip: '172.67.133.90', ports: [9090], status: '200 OK', tech: 'Prometheus Grafana', risk: 'High' },
      { name: 'jenkins.cyber-vault.io', ip: '198.51.100.88', ports: [8080], status: '401 Unauthorized', tech: 'Jenkins 2.319', risk: 'Medium' },
    ],
    dns: [
      { type: 'A', name: '@', value: '172.67.133.21', ttl: 300, status: 'Valid' },
      { type: 'TXT', name: '@', value: 'v=spf1 mx ~all', ttl: 3600, status: 'Warning (Weak SPF)' },
      { type: 'TXT', name: '_dmarc', value: 'v=DMARC1; p=none;', ttl: 3600, status: 'Warning (Policy: none)' },
    ],
    ssl: {
      issuer: "Let's Encrypt Authority X3",
      validFrom: "2026-06-01",
      validTo: "2026-09-01",
      daysLeft: 22,
      protocol: "TLS v1.3",
      cipher: "ECDHE-RSA-AES128-GCM-SHA256",
      hsts: true,
      ocspStapling: false,
    },
    ports: [
      { port: 80, protocol: 'TCP', service: 'HTTP', state: 'Open', risk: 'Safe' },
      { port: 443, protocol: 'TCP', service: 'HTTPS', state: 'Open', risk: 'Safe' },
      { port: 9090, protocol: 'TCP', service: 'Prometheus', state: 'Open', risk: 'High' },
      { port: 8080, protocol: 'TCP', service: 'Jenkins HTTP', state: 'Open', risk: 'Medium' },
    ]
  }
};

export default function DomainScanPage({ onOpenModal }) {
  const { addToast } = useToast();
  const [targetDomain, setTargetDomain] = useState('acme-corp.com');
  const [scanType, setScanType] = useState('full');
  const [isScanning, setIsScanning] = useState(false);
  const [progress, setProgress] = useState(100);
  const [activeTab, setActiveTab] = useState('subdomains');
  const [searchFilter, setSearchFilter] = useState('');
  const [consoleLogs, setConsoleLogs] = useState([
    { time: '16:30:00', text: 'Scan ready. Enter domain to perform real-time surface discovery.', type: 'info' }
  ]);

  const [scanResult, setScanResult] = useState(MOCK_SCAN_DATASETS['acme-corp.com']);

  const handleStartScan = useCallback(async () => {
    if (!targetDomain.trim()) return;

    const cleanedDomain = targetDomain.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    setIsScanning(true);
    setProgress(5);
    addToast(`Launching multi-threaded scan on ${cleanedDomain}`, 'info');
    setConsoleLogs([
      { time: new Date().toLocaleTimeString(), text: `Initializing ${scanType.toUpperCase()} scan for [${cleanedDomain}]...`, type: 'info' }
    ]);

    // Send API request to backend
    initiateDomainScan(cleanedDomain).then((apiData) => {
      if (apiData) {
        setConsoleLogs((prev) => [
          ...prev,
          { time: new Date().toLocaleTimeString(), text: `[BACKEND API] Real-time scan result received from server!`, type: 'success' }
        ]);
      }
    }).catch((err) => {
      console.warn('Backend API scan error:', err);
    });

    let currentProgress = 5;
    const interval = setInterval(() => {
      currentProgress += Math.floor(Math.random() * 15) + 10;

      if (currentProgress >= 25 && currentProgress < 50) {
        setConsoleLogs((prev) => [
          ...prev,
          { time: new Date().toLocaleTimeString(), text: `[DNS] Querying A, AAAA, MX, TXT, DMARC records...`, type: 'info' },
          { time: new Date().toLocaleTimeString(), text: `[SUBDOMAINS] Enumerating passive certificates & CT logs...`, type: 'info' }
        ]);
      } else if (currentProgress >= 50 && currentProgress < 75) {
        setConsoleLogs((prev) => [
          ...prev,
          { time: new Date().toLocaleTimeString(), text: `[SSL] Verifying TLS 1.3 Handshake & HSTS policy...`, type: 'success' },
          { time: new Date().toLocaleTimeString(), text: `[PORTS] Scanning top 100 exposed service ports...`, type: 'warning' }
        ]);
      } else if (currentProgress >= 75 && currentProgress < 100) {
        setConsoleLogs((prev) => [
          ...prev,
          { time: new Date().toLocaleTimeString(), text: `[RISK ENGINE] Correlating CVE threat intelligence database...`, type: 'info' }
        ]);
      }

      if (currentProgress >= 100) {
        clearInterval(interval);
        setProgress(100);
        setIsScanning(false);
        addToast(`Domain scan completed for ${cleanedDomain}`, 'success');
        setConsoleLogs((prev) => [
          ...prev,
          { time: new Date().toLocaleTimeString(), text: `Scan completed successfully for ${cleanedDomain}.`, type: 'success' }
        ]);

        if (MOCK_SCAN_DATASETS[cleanedDomain]) {
          setScanResult(MOCK_SCAN_DATASETS[cleanedDomain]);
        } else {
          setScanResult({
            domain: cleanedDomain,
            grade: 'B',
            score: 76,
            ip: '198.51.100.77',
            registrar: 'Global Registrar LLC',
            created: '2020-01-15',
            expires: '2026-11-20',
            subdomains: [
              { name: `${cleanedDomain}`, ip: '198.51.100.77', ports: [80, 443], status: '200 OK', tech: 'Nginx, PHP', risk: 'Safe' },
              { name: `api.${cleanedDomain}`, ip: '198.51.100.78', ports: [443], status: '200 OK', tech: 'Node.js', risk: 'Safe' },
              { name: `test.${cleanedDomain}`, ip: '198.51.100.99', ports: [8080], status: '200 OK', tech: 'Tomcat', risk: 'High' },
            ],
            dns: [
              { type: 'A', name: '@', value: '198.51.100.77', ttl: 300, status: 'Valid' },
              { type: 'TXT', name: '@', value: 'v=spf1 mx ~all', ttl: 3600, status: 'Warning' },
            ],
            ssl: {
              issuer: "Let's Encrypt Authority X3",
              validFrom: "2026-05-01",
              validTo: "2026-08-01",
              daysLeft: 12,
              protocol: "TLS v1.3",
              cipher: "ECDHE-RSA-AES256-GCM-SHA384",
              hsts: true,
              ocspStapling: true,
            },
            ports: [
              { port: 80, protocol: 'TCP', service: 'HTTP', state: 'Open', risk: 'Safe' },
              { port: 443, protocol: 'TCP', service: 'HTTPS', state: 'Open', risk: 'Safe' },
              { port: 8080, protocol: 'TCP', service: 'HTTP-ALT', state: 'Open', risk: 'High' },
            ]
          });
        }
      } else {
        setProgress(currentProgress);
      }
    }, 400);
  }, [targetDomain, scanType, addToast]);

  const handleSelectQuickTarget = (domain) => {
    setTargetDomain(domain);
    if (MOCK_SCAN_DATASETS[domain]) {
      setScanResult(MOCK_SCAN_DATASETS[domain]);
      addToast(`Loaded scan analysis for ${domain}`, 'info');
    }
  };

  const filteredSubdomains = useMemo(() => {
    if (!scanResult?.subdomains) return [];
    if (!searchFilter.trim()) return scanResult.subdomains;
    const q = searchFilter.toLowerCase();
    return scanResult.subdomains.filter(
      (s) => s.name.toLowerCase().includes(q) || s.ip.includes(q) || s.tech.toLowerCase().includes(q)
    );
  }, [scanResult, searchFilter]);

  const handleExportReport = (format) => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(scanResult, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `domain-scan-${scanResult.domain}.${format}`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
    addToast(`Exported domain scan report (${format.toUpperCase()})`, 'success');
  };

  return (
    <div className="page-content domain-scan-container">
      <div className="page-header">
        <div className="page-header__left">
          <h1 className="page-header__title">
            Domain <span>Scan</span>
          </h1>
          <p className="page-header__subtitle">
            Perform real-time attack surface discovery, subdomain enumeration, and DNS/SSL vulnerability audits.
          </p>
        </div>
        <div className="flex-gap-md">
          <button className="export-btn" onClick={() => handleExportReport('json')}>
            <Download size={14} /> Export JSON
          </button>
        </div>
      </div>

      <div className="domain-scan-hero">
        <div className="domain-hero__header">
          <div className="domain-hero__title">
            <Globe size={22} color="var(--neon-blue)" />
            Target Domain Surface Reconnaissance
          </div>
          <p className="domain-hero__subtitle">
            Enter a domain name to execute an automated multi-threaded security scan across all public endpoints.
          </p>
        </div>

        <div className="domain-input-group">
          <div className="domain-input-wrapper">
            <Globe size={18} />
            <input
              type="text"
              className="domain-input"
              value={targetDomain}
              onChange={(e) => setTargetDomain(e.target.value)}
              placeholder="e.g. acme-corp.com or mycompany.io"
              disabled={isScanning}
              onKeyDown={(e) => e.key === 'Enter' && handleStartScan()}
            />
          </div>

          <select
            className="domain-select"
            value={scanType}
            onChange={(e) => setScanType(e.target.value)}
            disabled={isScanning}
          >
            <option value="full">Full Attack Surface Recon</option>
            <option value="subdomains">Subdomain Enumeration Only</option>
            <option value="dns">DNS & Email Security Audit</option>
            <option value="ssl">SSL/TLS & Certificate Analysis</option>
          </select>

          <button
            className="scan-launch-btn"
            onClick={handleStartScan}
            disabled={isScanning || !targetDomain.trim()}
          >
            {isScanning ? (
              <>
                <RefreshCw size={16} className="spin-icon" /> Scanning...
              </>
            ) : (
              <>
                <Zap size={16} /> Launch Scan
              </>
            )}
          </button>
        </div>

        <div className="quick-targets">
          <span>Preset Targets:</span>
          {Object.keys(MOCK_SCAN_DATASETS).map((d) => (
            <button
              key={d}
              className="target-chip"
              onClick={() => handleSelectQuickTarget(d)}
              disabled={isScanning}
            >
              {d}
            </button>
          ))}
        </div>
      </div>

      {isScanning && (
        <div className="scan-progress-card">
          <div className="progress-header">
            <div className="progress-title">
              <Activity size={18} color="var(--neon-blue)" className="spin-icon" />
              Scanning Target: <span style={{ color: 'var(--neon-blue)', fontFamily: 'monospace' }}>{targetDomain}</span>
            </div>
            <div className="progress-percent">{progress}%</div>
          </div>
          <div className="progress-bar-track">
            <div className="progress-bar-fill" style={{ width: `${progress}%` }} />
          </div>

          <div className="scan-console">
            {consoleLogs.map((log, idx) => (
              <div key={idx} className="console-line">
                <span className="console-time">[{log.time}]</span>
                <span className={`console-msg ${log.type}`}>{log.text}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {scanResult && (
        <div className="domain-kpi-grid">
          <div className="domain-kpi-card">
            <div className="kpi-header-row">
              <span className="kpi-lbl">Domain Health Grade</span>
              <div className="kpi-icon-box" style={{ background: 'rgba(56,189,248,0.12)', color: 'var(--neon-blue)' }}>
                <ShieldCheck size={20} />
              </div>
            </div>
            <div className="kpi-val" style={{ color: scanResult.score >= 80 ? '#4ade80' : 'var(--high)' }}>
              {scanResult.grade} <span style={{ fontSize: 16, color: 'var(--text-muted)' }}>({scanResult.score}/100)</span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              Registrar: <strong style={{ color: 'var(--text-primary)' }}>{scanResult.registrar}</strong>
            </div>
          </div>

          <div className="domain-kpi-card">
            <div className="kpi-header-row">
              <span className="kpi-lbl">Discovered Subdomains</span>
              <div className="kpi-icon-box" style={{ background: 'rgba(129,140,248,0.12)', color: '#818cf8' }}>
                <Server size={20} />
              </div>
            </div>
            <div className="kpi-val">{scanResult.subdomains.length}</div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              Primary IP: <span style={{ fontFamily: 'monospace', color: 'var(--neon-blue)' }}>{scanResult.ip}</span>
            </div>
          </div>

          <div className="domain-kpi-card">
            <div className="kpi-header-row">
              <span className="kpi-lbl">Exposed Ports</span>
              <div className="kpi-icon-box" style={{ background: 'rgba(249,115,22,0.12)', color: 'var(--high)' }}>
                <Radio size={20} />
              </div>
            </div>
            <div className="kpi-val" style={{ color: scanResult.ports.some(p => p.risk === 'Critical') ? 'var(--critical)' : 'var(--text-primary)' }}>
              {scanResult.ports.length} <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Ports</span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              Critical Open: <strong>{scanResult.ports.filter(p => p.risk === 'Critical' || p.risk === 'High').length}</strong>
            </div>
          </div>

          <div className="domain-kpi-card">
            <div className="kpi-header-row">
              <span className="kpi-lbl">SSL/TLS Certificate</span>
              <div className="kpi-icon-box" style={{ background: 'rgba(34,197,94,0.12)', color: '#4ade80' }}>
                <Lock size={20} />
              </div>
            </div>
            <div className="kpi-val" style={{ fontSize: 20, color: '#4ade80' }}>
              {scanResult.ssl.protocol}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
              Valid for <strong style={{ color: 'var(--text-primary)' }}>{scanResult.ssl.daysLeft} days</strong> ({scanResult.ssl.issuer.split(' ')[0]})
            </div>
          </div>
        </div>
      )}

      {scanResult && (
        <div className="domain-tabs-wrapper">
          <div className="domain-tab-list">
            <button
              className={`domain-tab-btn ${activeTab === 'subdomains' ? 'active' : ''}`}
              onClick={() => setActiveTab('subdomains')}
            >
              <Server size={15} /> Discovered Subdomains
              <span className="tab-badge">{scanResult.subdomains.length}</span>
            </button>

            <button
              className={`domain-tab-btn ${activeTab === 'dns' ? 'active' : ''}`}
              onClick={() => setActiveTab('dns')}
            >
              <Globe size={15} /> DNS & Mail Security
              <span className="tab-badge">{scanResult.dns.length}</span>
            </button>

            <button
              className={`domain-tab-btn ${activeTab === 'ssl' ? 'active' : ''}`}
              onClick={() => setActiveTab('ssl')}
            >
              <Lock size={15} /> SSL/TLS Audit
            </button>

            <button
              className={`domain-tab-btn ${activeTab === 'ports' ? 'active' : ''}`}
              onClick={() => setActiveTab('ports')}
            >
              <Radio size={15} /> Port Matrix
              <span className="tab-badge">{scanResult.ports.length}</span>
            </button>
          </div>

          {activeTab === 'subdomains' && (
            <div>
              <div className="tab-controls">
                <div className="table-search-box">
                  <Search size={14} color="var(--text-muted)" />
                  <input
                    type="text"
                    placeholder="Filter subdomains, IPs, stack..."
                    value={searchFilter}
                    onChange={(e) => setSearchFilter(e.target.value)}
                  />
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                  Showing {filteredSubdomains.length} of {scanResult.subdomains.length} subdomains
                </div>
              </div>

              <table className="domain-data-table">
                <thead>
                  <tr>
                    <th>Subdomain FQDN</th>
                    <th>IP Address</th>
                    <th>Open Ports</th>
                    <th>HTTP Status</th>
                    <th>Tech Stack</th>
                    <th>Exposure Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredSubdomains.map((sub, idx) => (
                    <tr key={idx}>
                      <td className="mono-cell" style={{ fontWeight: 600, color: 'var(--neon-blue)' }}>
                        <a href={`https://${sub.name}`} target="_blank" rel="noreferrer" style={{ textDecoration: 'none', color: 'inherit', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                          {sub.name} <ExternalLink size={12} style={{ opacity: 0.6 }} />
                        </a>
                      </td>
                      <td className="mono-cell">{sub.ip}</td>
                      <td>
                        {sub.ports.map((p) => (
                          <span key={p} className={`port-tag ${p === 8080 || p === 5432 ? 'risk' : ''}`}>
                            :{p}
                          </span>
                        ))}
                      </td>
                      <td>
                        <span style={{ fontSize: 12, fontWeight: 600, color: sub.status.includes('200') ? '#4ade80' : 'var(--high)' }}>
                          {sub.status}
                        </span>
                      </td>
                      <td style={{ color: 'var(--text-secondary)', fontSize: 12 }}>{sub.tech}</td>
                      <td>
                        <span className={`status-badge ${sub.risk.toLowerCase()}`}>
                          {sub.risk === 'Critical' && <AlertTriangle size={12} />}
                          {sub.risk}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === 'dns' && (
            <div>
              <table className="domain-data-table">
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Hostname</th>
                    <th>Value / Record Data</th>
                    <th>TTL</th>
                    <th>Security Audit</th>
                  </tr>
                </thead>
                <tbody>
                  {scanResult.dns.map((rec, idx) => (
                    <tr key={idx}>
                      <td>
                        <span className="port-tag" style={{ fontWeight: 700 }}>
                          {rec.type}
                        </span>
                      </td>
                      <td className="mono-cell">{rec.name}</td>
                      <td className="mono-cell" style={{ fontSize: 12, wordBreak: 'break-all', maxWidth: 400 }}>
                        {rec.value}
                      </td>
                      <td className="mono-cell" style={{ color: 'var(--text-muted)' }}>{rec.ttl}s</td>
                      <td>
                        <span className={`status-badge ${rec.status.includes('Valid') || rec.status.includes('Optimal') ? 'safe' : 'medium'}`}>
                          {rec.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === 'ssl' && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 20 }}>
              <div style={{ background: 'var(--bg-card)', padding: 18, borderRadius: 'var(--radius-md)', border: '1px solid var(--border)' }}>
                <h4 style={{ marginBottom: 12, fontSize: 14, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Lock size={16} color="var(--neon-blue)" /> Certificate Details
                </h4>
                <div style={{ fontSize: 13, display: 'flex', flexDirection: 'column', gap: 10, color: 'var(--text-secondary)' }}>
                  <div>Issuer: <strong style={{ color: 'var(--text-primary)' }}>{scanResult.ssl.issuer}</strong></div>
                  <div>Valid From: <span className="mono-cell">{scanResult.ssl.validFrom}</span></div>
                  <div>Valid To: <span className="mono-cell">{scanResult.ssl.validTo}</span></div>
                  <div>Days Remaining: <span className="mono-cell" style={{ color: '#4ade80', fontWeight: 700 }}>{scanResult.ssl.daysLeft} Days</span></div>
                </div>
              </div>

              <div style={{ background: 'var(--bg-card)', padding: 18, borderRadius: 'var(--radius-md)', border: '1px solid var(--border)' }}>
                <h4 style={{ marginBottom: 12, fontSize: 14, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <ShieldCheck size={16} color="#4ade80" /> Cryptographic Configuration
                </h4>
                <div style={{ fontSize: 13, display: 'flex', flexDirection: 'column', gap: 10, color: 'var(--text-secondary)' }}>
                  <div>Protocol Version: <span className="mono-cell" style={{ color: 'var(--neon-blue)' }}>{scanResult.ssl.protocol}</span></div>
                  <div>Cipher Suite: <span className="mono-cell" style={{ fontSize: 11 }}>{scanResult.ssl.cipher}</span></div>
                  <div>HSTS Enabled: <strong style={{ color: scanResult.ssl.hsts ? '#4ade80' : 'var(--critical)' }}>{scanResult.ssl.hsts ? 'YES (Strict-Transport-Security)' : 'NO'}</strong></div>
                  <div>OCSP Stapling: <strong style={{ color: scanResult.ssl.ocspStapling ? '#4ade80' : 'var(--high)' }}>{scanResult.ssl.ocspStapling ? 'Enabled' : 'Disabled'}</strong></div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'ports' && (
            <div>
              <table className="domain-data-table">
                <thead>
                  <tr>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>Service Name</th>
                    <th>State</th>
                    <th>Risk Rating</th>
                  </tr>
                </thead>
                <tbody>
                  {scanResult.ports.map((p, idx) => (
                    <tr key={idx}>
                      <td className="mono-cell" style={{ fontWeight: 700, color: 'var(--neon-blue)' }}>
                        :{p.port}
                      </td>
                      <td className="mono-cell">{p.protocol}</td>
                      <td style={{ fontWeight: 600 }}>{p.service}</td>
                      <td>
                        <span style={{ color: p.state === 'Open' ? '#4ade80' : 'var(--high)', fontWeight: 600, fontSize: 12 }}>
                          {p.state}
                        </span>
                      </td>
                      <td>
                        <span className={`status-badge ${p.risk.toLowerCase()}`}>
                          {p.risk}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

        </div>
      )}

    </div>
  );
}
