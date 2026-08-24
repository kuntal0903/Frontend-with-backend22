import { FileText, Download, Check } from 'lucide-react';

export default function ExportCard({ onExport }) {
  return (
    <div className="dash-card" style={{ background: 'linear-gradient(135deg, var(--bg-surface) 0%, var(--bg-raised) 100%)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <FileText size={24} color="var(--neon-blue)" />
        <div>
          <h4 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>Generate Surface Audit Report</h4>
          <p style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Download full JSON/PDF diagnostic report for compliance and auditing.</p>
        </div>
      </div>
      <button className="export-btn" style={{ marginTop: 14, width: '100%', justifyContent: 'center' }} onClick={onExport}>
        <Download size={14} /> Download Report Payload
      </button>
    </div>
  );
}
