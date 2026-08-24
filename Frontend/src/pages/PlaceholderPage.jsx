import { Globe } from 'lucide-react';

export default function PlaceholderPage({ pageId }) {
  return (
    <div className="page-content" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: 400, textAlign: 'center' }}>
      <Globe size={48} color="var(--neon-blue)" style={{ marginBottom: 16, opacity: 0.8 }} />
      <h2 style={{ fontSize: 20, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8, textTransform: 'capitalize' }}>
        {pageId.replace('-', ' ')} Module
      </h2>
      <p style={{ fontSize: 13, color: 'var(--text-secondary)', maxWidth: 420 }}>
        This surface module is currently monitoring target telemetry. Select Dashboard, Domain Scan, or Settings from the sidebar menu.
      </p>
    </div>
  );
}
